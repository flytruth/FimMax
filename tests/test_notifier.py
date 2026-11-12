"""Tests for the Telegram notifier."""

from __future__ import annotations

import httpx
import pytest
import respx

from wazuh_fim_telegram.models import ActionType, FimEvent, Severity
from wazuh_fim_telegram.notifier import Notifier, format_digest


def _ev(**kwargs) -> FimEvent:
    base = dict(
        event_id="e1",
        rule_id="550",
        rule_description="File modified: /etc/passwd",
        agent_id="001",
        agent_name="web-01",
        severity=Severity.HIGH,
        action=ActionType.MODIFIED,
        file_path="/etc/passwd",
        file_before_hash="aabb",
        file_after_hash="ccdd",
        file_before_perm="0644",
        file_after_perm="0640",
        file_owner_before="root",
        file_owner_after="root",
        file_size_before=1024,
        file_size_after=2048,
        timestamp="2025-01-01T00:00:00Z",
    )
    base.update(kwargs)
    return FimEvent(**base)


def test_format_event_contains_severity_emoji_and_path():
    text = Notifier.format_event(_ev())
    assert "🟠" in text  # HIGH emoji (orange)
    assert "[HIGH]" in text
    assert "/etc/passwd" in text
    assert "Rule:" in text
    assert "web-01" in text
    assert "hash:" in text
    assert "perm:" in text
    assert "size:" in text


def test_format_event_escapes_html():
    text = Notifier.format_event(
        _ev(
            file_path="/etc/<script>alert('xss')</script>",
            rule_description="a & b < c > d",
        )
    )
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "&amp;" in text
    assert "&lt;" in text
    assert "&gt;" in text


def test_format_event_no_diff_for_added():
    text = Notifier.format_event(
        _ev(
            action=ActionType.ADDED,
            file_before_hash="",
            file_before_perm="",
            file_before_owner="",
            file_size_before=None,
        )
    )
    assert "Changed fields:" not in text


def test_format_digest():
    summary = {
        "day": "2025-11-12",
        "total": 7,
        "by_severity": {"high": 2, "medium": 5},
        "by_agent": {"001": 5, "002": 2},
    }
    text = format_digest(summary)
    assert "Daily FIM digest" in text
    assert "2025-11-12" in text
    assert "Total events:" in text
    assert "7" in text
    assert "high=2" in text
    assert "medium=5" in text
    assert "001=5" in text


@respx.mock
async def test_send_alert_success():
    respx.post("https://api.telegram.org/bot123:abc/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 42}})
    )
    async with Notifier("123:abc") as n:
        result = await n.send_alert(_ev(), chat_id="-100123456")
    assert result.ok is True
    assert result.message_id == 42


@respx.mock
async def test_send_alert_retries_on_500_then_succeeds():
    route = respx.post("https://api.telegram.org/bot123:abc/sendMessage").mock(
        side_effect=[
            httpx.Response(500, text="oops"),
            httpx.Response(200, json={"ok": True, "result": {"message_id": 1}}),
        ]
    )
    async with Notifier("123:abc", max_retries=3) as n:
        result = await n.send_alert(_ev(), chat_id="-1001")
    assert result.ok is True
    assert route.call_count == 2


@respx.mock
async def test_send_alert_no_retry_on_400():
    route = respx.post("https://api.telegram.org/bot123:abc/sendMessage").mock(
        return_value=httpx.Response(400, text="chat not found")
    )
    async with Notifier("123:abc", max_retries=3) as n:
        result = await n.send_alert(_ev(), chat_id="-1001")
    assert result.ok is False
    assert "400" in result.error
    assert route.call_count == 1


async def test_send_alert_empty_chat_id_returns_error():
    async with Notifier("123:abc") as n:
        result = await n.send_alert(_ev(), chat_id="")
    assert result.ok is False
    assert "chat_id" in result.error


@respx.mock
async def test_send_alert_truncates_overlong_message():
    # Build a payload with a very long rule description.
    long_desc = "x" * 5000
    captured: dict = {}

    def _capture(request):
        captured["text"] = request.read().decode()
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    respx.post("https://api.telegram.org/bot123:abc/sendMessage").mock(side_effect=_capture)
    async with Notifier("123:abc") as n:
        await n.send_alert(_ev(rule_description=long_desc), chat_id="-1001")
    import json

    body = json.loads(captured["text"])
    assert len(body["text"]) <= 3800 + len("\n…[truncated]")
    assert body["text"].endswith("…[truncated]")


def test_notifier_requires_token():
    with pytest.raises(ValueError):
        Notifier("")
