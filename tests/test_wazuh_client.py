"""Tests for the Wazuh API client.

Uses respx to mock httpx so we never hit a real Wazuh API.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from wazuh_fim_telegram.config import AuthStrategy, Settings, Source
from wazuh_fim_telegram.wazuh_client import WazuhAPIError, WazuhClient


def _base_settings(tmp_path, **overrides) -> Settings:
    defaults = dict(
        wazuh_api_url="https://wazuh.test:55000",
        wazuh_api_user="wazuh",
        wazuh_api_password="wazuh",
        wazuh_auth_strategy=AuthStrategy.JWT,
        wazuh_api_verify_tls=False,
        wazuh_source=Source.EVENTS,
        wazuh_poll_interval_sec=5,
        wazuh_page_size=50,
        wazuh_max_events_per_cycle=200,
        state_path=tmp_path / "state.sqlite",
        telegram_bot_token="123:abc",
        telegram_chat_id="-1001",
    )
    defaults.update(overrides)
    return Settings(**defaults)


@respx.mock
async def test_auth_then_fetch_events(tmp_path):
    settings = _base_settings(tmp_path)

    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "TOKEN-123"}})
    )
    respx.get("https://wazuh.test:55000/events").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": "e1",
                            "rule": {"id": "550", "groups": ["syscheck"], "level": 7},
                            "agent": {"id": "001", "name": "web"},
                            "data": {"path": "/etc/foo"},
                        },
                        {
                            "id": "e2",
                            "rule": {"id": "550", "groups": ["syscheck"], "level": 7},
                            "agent": {"id": "001", "name": "web"},
                            "data": {"path": "/etc/bar"},
                        },
                    ],
                    "total_affected_items": 2,
                }
            },
        )
    )

    async with WazuhClient(settings) as client:
        events = await client.fetch_fim_events(since_id=None)
    assert len(events) == 2
    # Auth header was used on the events request.
    events_request = respx.calls[1].request
    assert events_request.headers["Authorization"] == "Bearer TOKEN-123"
    # Query params filtered by syscheck.
    assert events_request.url.params["rule.groups"] == "syscheck"


@respx.mock
async def test_refreshes_token_on_401(tmp_path):
    settings = _base_settings(tmp_path)

    auth_route = respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "TOKEN-NEW"}})
    )

    events_route = respx.get("https://wazuh.test:55000/events").mock(
        side_effect=[
            httpx.Response(401, json={"error": "token expired"}),
            httpx.Response(200, json={"data": {"affected_items": []}}),
        ]
    )

    async with WazuhClient(settings) as client:
        # Seed an expired token so the first call returns 401.
        client._token = "TOKEN-OLD"
        client._token_expires_at = 9999999999.0  # far future, so we skip login
        events = await client.fetch_fim_events(since_id=None)

    assert events == []
    # 1 (failed events) + 1 (auth refresh) + 1 (retry events) = 3 calls.
    assert events_route.call_count == 2
    assert auth_route.call_count == 1


@respx.mock
async def test_pagination_stops_when_page_smaller_than_size(tmp_path):
    # Use page_size=10 (the minimum allowed by Settings) and a mock that
    # returns a full page on the first call then a partial page on the
    # second, to exercise the "len(affected) < page_size" break.
    settings = _base_settings(tmp_path, wazuh_page_size=10)

    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "T"}})
    )

    full_page = [
        {"id": f"e{i:02d}", "rule": {"groups": ["syscheck"]}, "data": {"path": f"/etc/{i}"}}
        for i in range(10)
    ]
    respx.get("https://wazuh.test:55000/events").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"affected_items": full_page}}),
            httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {
                                "id": "e10",
                                "rule": {"groups": ["syscheck"]},
                                "data": {"path": "/etc/10"},
                            },
                        ]
                    }
                },
            ),
        ]
    )

    async with WazuhClient(settings) as client:
        events = await client.fetch_fim_events(since_id=None)
    expected = [f"e{i:02d}" for i in range(10)] + ["e10"]
    assert [e["id"] for e in events] == expected
    assert respx.get("https://wazuh.test:55000/events").call_count == 2


@respx.mock
async def test_since_id_filters_old_events(tmp_path):
    settings = _base_settings(tmp_path)

    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "T"}})
    )
    respx.get("https://wazuh.test:55000/events").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": "evt-001",
                            "rule": {"groups": ["syscheck"]},
                            "data": {"path": "/etc/old"},
                        },
                        {
                            "id": "evt-002",
                            "rule": {"groups": ["syscheck"]},
                            "data": {"path": "/etc/new"},
                        },
                    ],
                }
            },
        )
    )

    async with WazuhClient(settings) as client:
        events = await client.fetch_fim_events(since_id="evt-001")
    # evt-001 should be filtered out (<= since_id), only evt-002 remains.
    assert [e["id"] for e in events] == ["evt-002"]


@respx.mock
async def test_5xx_raises(tmp_path):
    settings = _base_settings(tmp_path)

    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "T"}})
    )
    respx.get("https://wazuh.test:55000/events").mock(
        return_value=httpx.Response(500, text="internal")
    )
    async with WazuhClient(settings) as client:
        with pytest.raises(WazuhAPIError) as ei:
            await client.fetch_fim_events(since_id=None)
    assert ei.value.status == 500


@respx.mock
async def test_basic_auth_strategy(tmp_path):
    settings = _base_settings(tmp_path, wazuh_auth_strategy=AuthStrategy.BASIC)
    respx.get("https://wazuh.test:55000/events").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}})
    )

    async with WazuhClient(settings) as client:
        await client.fetch_fim_events(since_id=None)

    req = respx.calls[0].request
    assert req.headers["Authorization"].startswith("Basic ")


@respx.mock
async def test_syscheck_source_uses_agent_endpoint(tmp_path):
    settings = _base_settings(
        tmp_path,
        wazuh_source=Source.SYSCHECK,
        wazuh_agent_ids="001,002",
    )
    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "T"}})
    )
    respx.get("https://wazuh.test:55000/syscheck/001").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"affected_items": [{"path": "/etc/a", "id": "s1"}]}},
        )
    )
    respx.get("https://wazuh.test:55000/syscheck/002").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}})
    )

    async with WazuhClient(settings) as client:
        events = await client.fetch_fim_events(since_id=None)
    assert len(events) == 1
    assert events[0]["path"] == "/etc/a"
    assert events[0]["agent_id"] == "001"


@respx.mock
async def test_ping_returns_true_on_ok(tmp_path):
    settings = _base_settings(tmp_path)
    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "T"}})
    )
    respx.get("https://wazuh.test:55000/").mock(
        return_value=httpx.Response(200, json={"data": {"title": "Wazuh"}})
    )
    async with WazuhClient(settings) as client:
        assert await client.ping() is True


@respx.mock
async def test_ping_returns_false_on_auth_error(tmp_path):
    settings = _base_settings(tmp_path)
    respx.post("https://wazuh.test:55000/security/user/authenticate").mock(
        return_value=httpx.Response(401, text="bad creds")
    )
    async with WazuhClient(settings) as client:
        assert await client.ping() is False
