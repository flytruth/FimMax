"""Tests for the FimBot — focus on the event processing pipeline.

We construct a FimBot with mocked dependencies (Wazuh client, notifier, state)
and verify that:
  - events are fetched and parsed
  - rules are applied (drop / mute / pass)
  - passing events are forwarded to the right chat
  - last-seen id is updated only when at least one event is forwarded
  - stats are tracked correctly
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from wazuh_fim_telegram.bot import FimBot
from wazuh_fim_telegram.config import Settings
from wazuh_fim_telegram.models import FimEvent, parse_many
from wazuh_fim_telegram.notifier import SendResult
from wazuh_fim_telegram.rules import RuleEngine
from wazuh_fim_telegram.state import State
from wazuh_fim_telegram.wazuh_client import WazuhClient


def _events() -> list[FimEvent]:
    return parse_many(
        [
            {
                "id": "e1",
                "timestamp": "2025-11-12T08:00:00Z",
                "rule": {
                    "id": "550",
                    "level": 7,
                    "groups": ["syscheck"],
                    "description": "modified /etc/passwd",
                },
                "agent": {"id": "001", "name": "web"},
                "data": {"path": "/etc/passwd", "before": {"hash": "a"}, "after": {"hash": "b"}},
            },
            {
                "id": "e2",
                "timestamp": "2025-11-12T08:01:00Z",
                "rule": {"id": "550", "level": 7, "groups": ["syscheck"]},
                "agent": {"id": "001", "name": "web"},
                "data": {"path": "/tmp/junk", "before": {"hash": "a"}, "after": {"hash": "b"}},
            },
            {
                "id": "e3",
                "timestamp": "2025-11-12T08:02:00Z",
                "rule": {"id": "554", "level": 3, "groups": ["syscheck"]},
                "agent": {"id": "002", "name": "db"},
                "data": {"path": "/var/lib/x", "after": {"hash": "c"}},
            },
        ]
    )


def _rules() -> RuleEngine:
    import textwrap

    return RuleEngine.from_text(
        textwrap.dedent("""
        rules:
          - name: drop-tmp
            action: drop
            match: {path_regex: '^/tmp/'}
          - name: mute-low-var-lib
            action: mute
            match: {path_regex: '^/var/lib/', severity: [low, info]}
    """)
    )


def _make_bot(settings, state, rules, events) -> FimBot:
    wazuh = WazuhClient(settings)
    wazuh.fetch_fim_events = AsyncMock(return_value=[e.raw for e in events])  # type: ignore

    notifier = AsyncMock()
    notifier.send_alert = AsyncMock(return_value=SendResult(ok=True, message_id=1))
    notifier.__aenter__ = AsyncMock(return_value=notifier)  # type: ignore
    notifier.__aexit__ = AsyncMock(return_value=None)  # type: ignore

    bot = FimBot(
        settings,
        wazuh_client=wazuh,
        notifier=notifier,  # type: ignore
        state=state,
        rules=rules,
    )
    return bot


async def test_pipeline_drops_mutes_and_forwards(settings: Settings, state: State):
    bot = _make_bot(settings, state, _rules(), _events())
    # Avoid touching telegram / asyncio loop.
    bot._app = None  # type: ignore

    await bot._process_events(_events())

    # e2 dropped (/tmp), e3 muted (low severity + /var/lib), e1 forwarded.
    assert bot.stats.events_seen == 3
    assert bot.stats.events_dropped == 1
    assert bot.stats.events_muted == 1
    assert bot.stats.events_forwarded == 1

    # Notifier was called exactly once, for e1, with the default chat.
    notifier = bot.notifier
    notifier.send_alert.assert_called_once()  # type: ignore
    call = notifier.send_alert.call_args  # type: ignore
    forwarded_event, chat_id = call.args
    assert forwarded_event.event_id == "e1"
    assert chat_id == settings.telegram_chat_id

    # Last seen id updated to e1 (last forwarded).
    assert state.get_last_seen_id(settings.wazuh_source.value) == "e1"


async def test_last_seen_id_not_updated_when_no_forward(settings: Settings, state: State):
    # All events get dropped by the rules engine.
    import textwrap

    rules = RuleEngine.from_text(
        textwrap.dedent("""
        rules:
          - name: drop-all
            action: drop
            match: {path_regex: '.*'}
    """)
    )
    bot = _make_bot(settings, state, rules, _events())

    await bot._process_events(_events())
    assert bot.stats.events_forwarded == 0
    assert state.get_last_seen_id(settings.wazuh_source.value) is None


async def test_chat_id_override_used_when_rule_routes(settings: Settings, state: State):
    import textwrap

    rules = RuleEngine.from_text(
        textwrap.dedent("""
        rules:
          - name: drop-tmp-and-var-lib
            action: drop
            match: {path_regex: '^/(tmp|var/lib)/'}
          - name: route-etc
            action: pass
            match: {path_regex: '^/etc/'}
            route_to_chat: "-100OVERRIDE"
    """)
    )
    bot = _make_bot(settings, state, rules, _events())

    await bot._process_events(_events())
    notifier = bot.notifier
    notifier.send_alert.assert_called_once()  # type: ignore
    _, chat_id = notifier.send_alert.call_args.args  # type: ignore
    assert chat_id == "-100OVERRIDE"


async def test_ad_hoc_mute_via_state(settings: Settings, state: State):
    # Pre-mute rule 550; rule engine would pass but state mutes.
    state.mute_rule("550", duration_sec=3600)
    rules = RuleEngine.empty()
    bot = _make_bot(settings, state, rules, _events())

    await bot._process_events(_events())
    # e1 and e2 have rule_id 550 → muted by state. e3 has rule_id 554 → forwarded.
    assert bot.stats.events_muted == 2
    assert bot.stats.events_forwarded == 1


async def test_process_events_empty_does_nothing(settings: Settings, state: State):
    bot = _make_bot(settings, state, _rules(), [])
    await bot._process_events([])
    assert bot.stats.events_seen == 0
    assert bot.stats.events_forwarded == 0
