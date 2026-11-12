"""Tests for the SQLite state store."""

from __future__ import annotations

import time

from wazuh_fim_telegram.models import ActionType, FimEvent, Severity


def _ev(**kwargs) -> FimEvent:
    base = dict(
        event_id="e1",
        rule_id="550",
        agent_id="001",
        agent_name="web",
        severity=Severity.HIGH,
        action=ActionType.MODIFIED,
        file_path="/etc/passwd",
        timestamp="2025-11-12T08:00:00Z",
    )
    base.update(kwargs)
    return FimEvent(**base)


def test_last_seen_id_roundtrip(state):
    assert state.get_last_seen_id("events") is None
    state.set_last_seen_id("events", "evt-100")
    assert state.get_last_seen_id("events") == "evt-100"
    # Different source is independent.
    assert state.get_last_seen_id("syscheck") is None


def test_mute_rule_roundtrip(state):
    assert not state.is_rule_muted("554")
    until = state.mute_rule("554", duration_sec=3600, reason="test")
    assert state.is_rule_muted("554")
    assert until > int(time.time())
    mutes = state.list_muted_rules()
    assert len(mutes) == 1
    assert mutes[0]["rule_id"] == "554"
    assert state.unmute_rule("554") is True
    assert not state.is_rule_muted("554")


def test_mute_path_roundtrip(state):
    assert not state.is_path_muted("/tmp/foo")
    state.mute_path("/tmp/foo", duration_sec=60)
    assert state.is_path_muted("/tmp/foo")
    assert state.unmute_path("/tmp/foo") is True
    assert not state.is_path_muted("/tmp/foo")


def test_record_event_increments_daily_counter(state):
    state.record_event(_ev(event_id="e1", severity=Severity.HIGH))
    state.record_event(_ev(event_id="e2", severity=Severity.HIGH))
    state.record_event(_ev(event_id="e3", severity=Severity.LOW))

    summary = state.daily_summary(day="2025-11-12")
    assert summary["total"] == 3
    assert summary["by_severity"]["high"] == 2
    assert summary["by_severity"]["low"] == 1
    assert summary["by_agent"]["001"] == 3


def test_recent_events_returns_latest(state):
    state.record_event(_ev(event_id="e1", timestamp="2025-11-12T08:00:00Z"))
    state.record_event(_ev(event_id="e2", timestamp="2025-11-12T08:30:00Z"))
    state.record_event(_ev(event_id="e3", timestamp="2025-11-12T09:00:00Z"))
    rows = state.recent_events(limit=2)
    assert len(rows) == 2
    assert rows[0]["event_id"] == "e3"
    assert rows[1]["event_id"] == "e2"


def test_recent_events_filter_by_severity(state):
    state.record_event(_ev(event_id="e1", severity=Severity.HIGH))
    state.record_event(_ev(event_id="e2", severity=Severity.LOW))
    rows = state.recent_events(limit=10, severity="low")
    assert len(rows) == 1
    assert rows[0]["event_id"] == "e2"
