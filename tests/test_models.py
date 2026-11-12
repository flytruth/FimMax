"""Unit tests for the model parser."""

from __future__ import annotations

from wazuh_fim_telegram.models import (
    ActionType,
    FimEvent,
    Severity,
    parse_many,
)


def test_parses_modified_event(sample_events_payload):
    ev = FimEvent.from_wazuh_payload(sample_events_payload[0])
    assert ev is not None
    assert ev.event_id == "evt-001"
    assert ev.rule_id == "550"
    assert ev.agent_id == "001"
    assert ev.agent_name == "web-01"
    assert ev.severity is Severity.HIGH
    assert ev.action is ActionType.MODIFIED
    assert ev.file_path == "/etc/passwd"
    assert ev.file_before_hash == "aabbcc"
    assert ev.file_after_hash == "ddeeff"
    assert ev.changed_fields() == ["hash", "perm", "size"]


def test_parses_added_event(sample_events_payload):
    ev = FimEvent.from_wazuh_payload(sample_events_payload[1])
    assert ev is not None
    assert ev.action is ActionType.ADDED
    assert ev.severity is Severity.MEDIUM
    assert ev.file_path == "/opt/app/config.yaml"


def test_parses_deleted_event(sample_events_payload):
    ev = FimEvent.from_wazuh_payload(sample_events_payload[2])
    assert ev is not None
    assert ev.action is ActionType.DELETED
    assert ev.severity is Severity.HIGH
    assert ev.agent_name == "db-01"


def test_skips_non_syscheck_event(sample_events_payload):
    ev = FimEvent.from_wazuh_payload(sample_events_payload[4])
    assert ev is None


def test_parse_many_skips_invalid_and_keeps_order(sample_events_payload):
    events = parse_many(sample_events_payload)
    ids = [e.event_id for e in events]
    assert ids == ["evt-001", "evt-002", "evt-003", "evt-004"]


def test_severity_levels():
    assert Severity.from_str("critical") is Severity.CRITICAL
    assert Severity.from_str("unknown_thing") is Severity.UNKNOWN
    assert Severity.from_str(None) is Severity.UNKNOWN


def test_action_heuristic_when_missing():
    ev = FimEvent.from_wazuh_payload(
        {
            "id": "x",
            "rule": {"id": "1", "groups": ["syscheck"], "level": 2},
            "agent": {"id": "001", "name": "x"},
            "data": {"path": "/etc/foo", "before": {"hash": "a"}, "after": {"hash": "b"}},
        }
    )
    assert ev is not None
    assert ev.action is ActionType.MODIFIED


def test_short_label(sample_events_payload):
    ev = FimEvent.from_wazuh_payload(sample_events_payload[0])
    assert ev is not None
    assert ev.short_label() == "modified:/etc/passwd"


def test_missing_path_returns_none():
    ev = FimEvent.from_wazuh_payload(
        {
            "id": "x",
            "rule": {"id": "1", "groups": ["syscheck"], "level": 2},
            "agent": {"id": "001", "name": "x"},
            "data": {},
        }
    )
    assert ev is None


def test_fallback_id_when_missing():
    ev = FimEvent.from_wazuh_payload(
        {
            "rule": {"id": "550", "groups": ["syscheck"], "level": 5},
            "agent": {"id": "001", "name": "x"},
            "data": {"path": "/etc/foo"},
        }
    )
    assert ev is not None
    assert ev.event_id and ev.event_id.startswith("001-550")
