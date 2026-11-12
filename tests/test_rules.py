"""Tests for the YAML rule engine."""

from __future__ import annotations

import textwrap

import pytest

from wazuh_fim_telegram.models import ActionType, FimEvent, Severity
from wazuh_fim_telegram.rules import RuleEngine


def _ev(**kwargs) -> FimEvent:
    base = dict(
        event_id="x",
        rule_id="550",
        agent_id="001",
        agent_name="web",
        severity=Severity.MEDIUM,
        action=ActionType.MODIFIED,
        file_path="/etc/passwd",
    )
    base.update(kwargs)
    return FimEvent(**base)


RULES_YAML = textwrap.dedent("""
    rules:
      - name: drop-tmp
        action: drop
        match:
          path_regex: '^/tmp/'

      - name: route-critical
        action: pass
        match:
          severity: [high, critical]
          path_regex: '^/etc/'
        route_to_chat: "-100CHANNEL"

      - name: mute-low-var-lib
        action: mute
        match:
          path_regex: '^/var/lib/'
          severity: [low, info]

      - name: drop-by-rule-id
        action: drop
        match:
          rule_id: ["999"]
""")


def test_first_match_wins():
    engine = RuleEngine.from_text(RULES_YAML)
    # Critical /etc → route-critical.
    d = engine.evaluate(_ev(severity=Severity.CRITICAL, file_path="/etc/shadow"))
    assert d.action == "pass"
    assert d.chat_id_override == "-100CHANNEL"

    # /tmp → drop (matches first rule, even though severity would also match
    # a later rule).
    d = engine.evaluate(_ev(severity=Severity.HIGH, file_path="/tmp/foo"))
    assert d.action == "drop"


def test_no_match_returns_default_pass():
    engine = RuleEngine.from_text(RULES_YAML)
    d = engine.evaluate(_ev(file_path="/var/log/syslog", severity=Severity.MEDIUM))
    assert d.action == "pass"
    assert d.chat_id_override is None


def test_mute_action():
    engine = RuleEngine.from_text(RULES_YAML)
    d = engine.evaluate(_ev(file_path="/var/lib/foo", severity=Severity.LOW))
    assert d.action == "mute"


def test_rule_id_list_match():
    engine = RuleEngine.from_text(RULES_YAML)
    d = engine.evaluate(_ev(rule_id="999", file_path="/opt/x"))
    assert d.action == "drop"


def test_duplicate_rule_name_rejected():
    bad = textwrap.dedent("""
        rules:
          - name: dup
            action: drop
            match: {path_regex: '.*'}
          - name: dup
            action: pass
            match: {path_regex: '.*'}
    """)
    with pytest.raises(ValueError, match="duplicate"):
        RuleEngine.from_text(bad)


def test_invalid_action_rejected():
    bad = textwrap.dedent("""
        rules:
          - name: x
            action: forward
            match: {path_regex: '.*'}
    """)
    with pytest.raises(ValueError, match="action"):
        RuleEngine.from_text(bad)


def test_missing_name_rejected():
    bad = textwrap.dedent("""
        rules:
          - action: drop
            match: {path_regex: '.*'}
    """)
    with pytest.raises(ValueError, match="name"):
        RuleEngine.from_text(bad)


def test_action_match():
    eng = RuleEngine.from_text(
        textwrap.dedent("""
        rules:
          - name: only-deletes
            action: drop
            match:
              action: [deleted]
    """)
    )
    assert eng.evaluate(_ev(action=ActionType.DELETED)).action == "drop"
    assert eng.evaluate(_ev(action=ActionType.MODIFIED)).action == "pass"


def test_empty_engine_passes_everything():
    eng = RuleEngine.empty()
    assert eng.evaluate(_ev()).action == "pass"


def test_agent_match():
    eng = RuleEngine.from_text(
        textwrap.dedent("""
        rules:
          - name: drop-db-agent
            action: drop
            match:
              agent_id: ["002"]
    """)
    )
    assert eng.evaluate(_ev(agent_id="002")).action == "drop"
    assert eng.evaluate(_ev(agent_id="001")).action == "pass"
