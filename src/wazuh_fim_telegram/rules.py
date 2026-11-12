"""YAML rule engine for filtering / routing FIM alerts.

Rules file format (see ``config/rules.example.yaml`` for a full example)::

    rules:
      - name: ignore-tmp
        action: drop
        match:
          path_regex: '^/tmp/'
      - name: route-critical
        action: pass
        match:
          severity: [high, critical]
          path_regex: '^/etc/'
        route_to_chat: "-1001234567890"
      - name: mute-cron-rotations
        action: mute
        match:
          rule_id: "554"
          path_regex: '^/var/log/.*\\.\\d$'

First match wins. If no rule matches, the default policy is ``pass``.

Rule fields:
  - ``name``           human-readable, must be unique
  - ``action``         drop | pass | mute
  - ``match``          conditions, all must match (AND)
  - ``route_to_chat``  optional chat_id override (only with ``pass``)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .logging_setup import get_logger
from .models import FimEvent, RuleDecision, Severity

log = get_logger(__name__)


@dataclass(frozen=True)
class MatchSpec:
    """Conjunction of match conditions."""

    path_regex: re.Pattern[str] | None = None
    rule_ids: frozenset[str] | None = None
    severities: frozenset[Severity] | None = None
    agents: frozenset[str] | None = None
    actions: frozenset[str] | None = None  # added | modified | deleted

    def matches(self, event: FimEvent) -> bool:
        if self.path_regex is not None and not self.path_regex.search(event.file_path):
            return False
        if self.rule_ids is not None and event.rule_id not in self.rule_ids:
            return False
        if self.severities is not None and event.severity not in self.severities:
            return False
        if self.agents is not None and event.agent_id not in self.agents:
            return False
        # Last check inlined (SIM103): returning the negated condition is the
        # same as `if ...: return False; return True`, but more compact.
        return not (self.actions is not None and event.action.value not in self.actions)


@dataclass(frozen=True)
class Rule:
    name: str
    action: str  # drop | pass | mute
    match: MatchSpec
    route_to_chat: str | None = None

    def decide(self, event: FimEvent) -> RuleDecision:
        return RuleDecision(
            action=self.action,
            reason=f"rule:{self.name}",
            chat_id_override=self.route_to_chat,
        )


class RuleEngine:
    """First-match-wins rule engine."""

    DEFAULT_ACTION = "pass"

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        seen: set[str] = set()
        for r in rules:
            if r.name in seen:
                raise ValueError(f"duplicate rule name: {r.name!r}")
            seen.add(r.name)

    @classmethod
    def from_file(cls, path: Path | str) -> RuleEngine:
        path = Path(path)
        log.info("rules.load", path=str(path))
        text = path.read_text(encoding="utf-8")
        return cls.from_text(text)

    @classmethod
    def from_text(cls, text: str) -> RuleEngine:
        doc = yaml.safe_load(text) or {}
        raw_rules = doc.get("rules") or []
        if not isinstance(raw_rules, list):
            raise ValueError("rules file must have a top-level 'rules' list")
        rules = [_build_rule(item, i) for i, item in enumerate(raw_rules)]
        log.info("rules.loaded", count=len(rules))
        return cls(rules)

    @classmethod
    def empty(cls) -> RuleEngine:
        return cls([])

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(self, event: FimEvent) -> RuleDecision:
        for rule in self._rules:
            if rule.match.matches(event):
                return rule.decide(event)
        return RuleDecision(action=self.DEFAULT_ACTION, reason="default")


def _build_rule(item: object, index: int) -> Rule:
    if not isinstance(item, dict):
        raise ValueError(f"rule #{index}: expected mapping, got {type(item).__name__}")

    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"rule #{index}: missing 'name'")
    action = str(item.get("action", "")).strip().lower()
    if action not in {"drop", "pass", "mute"}:
        raise ValueError(f"rule {name!r}: action must be one of drop|pass|mute, got {action!r}")

    match = _build_match(item.get("match") or {}, name=name)
    route_to = item.get("route_to_chat")
    if route_to is not None:
        route_to = str(route_to)
    return Rule(name=name, action=action, match=match, route_to_chat=route_to)


def _build_match(spec: dict[str, Any], *, name: str) -> MatchSpec:
    path_regex: re.Pattern[str] | None = None
    if "path_regex" in spec:
        path_regex = re.compile(str(spec["path_regex"]))

    rule_ids = _as_frozenset(spec.get("rule_id"))
    sev_raw = spec.get("severity")
    severities: frozenset[Severity] | None = None
    if sev_raw is not None:
        if isinstance(sev_raw, str):
            items = [sev_raw]
        elif isinstance(sev_raw, list):
            items = list(sev_raw)
        else:
            raise ValueError(f"rule {name!r}: severity must be a string or list")
        severities = frozenset(Severity.from_str(s) for s in items)

    agents = _as_frozenset(spec.get("agent_id"))
    actions = _as_frozenset(spec.get("action"))

    return MatchSpec(
        path_regex=path_regex,
        rule_ids=rule_ids,
        severities=severities,
        agents=agents,
        actions=actions,
    )


def _as_frozenset(value: object) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Iterable):
        return frozenset(str(v) for v in value)
    return frozenset({str(value)})
