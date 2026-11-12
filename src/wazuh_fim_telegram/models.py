"""Domain models for FIM events and rule decisions.

The :class:`FimEvent` is the normalized shape we pass through the pipeline:
Wazuh API response → :class:`FimEvent` → rules → notifier → Telegram message.

Keeping the model narrow (only what we actually use downstream) means changes
to the Wazuh API payload shape rarely break us.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class Severity(str, Enum):
    """Wazuh severity levels we care about for routing/formatting."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        v = value.strip().lower()
        try:
            return cls(v)
        except ValueError:
            return cls.UNKNOWN


class ActionType(str, Enum):
    """What the FIM event represents."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNKNOWN = "unknown"


class FimEvent(BaseModel):
    """Normalized FIM event."""

    event_id: str
    rule_id: str = "0"
    rule_description: str = ""
    agent_id: str = "000"
    agent_name: str = "unknown"
    severity: Severity = Severity.UNKNOWN
    action: ActionType = ActionType.UNKNOWN
    file_path: str = ""
    file_before_hash: str = ""
    file_after_hash: str = ""
    file_before_perm: str = ""
    file_after_perm: str = ""
    file_owner_before: str = ""
    file_owner_after: str = ""
    file_size_before: int | None = None
    file_size_after: int | None = None
    timestamp: str = ""  # ISO-8601 as reported by Wazuh
    received_at: str = ""  # ISO-8601 set by us when we pulled the event
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_wazuh_payload(cls, payload: dict[str, Any]) -> FimEvent | None:
        """Build a :class:`FimEvent` from a Wazuh API event payload.

        Returns ``None`` when the payload is not a FIM event (no rule.groups
        containing ``syscheck``) or is missing the minimum required fields.

        Wazuh event payloads vary between the ``/events`` endpoint (rule-based)
        and ``/syscheck/{agent}`` endpoint (scan-based). This parser handles
        both shapes.
        """
        # --- /events payload ------------------------------------------------
        # Shape: { "id": "...", "rule": {"id":..., "description":..., "groups":[...], "level":...},
        #          "agent": {"id":..., "name":...}, "data": {...}, "timestamp": "..." }
        if "rule" in payload:
            rule = payload.get("rule") or {}
            groups = rule.get("groups") or []
            if not any(g == "syscheck" for g in groups):
                return None

            data = payload.get("data") or {}
            agent = payload.get("agent") or {}

            action = _action_from_data(data)
            file_path = data.get("path") or data.get("syscheck", {}).get("path", "")
            if not file_path:
                return None

            severity = _severity_from_rule(rule)

            before = data.get("before") or {}
            after = data.get("after") or {}
            return cls(
                event_id=str(payload.get("id") or _fallback_id(payload)),
                rule_id=str(rule.get("id") or "0"),
                rule_description=str(rule.get("description") or ""),
                agent_id=str(agent.get("id") or "000"),
                agent_name=str(agent.get("name") or "unknown"),
                severity=severity,
                action=action,
                file_path=file_path,
                file_before_hash=str(before.get("hash", "")) if isinstance(before, dict) else "",
                file_after_hash=str(after.get("hash", "")) if isinstance(after, dict) else "",
                file_before_perm=str(before.get("perm", "")) if isinstance(before, dict) else "",
                file_after_perm=str(after.get("perm", "")) if isinstance(after, dict) else "",
                file_owner_before=str(before.get("owner", "")) if isinstance(before, dict) else "",
                file_owner_after=str(after.get("owner", "")) if isinstance(after, dict) else "",
                file_size_before=_as_int(before.get("size") if isinstance(before, dict) else None),
                file_size_after=_as_int(after.get("size") if isinstance(after, dict) else None),
                timestamp=str(payload.get("timestamp") or ""),
                raw=payload,
            )

        # --- /syscheck/{agent} payload --------------------------------------
        # Shape: { "data": {"affected_items": [{ "path":..., "hash":..., ... }]} }
        scan_items = ((payload.get("data") or {}).get("affected_items")) or []
        # Callers handle lists; this method handles single items.
        if isinstance(scan_items, list) and scan_items:
            item = scan_items[0]
            path = item.get("path") or ""
            if not path:
                return None
            return cls(
                event_id=str(item.get("id") or f"syscheck-{path}"),
                rule_id="553",  # generic syscheck rule id
                rule_description="File integrity monitoring scan",
                agent_id=str(item.get("agent_id") or "000"),
                agent_name=str(item.get("agent_name") or "unknown"),
                severity=Severity.from_str(item.get("severity")),
                action=_action_from_data(item),
                file_path=path,
                file_after_hash=str(item.get("hash") or item.get("hash_after") or ""),
                file_before_hash=str(item.get("hash_before") or ""),
                file_after_perm=str(item.get("perm") or item.get("perm_after") or ""),
                file_before_perm=str(item.get("perm_before") or ""),
                file_owner_after=str(item.get("owner") or ""),
                file_owner_before=str(item.get("owner_before") or ""),
                file_size_after=_as_int(item.get("size")),
                file_size_before=_as_int(item.get("size_before")),
                timestamp=str(item.get("timestamp") or item.get("date") or ""),
                raw=payload,
            )

        return None

    def short_label(self) -> str:
        return f"{self.action.value}:{self.file_path}"

    def changed_fields(self) -> list[str]:
        out: list[str] = []
        if (
            self.file_before_hash
            and self.file_after_hash
            and self.file_before_hash != self.file_after_hash
        ):
            out.append("hash")
        if (
            self.file_before_perm
            and self.file_after_perm
            and self.file_before_perm != self.file_after_perm
        ):
            out.append("perm")
        if (
            self.file_owner_before
            and self.file_owner_after
            and self.file_owner_before != self.file_owner_after
        ):
            out.append("owner")
        if (
            self.file_size_before is not None
            and self.file_size_after is not None
            and self.file_size_before != self.file_size_after
        ):
            out.append("size")
        return out


class RuleDecision(BaseModel):
    """Decision returned by the rule engine for a single event."""

    action: str  # "pass", "drop", "mute"
    reason: str = ""
    chat_id_override: str | None = None


def _action_from_data(data: dict[str, Any]) -> ActionType:
    if "action" in data:
        try:
            return ActionType(str(data["action"]).lower())
        except ValueError:
            return ActionType.UNKNOWN
    # Heuristic: presence of `before` only = deleted, `after` only = added,
    # both = modified.
    has_before = bool(data.get("before"))
    has_after = bool(data.get("after"))
    if has_before and not has_after:
        return ActionType.DELETED
    if has_after and not has_before:
        return ActionType.ADDED
    if has_before and has_after:
        return ActionType.MODIFIED
    return ActionType.UNKNOWN


def _severity_from_rule(rule: dict[str, Any]) -> Severity:
    level = rule.get("level")
    if level is None:
        return Severity.UNKNOWN
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return Severity.from_str(str(level))
    if lvl >= 12:
        return Severity.CRITICAL
    if lvl >= 7:
        return Severity.HIGH
    if lvl >= 4:
        return Severity.MEDIUM
    if lvl >= 1:
        return Severity.LOW
    return Severity.INFO


def _as_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _fallback_id(payload: dict[str, Any]) -> str:
    """Synthesize an id when Wazuh doesn't return one (rare)."""
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    data = payload.get("data") or {}
    return f"{agent.get('id','000')}-{rule.get('id','0')}-{data.get('path','')}"


def parse_many(payloads: list[dict[str, Any]]) -> list[FimEvent]:
    """Parse a list of raw Wazuh payloads into FIM events, skipping invalid ones."""
    out: list[FimEvent] = []
    for p in payloads:
        try:
            ev = FimEvent.from_wazuh_payload(p)
            if ev is not None:
                out.append(ev)
        except ValidationError:
            continue
    return out
