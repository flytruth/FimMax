"""SQLite-backed state store.

Tracks:
  - ``last_seen_event_id`` per source (so we don't reprocess events across
    restarts)
  - ``muted_rules`` (rule_id → until-ts, set via /mute bot command)
  - ``muted_paths`` (path glob → until-ts, set via /mute bot command)
  - ``daily_counters`` (per-day counts per severity + per agent, used by the
    daily digest)

The schema is intentionally simple — a single process owns the DB. If you want
HA / multi-reader later, swap this for PostgreSQL without touching the rest of
the codebase.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .logging_setup import get_logger
from .models import FimEvent, Severity

log = get_logger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS muted_rules (
    rule_id   TEXT PRIMARY KEY,
    muted_at  INTEGER NOT NULL,
    until_ts  INTEGER NOT NULL,
    reason    TEXT
);

CREATE TABLE IF NOT EXISTS muted_paths (
    path      TEXT PRIMARY KEY,
    muted_at  INTEGER NOT NULL,
    until_ts  INTEGER NOT NULL,
    reason    TEXT
);

CREATE TABLE IF NOT EXISTS daily_counters (
    day        TEXT NOT NULL,
    severity   TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, severity, agent_id)
);

CREATE TABLE IF NOT EXISTS recent_events (
    event_id    TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    severity    TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    rule_id     TEXT NOT NULL
);
"""


class State:
    """Thread-safe SQLite state store."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,  # autocommit; we wrap multi-step txns manually
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._prune_recent_events()
        log.info("state.opened", path=str(self._path))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- last seen id --------------------------------------------------------

    def get_last_seen_id(self, source: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (f"last_seen:{source}",)
            ).fetchone()
        return row["value"] if row else None

    def set_last_seen_id(self, source: str, event_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                (f"last_seen:{source}", event_id),
            )

    # --- muted rules / paths -------------------------------------------------

    def mute_rule(self, rule_id: str, duration_sec: int, reason: str = "") -> int:
        now = int(time.time())
        until = now + duration_sec
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO muted_rules (rule_id, muted_at, until_ts, reason) "
                "VALUES (?, ?, ?, ?)",
                (rule_id, now, until, reason),
            )
        return until

    def unmute_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM muted_rules WHERE rule_id = ?", (rule_id,)
            )
        return cur.rowcount > 0

    def is_rule_muted(self, rule_id: str) -> bool:
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT until_ts FROM muted_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
        return bool(row and row["until_ts"] > now)

    def list_muted_rules(self) -> list[dict[str, Any]]:
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT rule_id, muted_at, until_ts, reason FROM muted_rules "
                "WHERE until_ts > ? ORDER BY until_ts ASC",
                (now,),
            ).fetchall()
        return [dict(r) for r in rows]

    def mute_path(self, path: str, duration_sec: int, reason: str = "") -> int:
        now = int(time.time())
        until = now + duration_sec
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO muted_paths (path, muted_at, until_ts, reason) "
                "VALUES (?, ?, ?, ?)",
                (path, now, until, reason),
            )
        return until

    def unmute_path(self, path: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM muted_paths WHERE path = ?", (path,)
            )
        return cur.rowcount > 0

    def is_path_muted(self, path: str) -> bool:
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT until_ts FROM muted_paths WHERE path = ?", (path,)
            ).fetchone()
        return bool(row and row["until_ts"] > now)

    # --- daily counters ------------------------------------------------------

    def record_event(self, event: FimEvent) -> None:
        day = (event.timestamp or _utc_now_iso())[:10]
        with self._lock:
            self._conn.execute(
                "INSERT INTO daily_counters (day, severity, agent_id, count) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(day, severity, agent_id) DO UPDATE SET count = count + 1",
                (day, event.severity.value, event.agent_id),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO recent_events "
                "(event_id, ts, severity, agent_id, action, file_path, rule_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.timestamp or _utc_now_iso(),
                    event.severity.value,
                    event.agent_id,
                    event.action.value,
                    event.file_path,
                    event.rule_id,
                ),
            )

    def daily_summary(self, day: str | None = None) -> dict[str, Any]:
        if day is None:
            day = _utc_now_iso()[:10]
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, agent_id, count FROM daily_counters WHERE day = ?",
                (day,),
            ).fetchall()
            total = self._conn.execute(
                "SELECT COALESCE(SUM(count), 0) AS total FROM daily_counters WHERE day = ?",
                (day,),
            ).fetchone()["total"]
        by_severity: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        for r in rows:
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + r["count"]
            by_agent[r["agent_id"]] = by_agent.get(r["agent_id"], 0) + r["count"]
        return {
            "day": day,
            "total": int(total),
            "by_severity": by_severity,
            "by_agent": by_agent,
        }

    def recent_events(self, limit: int = 10, severity: str | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT event_id, ts, severity, agent_id, action, file_path, rule_id "
            "FROM recent_events "
        )
        params: list[Any] = []
        if severity:
            sql += "WHERE severity = ? "
            params.append(severity)
        sql += "ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def _prune_recent_events(self, keep_days: int = 7) -> None:
        cutoff = _utc_now_iso(offset_days=-keep_days)
        with self._lock:
            self._conn.execute(
                "DELETE FROM recent_events WHERE ts < ?", (cutoff,)
            )
            # Prune expired mutes.
            now = int(time.time())
            self._conn.execute("DELETE FROM muted_rules WHERE until_ts <= ?", (now,))
            self._conn.execute("DELETE FROM muted_paths WHERE until_ts <= ?", (now,))


def _utc_now_iso(offset_days: int = 0) -> str:
    ts = time.time() + offset_days * 86400
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def coerce_events_for_summary(events: Iterable[FimEvent]) -> dict[str, Any]:
    """Build an in-memory summary from a list of events (used in tests)."""
    by_severity: dict[str, int] = {}
    by_agent: dict[str, int] = {}
    for ev in events:
        by_severity[ev.severity.value] = by_severity.get(ev.severity.value, 0) + 1
        by_agent[ev.agent_id] = by_agent.get(ev.agent_id, 0) + 1
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_agent": by_agent,
    }


def severity_rank(s: Severity) -> int:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
        Severity.UNKNOWN: -1,
    }
    return order.get(s, -1)
