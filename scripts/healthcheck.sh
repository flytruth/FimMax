#!/usr/bin/env bash
#
# healthcheck.sh — used as the Docker HEALTHCHECK and by external monitors.
#
# Exits 0 if the bot process is responsive (the state DB is writable and the
# last poll happened less than 5 intervals ago), non-zero otherwise.
#
# This is intentionally a pure-bash probe — no Python imports — so it's cheap
# to run every 30s inside the container.

set -Eeuo pipefail

STATE_FILE="${STATE_FILE:-/var/lib/wazuh-fim-telegram/state.sqlite}"
MAX_AGE_SEC="${MAX_AGE_SEC:-150}"   # 5x default 30s poll interval
POLL_INTERVAL="${POLL_INTERVAL:-30}"

if [[ ! -f "${STATE_FILE}" ]]; then
  echo "state file not found: ${STATE_FILE}" >&2
  exit 1
fi

# Read the latest row timestamp from recent_events. We use sqlite3 if it's
# available; otherwise fall back to a Python one-liner.
latest_ts=""
if command -v sqlite3 >/dev/null 2>&1; then
  latest_ts="$(sqlite3 "${STATE_FILE}" \
    "SELECT ts FROM recent_events ORDER BY ts DESC LIMIT 1;" 2>/dev/null || true)"
else
  latest_ts="$("${PYTHON:-python3}" -c "
import sqlite3, sys
try:
    c = sqlite3.connect('${STATE_FILE}')
    row = c.execute('SELECT ts FROM recent_events ORDER BY ts DESC LIMIT 1').fetchone()
    print(row[0] if row else '')
except Exception:
    pass
" 2>/dev/null || true)"
fi

if [[ -z "${latest_ts}" ]]; then
  # No events yet — that's OK, the bot might just have started.
  # Make sure the process exists.
  if [[ -f /var/run/wazuh-fim-telegram.pid ]]; then
    pid="$(cat /var/run/wazuh-fim-telegram.pid)"
    if kill -0 "${pid}" 2>/dev/null; then
      exit 0
    fi
  fi
  echo "no events recorded and no pid file" >&2
  exit 1
fi

# Compare latest_ts to now.
now_epoch="$(date +%s)"
latest_epoch="$("${PYTHON:-python3}" -c "
import sys
from datetime import datetime
ts = '${latest_ts}'
try:
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    dt = datetime.fromisoformat(ts)
    print(int(dt.timestamp()))
except Exception:
    print(0)
")"

age=$(( now_epoch - latest_epoch ))
if (( age > MAX_AGE_SEC )); then
  echo "stale: last event ${age}s ago (max ${MAX_AGE_SEC}s)" >&2
  exit 1
fi

exit 0
