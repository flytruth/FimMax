# Architecture

## Overview

`wazuh-fim-telegram` is a single asyncio process with four cooperating
components: a **poller** that talks to the Wazuh API, a **rule engine** that
decides what to do with each event, a **state store** that persists cursors /
mutes / counters, and a **Telegram bot** that both pushes alerts and answers
interactive commands. A fifth component, the **digest scheduler**, fires once
a day.

```
                    ┌────────────────────────────────────────────────────────┐
                    │                    asyncio loop                        │
                    │                                                       │
                    │   ┌──────────────┐         ┌──────────────────────┐   │
                    │   │  poller task │ ────►   │  WazuhClient          │   │
                    │   │  (every 30s) │         │  (httpx, JWT/basic)  │   │
                    │   └──────┬───────┘         └──────────────────────┘   │
                    │          │ raw payloads                               │
                    │          ▼                                             │
                    │   ┌──────────────┐         ┌──────────────────────┐   │
                    │   │ parse_many   │ ────►   │  RuleEngine.evaluate │   │
                    │   │ (models.py)  │         │  (rules.py)          │   │
                    │   └──────┬───────┘         └──────────┬───────────┘   │
                    │          │ FimEvent + RuleDecision    │                │
                    │          ▼                            ▼                │
                    │   ┌──────────────────────────────────────────────┐   │
                    │   │  State (SQLite)                               │   │
                    │   │   - set_last_seen_id                          │   │
                    │   │   - record_event + daily_counters             │   │
                    │   │   - is_rule_muted / is_path_muted             │   │
                    │   └──────────────────────────────────────────────┘   │
                    │          │                                            │
                    │          ▼                                            │
                    │   ┌──────────────┐         ┌──────────────────────┐   │
                    │   │ Notifier     │ ────►   │ Telegram Bot API     │   │
                    │   │ (format +    │         │  /sendMessage        │   │
                    │   │  send)       │         └──────────────────────┘   │
                    │   └──────────────┘                                    │
                    │                                                       │
                    │   ┌──────────────────────────────────────────────┐   │
                    │   │  python-telegram-bot Application             │   │
                    │   │   - long-polling for updates                 │   │
                    │   │   - CommandHandler for /status, /mute, ...   │   │
                    │   └──────────────────────────────────────────────┘   │
                    │                                                       │
                    │   ┌──────────────────────────────────────────────┐   │
                    │   │  APScheduler daily-digest job                 │   │
                    │   └──────────────────────────────────────────────┘   │
                    └────────────────────────────────────────────────────────┘
```

## Component walkthrough

### `WazuhClient` (`wazuh_client.py`)

Async httpx client. Auth strategy is selected by `WAZUH_AUTH_STRATEGY`:

- **JWT** (default, Wazuh ≥4.3): `POST /security/user/authenticate` with
  basic auth → bearer token cached in memory with an 840s TTL (Wazuh tokens
  last 900s). On any 401 the token is invalidated and we re-auth + retry the
  request **once**. Subsequent 401s surface as `WazuhAPIError`.
- **Basic** (older Wazuh): basic auth on every request.

`fetch_fim_events(since_id)` pulls events strictly newer than `since_id`,
sorted ascending. Two sources:

- `events` (default): `GET /events?rule.groups=syscheck&limit=…&offset=…&sort=-id`,
  paginated by `offset`, filtered client-side against `since_id`.
- `syscheck`: `GET /syscheck/{agent_id}` per agent in `WAZUH_AGENT_IDS`,
  paginated by `offset`. Each item is annotated with its `agent_id` so the
  parser works.

The cycle is bounded by `WAZUH_MAX_EVENTS_PER_CYCLE` to avoid pathological
backlog storms taking down the bot.

### `models.py`

`FimEvent.from_wazuh_payload()` normalises both `/events` and `/syscheck`
payloads into a single shape. It returns `None` for non-syscheck payloads
(missing `rule.groups` containing `syscheck`) and for payloads without a
`path`. `parse_many()` is the list version, swallowing `ValidationError`s.

Severity is mapped from the Wazuh `rule.level` integer:

| level | severity  |
| ----- | --------- |
| ≥12   | critical  |
| 7–11  | high      |
| 4–6   | medium    |
| 1–3   | low       |
| 0     | info      |

Action is inferred from the presence of `before` / `after` blocks:
both → `modified`, only `before` → `deleted`, only `after` → `added`.

### `rules.py`

YAML rules → in-memory `Rule` list. `RuleEngine.evaluate(event)` returns a
`RuleDecision(action, reason, chat_id_override)`. First match wins; default
is `pass`. Match conditions are AND-ed.

The engine is intentionally a thin wrapper around `re.Pattern` and
`frozenset` checks — no expression language, no `eval()`, no Jinja. If you
need more, write a custom matcher in Python and call it from `evaluate`.

### `state.py`

SQLite, autocommit, thread-safe via a single `threading.Lock`. Schema lives
in `SCHEMA` at the top of the module; the DB is created lazily on first
connect. Tables:

- `meta(key, value)` — last-seen cursors, keyed `last_seen:<source>`.
- `muted_rules(rule_id, muted_at, until_ts, reason)` — set by `/mute`,
  pruned on read and on startup.
- `muted_paths(path, muted_at, until_ts, reason)` — reserved for future
  path-level mutes (currently only rule-level mutes are exposed via the bot).
- `daily_counters(day, severity, agent_id, count)` — upserted on every
  recorded event.
- `recent_events(event_id, ts, severity, agent_id, action, file_path, rule_id)`
  — last 7 days of events for `/alerts` and `/fim` queries.

### `notifier.py`

Formats a `FimEvent` into HTML and POSTs to `/bot<token>/sendMessage`. Key
decisions:

- **HTML mode** with explicit `html.escape()` everywhere — never markdown,
  because file paths can contain `_` `*` `[` which markdown would
  misinterpret.
- **No retry on 400/403** (bad chat id, bot blocked, etc.) — these won't fix
  themselves. **Retry with exponential backoff on 5xx and network errors**.
- **Truncation at 3800 chars** + `[truncated]` tail to stay under Telegram's
  4096-char limit even with the wrapper overhead.

### `bot.py` — `FimBot`

Owns one of each: `WazuhClient`, `Notifier`, `State`, `RuleEngine`,
`Application` (python-telegram-bot), `PollerStats`.

`start()`:

1. Initialises the PTB `Application` and registers command handlers.
2. Enters the Wazuh client and notifier async context managers.
3. Starts the PTB updater (long polling for bot commands).
4. Spawns the `_poll_loop` background task.

`_poll_loop()`:

```
while not stop:
    request_id = f"poll-{cycles+1}"
    since = state.get_last_seen_id(source)
    raw_events = await wazuh.fetch_fim_events(since)
    events = parse_many(raw_events)
    await _process_events(events)
    await asyncio.wait_for(stop.wait(), timeout=interval)
```

The `request_id` context var is propagated by structlog so every log line
emitted during this cycle can be filtered with `request_id=poll-42`.

`_process_events()` applies rules → state-mute check → state record →
notifier send, in that order. `last_seen_id` is updated **only** to the last
forwarded event id, so a poll cycle that produces only muted/dropped events
does not advance the cursor past future events that might be interesting.

### `digest.py`

APScheduler `AsyncIOScheduler` with a `CronTrigger.from_crontab` schedule.
`DigestJob.run_now()` is also called directly by the bot's `/digest` command.
The summary is rendered by `Notifier.format_digest()` (kept in
`notifier.py` so the formatting can be unit-tested without an event loop).

## Failure modes & trade-offs

- **Single process**: no HA. Run two instances only if they have different
  `STATE_PATH`s and route to different chats, otherwise they'll duplicate
  alerts. If you need HA, the cleanest path is to add a Postgres backend for
  `state.py` and a row-level lock on `last_seen`.
- **Polling, not webhooks**: simpler to deploy (no ingress), but adds up to
  `WAZUH_POLL_INTERVAL_SEC` of latency. Lower the interval to 5–10s for
  near-real-time alerting; the Wazuh API handles this fine.
- **SQLite, not Postgres**: fine up to ~1k events/day. Beyond that, the
  `recent_events` table grows; we prune to 7 days automatically, but you may
  want to lower that or move to Postgres.
- **No deduplication beyond `event_id`**: Wazuh dedupes by content already;
  adding a second layer here would hide real repeated alerts.

## Security notes

- The bot token and Wazuh credentials live only in env vars / `.env` and are
  never logged. `Notifier.format_event` HTML-escapes all untrusted fields
  (file paths, agent names, rule descriptions) to prevent injection into
  Telegram messages.
- `TELEGRAM_ALLOWED_USER_IDS` is enforced by `FimBot._authorized()` before
  every command handler. Pushed alerts bypass this (they go to the
  configured chat ID regardless).
- The Docker image runs as a non-root user (UID 1000) with `tini` as PID 1
  for clean SIGTERM handling.
