# FimMax

> Forward **Wazuh File Integrity Monitoring** alerts to **Telegram**, with an
> interactive bot, a daily digest, structured JSON logging and Docker
> packaging.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

`wazuh-fim-telegram` is a small, single-process bridge that polls the Wazuh
REST API for `syscheck` events, applies user-defined YAML rules to filter /
route / mute them, and forwards the matching ones to a Telegram chat or
channel. It also runs an interactive Telegram bot you can query from your
phone (`/status`, `/alerts`, `/fim <path>`, `/mute <rule_id> [h]`, `/digest`…)
and ships a scheduled daily digest.

It is deliberately **not** an alerting framework: there are no Alertmanager
silences, no Web UI, no database beyond a tiny SQLite file. The goal is to be
the simplest reliable way to get Wazuh FIM events onto your phone.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Quick start (Docker)](#quick-start-docker)
- [Configuration](#configuration)
- [Telegram bot commands](#telegram-bot-commands)
- [Rules file](#rules-file)
- [Local development](#local-development)
- [Testing](#testing)
- [Deployment](#deployment)
  - [Docker Compose](#docker-compose)
  - [systemd (bare metal)](#systemd-bare-metal)
- [Health check](#health-check)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

---

## Features

- **Push FIM alerts** to Telegram with severity emoji, before/after diff
  (hash / perm / owner / size), agent name and rule ID.
- **Interactive bot**: `/status`, `/alerts [n]`, `/fim <path>`, `/mute`,
  `/unmute`, `/mutes`, `/digest`, `/help`.
- **Daily digest** at a configurable cron, sent to your default chat.
- **YAML rule engine**: drop, mute, or route to a different chat by path,
  severity, rule ID, agent, action. First match wins.
- **Wazuh API polling** with JWT (≥4.3) and basic-auth fallback, automatic
  token refresh on 401, pagination, and per-source last-seen cursor so
  restarts never re-process events.
- **SQLite state**: last-seen cursor, mute list (with TTLs), 7-day recent
  events, daily counters — all in one file that survives container restarts.
- **Structured JSON logs** via structlog, with per-poll-cycle `request_id`
  for easy log correlation.
- **Docker packaging** with a non-root user, `tini` as PID 1, healthcheck,
  and a slim multi-stage build (~80 MB).
- **pytest + GitHub Actions CI**: matrix on Python 3.10/3.11/3.12, ruff,
  mypy --strict, shellcheck, Docker smoke test on every PR.

## How it works

```
            ┌─────────────────┐     JWT / basic auth
            │  Wazuh manager  │ ◄──────────────────────┐
            │   REST API      │                        │
            └────────┬────────┘                        │
                     │  GET /events?rule.groups=syscheck (or /syscheck/{agent})
                     ▼                                  │
   ┌──────────────────────────────────────┐             │
   │       wazuh-fim-telegram             │             │
   │                                      │             │
   │  WazuhClient ──► models.FimEvent ──► │             │
   │  RuleEngine ──► State (SQLite) ──►   │             │
   │  Notifier  ──────────────────────────┼─────────────┤
   │                                      │             │
   │  Telegram bot (long polling)         │             │
   │  Digest scheduler (APScheduler cron) │             │
   └──────────────┬───────────────────────┘             │
                  │                                      │
                  ▼ sendMessage                          │
            ┌─────────────────┐                         │
            │   Telegram      │                         │
            │   chat/channel  │                         │
            └─────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for a deeper walkthrough.

## Quick start (Docker)

You need:

- A Wazuh manager with the REST API enabled (default port 55000).
- A Telegram bot token (talk to **@BotFather**, run `/newbot`).
- The numeric chat ID you want alerts pushed to (e.g. `-1001234567890` for a
  channel, `123456789` for a private chat — get it from `@userinfobot`).

```bash
git clone https://github.com/your-org/wazuh-fim-telegram.git
cd wazuh-fim-telegram
cp .env.example .env
$EDITOR .env             # fill in WAZUH_* and TELEGRAM_*
cp config/rules.example.yaml config/rules.yaml
$EDITOR config/rules.yaml

docker compose up -d --build
docker compose logs -f
```

Send a synthetic alert to confirm the pipeline:

```bash
docker compose exec wazuh-fim-telegram /app/scripts/send-test-alert.sh
```

Open Telegram, type `/status` to your bot, and you should see counters and the
last poll timestamp.

## Configuration

All settings come from environment variables (and an optional `.env` file).
The full list with defaults and descriptions is in [`.env.example`](.env.example).
The most important ones:

| Variable                       | Purpose                                                        | Default                          |
| ------------------------------ | ------------------------------------------------------------- | -------------------------------- |
| `WAZUH_API_URL`                | Base URL of the Wazuh API                                     | `https://wazuh-manager:55000`    |
| `WAZUH_API_USER` / `_PASSWORD` | API credentials                                               | `wazuh` / `wazuh`                |
| `WAZUH_AUTH_STRATEGY`          | `jwt` (≥4.3) or `basic`                                       | `jwt`                            |
| `WAZUH_SOURCE`                 | `events` (≥4.4) or `syscheck` (per-agent scans)               | `events`                         |
| `WAZUH_POLL_INTERVAL_SEC`      | Seconds between polls                                         | `30`                             |
| `TELEGRAM_BOT_TOKEN`           | Token from @BotFather                                         | (required)                       |
| `TELEGRAM_CHAT_ID`             | Default chat for pushed alerts + digest                       | (required)                       |
| `TELEGRAM_ALLOWED_USER_IDS`    | Comma-separated Telegram user IDs allowed to issue commands   | (empty = anyone)                 |
| `RULES_PATH`                   | Path to the YAML rules file                                   | (unset = no rules)               |
| `STATE_PATH`                   | SQLite state file path                                        | `/var/lib/wazuh-fim-telegram/state.sqlite` |
| `DIGEST_CRON`                  | APScheduler cron expression for the daily digest              | `0 9 * * *` (09:00 daily)        |
| `LOG_LEVEL` / `LOG_FORMAT`     | Logging                                                       | `INFO` / `json`                  |

Validate your config without starting the bot:

```bash
./scripts/fim-watcher.sh validate-config
```

## Telegram bot commands

Once the bot is running, the following commands are available (subject to
`TELEGRAM_ALLOWED_USER_IDS`):

| Command                  | What it does                                                |
| ------------------------ | ----------------------------------------------------------- |
| `/start`, `/help`        | Greeting + command list                                     |
| `/status`                | Wazuh URL, source, poll interval, last seen id, cycle counters, active mutes, last error |
| `/alerts [n]`            | Last n recent FIM alerts from the state DB (default 10, max 50) |
| `/fim <path>`            | Recent alerts whose path contains the substring             |
| `/mute <rule_id> [h]`    | Mute a Wazuh rule for N hours (default 1h, max 720h)        |
| `/unmute <rule_id>`      | Lift a rule mute                                            |
| `/mutes`                 | List active mutes with expiry timestamps                    |
| `/digest`                | Send the daily digest immediately                           |

Pushed alerts look like:

```
🔴 FIM alert  [HIGH]

Rule: #550 — File modified: /etc/passwd
Action: MODIFIED
Agent: web-01 (001)
Path: /etc/passwd

Changed fields: hash, perm, size
  hash: aabbcc… → ddeeff…
  perm: 0644 → 0640
  size: 1024 → 2048

ts: 2025-11-12T08:00:00Z
```

## Rules file

Rules are evaluated top-to-bottom; the first match wins. If no rule matches,
the default action is `pass`. See [`config/rules.example.yaml`](config/rules.example.yaml)
for a full example.

```yaml
rules:
  - name: drop-tmp
    action: drop
    match:
      path_regex: '^/(tmp|var/tmp)/'

  - name: route-critical
    action: pass
    match:
      severity: [high, critical]
      path_regex: '^/(etc|usr|bin|sbin)/'
    route_to_chat: "-100SECURITY_CHANNEL"

  - name: mute-low-var-lib
    action: mute
    match:
      path_regex: '^/var/lib/'
      severity: [low, info]
```

Actions: `drop` (silently discard), `pass` (forward to Telegram, optionally
to a different chat), `mute` (store for `/alerts` queries, but don't page).

Match conditions are AND-ed within a rule. Available fields: `path_regex`,
`rule_id` (string or list), `severity` (string or list), `agent_id` (string
or list), `action` (one or more of `added` / `modified` / `deleted`).

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install       # optional but recommended

# Run the bot locally (loads .env if present):
./scripts/fim-watcher.sh run

# Or just the test suite + lint:
make test
make lint
```

Logs default to JSON. For local debugging, set `LOG_FORMAT=console` for
colored, human-readable output.

## Testing

```bash
pytest                # full suite with coverage
pytest -k rules       # only the rule engine tests
pytest --cov-report=html && open htmlcov/index.html
```

The suite uses `respx` to mock the Wazuh and Telegram HTTP APIs, so it runs
fully offline in a few seconds. CI runs it on Python 3.10, 3.11 and 3.12.

## Deployment

### Docker Compose

Recommended. See [Quick start](#quick-start-docker). The compose file mounts
a named volume at `/var/lib/wazuh-fim-telegram` so the SQLite state (last-seen
cursor, mutes, recent events) survives restarts.

### systemd (bare metal)

If you'd rather run on the Wazuh manager itself:

```bash
sudo pip install --break-system-packages .
sudo cp config/wazuh-fim-telegram.service /etc/systemd/system/
sudo cp .env /etc/wazuh-fim-telegram/.env
sudo cp config/rules.yaml /etc/wazuh-fim-telegram/rules.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-fim-telegram
journalctl -u wazuh-fim-telegram -f
```

A reference unit file is in [`docs/deployment.md`](docs/deployment.md).

## Health check

The Docker image ships with a healthcheck script (`scripts/healthcheck.sh`)
that checks the SQLite state DB was written to recently. Compose exposes
this via the standard `HEALTHCHECK`:

```bash
docker inspect --format '{{.State.Health.Status}}' wazuh-fim-telegram
```

## Troubleshooting

| Symptom                                          | Likely cause                                                          | Fix |
| ------------------------------------------------ | --------------------------------------------------------------------- | --- |
| Bot starts but no alerts come through            | No FIM events being generated, or `WAZUH_SOURCE` mismatch             | Run `/status` in Telegram; check `events_seen`. On the Wazuh side: `grep syscheck /var/ossec/logs/alerts/alerts.json` |
| `401 Unauthorized` in logs                       | Wrong `WAZUH_API_USER` / `_PASSWORD`, or `WAZUH_AUTH_STRATEGY` wrong  | Verify creds with `curl -u wazuh:wazuh https://wazuh:55000/security/user/authenticate` |
| `400 Bad Request: chat not found` from Telegram  | `TELEGRAM_CHAT_ID` wrong, or the bot was never added to the channel   | For channels: add the bot as administrator. For private chats: send `/start` to the bot first. |
| Alerts arrive twice after restart                | `STATE_PATH` not persisted (Docker volume missing)                    | Check `docker volume ls`; ensure the named volume is mounted. |
| `/mute` doesn't suppress alerts                  | The mute has expired, or you muted a rule ID that doesn't match the event's `rule_id` | Check `/mutes` and `/alerts` to compare rule IDs. |

More in [`docs/deployment.md`](docs/deployment.md).

## Project layout

```
wazuh-fim-telegram/
├── src/wazuh_fim_telegram/   # the Python package
│   ├── __main__.py           # entry: python -m wazuh_fim_telegram
│   ├── cli.py                # argparse CLI
│   ├── config.py             # pydantic-settings Settings
│   ├── logging_setup.py      # structlog JSON logging + request_id
│   ├── models.py             # FimEvent + Severity + parse_many
│   ├── wazuh_client.py       # async Wazuh API client (JWT + basic)
│   ├── rules.py              # YAML rule engine
│   ├── state.py              # SQLite state store
│   ├── notifier.py           # Telegram message formatting + send
│   ├── digest.py             # APScheduler daily digest
│   └── bot.py                # FimBot: poller + python-telegram-bot
├── scripts/                  # bash entrypoints
│   ├── fim-watcher.sh        # main wrapper (Docker CMD / systemd ExecStart)
│   ├── send-test-alert.sh    # synthetic alert smoke test
│   └── healthcheck.sh        # Docker HEALTHCHECK probe
├── config/
│   └── rules.example.yaml    # example rules file
├── tests/                    # pytest suite
├── docs/                     # architecture + deployment docs
├── .github/workflows/        # CI + CodeQL
├── Dockerfile                # multi-stage, non-root, tini
├── docker-compose.yml
├── pyproject.toml            # deps + tool config (ruff, mypy, pytest)
├── Makefile                  # dev shortcuts
└── README.md
```

## Contributing

PRs welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first — keep PRs
small, add tests for new behaviour, and make sure `ruff`, `mypy` and `pytest`
all pass locally before pushing. Conventional commits are appreciated but
not enforced.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — see [`LICENSE`](LICENSE). Wazuh and the Wazuh logo are trademarks of
their respective owners; this project is not affiliated with or endorsed by
Wazuh, Inc.
