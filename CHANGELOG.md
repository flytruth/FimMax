# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Pending

- Nothing yet.

## [1.0.0] — 2025-11-12

### Added

- Initial public release.
- **Wazuh API client**: JWT (≥4.3) and basic-auth strategies, automatic token
  refresh on 401, transparent pagination, last-seen cursor per source
  (`events` or `syscheck`).
- **Telegram notifier**: HTML-formatted FIM alerts with severity emoji,
  before/after diff (hash / perm / owner / size), exponential-backoff retry
  on 5xx, message truncation at the Telegram 4096-char limit.
- **Interactive bot**: `/start`, `/help`, `/status`, `/alerts [n]`,
  `/fim <path>`, `/mute <rule_id> [h]`, `/unmute <rule_id>`, `/mutes`,
  `/digest`. Access control via `TELEGRAM_ALLOWED_USER_IDS`.
- **Daily digest**: APScheduler cron, per-severity and per-agent counts from
  the SQLite state DB.
- **YAML rule engine**: drop / mute / pass with `path_regex`, `rule_id`,
  `severity`, `agent_id`, `action` matchers; optional `route_to_chat`
  override. First match wins.
- **SQLite state store**: last-seen cursor, mute list with TTLs, 7-day recent
  events window, daily counters.
- **Structured JSON logging** via structlog with per-poll-cycle `request_id`.
- **Docker packaging**: multi-stage build, non-root user, `tini` PID 1,
  healthcheck, ~80 MB image.
- **CLI subcommands**: `run`, `validate-config`, `send-test`,
  `digest-now [--send]`, `version`.
- **CI**: GitHub Actions matrix on Python 3.10 / 3.11 / 3.12 (ruff, mypy
  --strict, pytest + coverage, Docker build + smoke, shellcheck) plus a
  weekly CodeQL scan.
- **Docs**: README, CONTRIBUTING, architecture, deployment, example rules,
  example env file.

### Security

- No outbound traffic beyond the configured Wazuh API and Telegram Bot API.
- `TELEGRAM_ALLOWED_USER_IDS` restricts who can issue bot commands.
- `.gitignore` blocks commits of `.env`, `config/rules.yaml`, and `*.sqlite`.
