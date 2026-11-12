"""Application configuration.

All settings are loaded from environment variables (with optional ``.env``
file) using pydantic-settings. The :class:`Settings` object is the single
source of truth for the runtime configuration; CLI flags override env vars
where applicable.

Wazuh API auth:
  Since v4.3 the Wazuh API uses JWT. We POST credentials to
  ``/security/user/authenticate`` and cache the resulting token. For older
  deployments that still accept basic auth on every request, set
  ``WAZUH_AUTH_STRATEGY=basic``.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthStrategy(str, Enum):
    """How the Wazuh API authenticates each request."""

    JWT = "jwt"  # POST /security/user/authenticate, use Bearer token
    BASIC = "basic"  # send Basic auth header on every request (pre-4.3)


class Source(str, Enum):
    """Which Wazuh API surface we pull FIM events from."""

    EVENTS = "events"  # GET /events?rule.groups=syscheck  (Wazuh >= 4.4)
    SYSCHECK = "syscheck"  # GET /syscheck/{agent_id}           (per-agent scans)


class Settings(BaseSettings):
    """Runtime settings, sourced from env vars (and optional .env)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Wazuh ---------------------------------------------------------------
    wazuh_api_url: str = Field(
        default="https://wazuh-manager:55000",
        description="Base URL of the Wazuh API (manager).",
    )
    wazuh_api_user: str = Field(default="wazuh")
    wazuh_api_password: str = Field(default="wazuh")
    wazuh_auth_strategy: AuthStrategy = AuthStrategy.JWT
    wazuh_api_verify_tls: bool = Field(
        default=True,
        description="Verify the Wazuh API TLS certificate.",
    )
    wazuh_source: Source = Source.EVENTS
    wazuh_agent_ids: str = Field(
        default="",
        description=(
            "Comma-separated agent IDs to poll when source=syscheck. "
            "Empty = all agents (paginated)."
        ),
    )
    wazuh_poll_interval_sec: int = Field(
        default=30, ge=5, description="Seconds between polls for new FIM events."
    )
    wazuh_page_size: int = Field(
        default=250, ge=10, le=2000, description="Page size for Wazuh API queries."
    )
    wazuh_request_timeout_sec: float = Field(default=15.0, ge=1.0)
    wazuh_max_events_per_cycle: int = Field(
        default=1000, ge=1, description="Hard cap on events processed per poll cycle."
    )

    # --- Telegram ------------------------------------------------------------
    telegram_bot_token: str = Field(
        default="",
        description="Bot token from @BotFather. Required for the bot + notifier.",
    )
    telegram_chat_id: str = Field(
        default="",
        description="Default chat / channel ID to push alerts to.",
    )
    telegram_allowed_user_ids: str = Field(
        default="",
        description=(
            "Comma-separated Telegram user IDs allowed to issue bot commands. "
            "Empty = allow anyone (not recommended)."
        ),
    )
    telegram_send_timeout_sec: float = Field(default=10.0, ge=1.0)

    # --- Rules / behaviour ---------------------------------------------------
    rules_path: Path | None = Field(
        default=None,
        description="Path to the YAML rules file. If unset, no rules are applied.",
    )
    state_path: Path = Field(
        default=Path("/var/lib/wazuh-fim-telegram/state.sqlite"),
        description="SQLite database path (last-seen event id, mute list, counters).",
    )
    digest_cron: str = Field(
        default="0 9 * * *",
        description="APScheduler cron expression for the daily digest (server local time).",
    )
    digest_timezone: str = Field(default="UTC")

    # --- Logging -------------------------------------------------------------
    log_level: str = Field(default="INFO")
    log_format: str = Field(
        default="json",
        description="'json' (production) or 'console' (colored local dev).",
    )

    @field_validator("telegram_bot_token")
    @classmethod
    def _token_nonempty_when_set(cls, v: str) -> str:
        # Allow empty during config validation; the CLI / bot will refuse to
        # start without it.
        return v.strip()

    @field_validator("wazuh_agent_ids")
    @classmethod
    def _strip_agent_ids(cls, v: str) -> str:
        return ",".join(part.strip() for part in v.split(",") if part.strip())

    @field_validator("telegram_allowed_user_ids")
    @classmethod
    def _strip_users(cls, v: str) -> str:
        return ",".join(part.strip() for part in v.split(",") if part.strip())

    def allowed_user_ids(self) -> set[int]:
        if not self.telegram_allowed_user_ids:
            return set()
        return {int(uid) for uid in self.telegram_allowed_user_ids.split(",")}

    def agent_ids(self) -> list[str]:
        if not self.wazuh_agent_ids:
            return []
        return self.wazuh_agent_ids.split(",")

    def as_logging_dict(self) -> dict[str, Any]:
        """Return a sanitized dict suitable for logging at startup."""
        return {
            "wazuh_api_url": self.wazuh_api_url,
            "wazuh_auth_strategy": self.wazuh_auth_strategy.value,
            "wazuh_source": self.wazuh_source.value,
            "wazuh_agent_ids": self.agent_ids(),
            "wazuh_poll_interval_sec": self.wazuh_poll_interval_sec,
            "wazuh_page_size": self.wazuh_page_size,
            "telegram_chat_id": self.telegram_chat_id or "<unset>",
            "telegram_allowed_users": sorted(self.allowed_user_ids()),
            "rules_path": str(self.rules_path) if self.rules_path else None,
            "state_path": str(self.state_path),
            "digest_cron": self.digest_cron,
            "log_level": self.log_level,
            "log_format": self.log_format,
        }


# A module-level singleton, lazily initialized. Tests construct Settings()
# directly so they can override env vars per-test.
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset the cached settings (used by tests)."""
    global _settings
    _settings = None


class RuntimeContext(BaseModel):
    """Mutable runtime context shared between the bot, notifier and digest."""

    settings: Settings
    muted_rule_ids: set[str] = Field(default_factory=set)
    muted_paths: set[str] = Field(default_factory=set)
