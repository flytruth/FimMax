"""Shared pytest fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make the package importable when running from a source checkout without
# installation.
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from wazuh_fim_telegram.config import Settings  # noqa: E402


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_events_payload(fixtures_dir: Path) -> list[dict]:
    return json.loads((fixtures_dir / "sample_events.json").read_text())


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        wazuh_api_url="https://wazuh.test:55000",
        wazuh_api_user="wazuh",
        wazuh_api_password="wazuh",
        wazuh_auth_strategy="jwt",
        wazuh_api_verify_tls=False,
        wazuh_source="events",
        wazuh_poll_interval_sec=5,
        wazuh_page_size=50,
        telegram_bot_token="123:abc",
        telegram_chat_id="-100123456",
        telegram_allowed_user_ids="111,222",
        rules_path=None,
        state_path=tmp_path / "state.sqlite",
        log_level="DEBUG",
        log_format="console",
    )


@pytest.fixture
def state(tmp_path: Path):
    from wazuh_fim_telegram.state import State

    s = State(tmp_path / "state.sqlite")
    yield s
    s.close()
