"""Tests for config + CLI plumbing (lightweight)."""

from __future__ import annotations

from wazuh_fim_telegram import __version__
from wazuh_fim_telegram.cli import main


def test_version_command(capsys):
    rc = main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == __version__


def test_validate_config_missing_token(monkeypatch, capsys, tmp_path):
    # Force a settings instance with no token / chat id.
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "s.sqlite"))
    rc = main(["validate-config"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "TELEGRAM_BOT_TOKEN" in err


def test_validate_config_ok(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-1001")
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "s.sqlite"))
    rc = main(["validate-config"])
    assert rc == 0
    # Logging output may also be on stdout; just check OK is present.
    assert "OK" in capsys.readouterr().out
