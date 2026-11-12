"""CLI entrypoint.

Subcommands:
  run              Start the bot + poller (default).
  validate-config  Load and print the resolved settings without contacting
                   any external service.
  send-test        Send a synthetic FIM alert to the configured chat. Useful
                   for verifying the Telegram bot token + chat id.
  digest-now       Compute today's digest from the state DB and print it
                   (does not send to Telegram unless --send is given).
  version          Print the version.

Designed to be wrapped by ``scripts/fim-watcher.sh``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

from . import __version__
from .config import Settings, get_settings, reset_settings
from .logging_setup import configure_logging, get_logger

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wazuh-fim-telegram",
        description="Wazuh FIM alerts → Telegram bot.",
    )
    p.add_argument(
        "--log-level",
        default=None,
        help="Override LOG_LEVEL (DEBUG, INFO, WARNING, ERROR).",
    )
    p.add_argument(
        "--log-format",
        choices=["json", "console"],
        default=None,
        help="Override LOG_FORMAT.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="Start the bot + poller (default).")
    sub.add_parser("validate-config", help="Load and print resolved settings.")

    st = sub.add_parser("send-test", help="Send a synthetic FIM alert.")
    st.add_argument(
        "--chat-id",
        default=None,
        help="Override TELEGRAM_CHAT_ID for this invocation.",
    )

    dn = sub.add_parser("digest-now", help="Compute and optionally send the digest.")
    dn.add_argument("--send", action="store_true", help="Send to Telegram chat.")

    sub.add_parser("version", help="Print version and exit.")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    reset_settings()
    settings = get_settings()

    log_level = args.log_level or settings.log_level
    log_format = args.log_format or settings.log_format
    configure_logging(level=log_level, fmt=log_format)

    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "validate-config":
        return _cmd_validate_config(settings)

    if args.command == "send-test":
        return asyncio.run(_cmd_send_test(settings, chat_id=args.chat_id))

    if args.command == "digest-now":
        return asyncio.run(_cmd_digest_now(settings, send=args.send))

    # "run"
    return asyncio.run(_cmd_run(settings))


def _cmd_validate_config(settings: Settings) -> int:
    log.info("config.resolved", **settings.as_logging_dict())
    issues: list[str] = []
    if not settings.telegram_bot_token:
        issues.append("TELEGRAM_BOT_TOKEN is not set")
    if not settings.telegram_chat_id:
        issues.append("TELEGRAM_CHAT_ID is not set")
    if not settings.wazuh_api_url.startswith(("http://", "https://")):
        issues.append(f"WAZUH_API_URL is not a URL: {settings.wazuh_api_url!r}")

    if settings.rules_path and not settings.rules_path.exists():
        issues.append(f"rules_path does not exist: {settings.rules_path}")

    if issues:
        for i in issues:
            log.error("config.invalid", issue=i)
        print("\n".join(issues), file=sys.stderr)
        return 2

    print("OK")
    return 0


async def _cmd_send_test(settings: Settings, *, chat_id: str | None) -> int:
    from .models import ActionType, FimEvent, Severity
    from .notifier import Notifier

    target = chat_id or settings.telegram_chat_id
    if not settings.telegram_bot_token:
        print("TELEGRAM_BOT_TOKEN is not set", file=sys.stderr)
        return 2
    if not target:
        print("TELEGRAM_CHAT_ID is not set", file=sys.stderr)
        return 2

    event = FimEvent(
        event_id="test-0001",
        rule_id="554",
        rule_description="Test alert from wazuh-fim-telegram CLI",
        agent_id="000",
        agent_name="wazuh-manager",
        severity=Severity.HIGH,
        action=ActionType.MODIFIED,
        file_path="/etc/wazuh-fim-telegram/test-alert",
        file_before_hash="a1b2c3...",
        file_after_hash="d4e5f6...",
        file_before_perm="0644",
        file_after_perm="0640",
        file_owner_before="root",
        file_owner_after="wazuh",
        file_size_before=1024,
        file_size_after=2048,
        timestamp="1970-01-01T00:00:00Z",
    )

    async with Notifier(settings.telegram_bot_token) as notifier:
        result = await notifier.send_alert(event, target)
    if result.ok:
        print(f"sent: message_id={result.message_id}")
        return 0
    print(f"failed: {result.error}", file=sys.stderr)
    return 1


async def _cmd_digest_now(settings: Settings, *, send: bool) -> int:
    from .digest import DigestJob
    from .notifier import Notifier
    from .state import State

    state = State(settings.state_path)
    notifier = Notifier(settings.telegram_bot_token)
    async with notifier:
        job = DigestJob(settings, state, notifier)
        if send:
            await job.run_now()
            print("digest sent")
        else:
            summary = state.daily_summary()
            from .notifier import format_digest

            print(format_digest(summary))
    state.close()
    return 0


async def _cmd_run(settings: Settings) -> int:
    from .bot import FimBot

    bot = FimBot(settings)
    try:
        await bot.start()
        # Run forever until Ctrl-C / SIGTERM. The stop signal is handled by
        # python-telegram-bot's signal handlers.
        from asyncio import Event

        stop = Event()
        # PTB installs signal handlers; we just wait until the loop is
        # cancelled.
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await bot.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
