"""Telegram bot + background FIM poller.

Single asyncio process that:
  1. Polls the Wazuh API for new FIM events every N seconds.
  2. For each event: parses, evaluates rules, skips muted, records in state,
     and forwards to Telegram.
  3. Runs an interactive bot with the commands:

       /start, /help        — quick usage
       /status              — health + counters + last poll
       /alerts [n]          — last n recent FIM alerts
       /fim <path>          — recent alerts matching path substring
       /mute <rule_id> [h]  — mute a rule for N hours (default 1h)
       /unmute <rule_id>    — lift a rule mute
       /mutes               — list active mutes
       /digest              — fire the daily digest immediately

Access control: if ``settings.allowed_user_ids()`` is non-empty, only those
Telegram user IDs may issue commands. Pushed alerts go to the configured chat
regardless.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from telegram import Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

from .config import Settings
from .logging_setup import get_logger
from .logging_setup import request_id as request_id_ctx
from .models import FimEvent, parse_many
from .notifier import Notifier
from .rules import RuleEngine
from .state import State
from .wazuh_client import WazuhAPIError, WazuhClient

log = get_logger(__name__)


@dataclass
class PollerStats:
    """Lightweight stats for /status. Not persisted."""

    cycles: int = 0
    events_seen: int = 0
    events_forwarded: int = 0
    events_dropped: int = 0
    events_muted: int = 0
    last_poll_at: str = ""
    last_poll_duration_ms: int = 0
    last_error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "cycles": self.cycles,
            "events_seen": self.events_seen,
            "events_forwarded": self.events_forwarded,
            "events_dropped": self.events_dropped,
            "events_muted": self.events_muted,
            "last_poll_at": self.last_poll_at,
            "last_poll_duration_ms": self.last_poll_duration_ms,
            "last_error": self.last_error,
        }


class FimBot:
    """Glue between Wazuh, rules, state, notifier and the Telegram bot."""

    def __init__(
        self,
        settings: Settings,
        *,
        wazuh_client: WazuhClient | None = None,
        notifier: Notifier | None = None,
        state: State | None = None,
        rules: RuleEngine | None = None,
    ) -> None:
        self.settings = settings
        self._owns_client = wazuh_client is None
        self._owns_notifier = notifier is None
        self._owns_state = state is None
        self.wazuh = wazuh_client or WazuhClient(settings)
        self.notifier = notifier or Notifier(
            settings.telegram_bot_token,
            timeout=settings.telegram_send_timeout_sec,
        )
        self.state = state or State(settings.state_path)
        self.rules = rules or (
            RuleEngine.from_file(settings.rules_path) if settings.rules_path else RuleEngine.empty()
        )
        self.stats = PollerStats()
        self._app: Application[Any, Any, Any, Any, Any, Any] | None = None
        self._poller_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    # --- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        log.info("bot.startup", settings=self.settings.as_logging_dict())

        if not self.settings.telegram_bot_token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
        if not self.settings.telegram_chat_id:
            log.warning("bot.startup.no_default_chat_id")

        self._app = ApplicationBuilder().token(self.settings.telegram_bot_token).build()
        self._register_handlers()

        await self.wazuh.__aenter__()
        await self.notifier.__aenter__()

        await self._app.initialize()
        await self._app.start()
        if self._app.updater is not None:
            await self._app.updater.start_polling(drop_pending_updates=True)

        # Kick off the poller in the background. We keep a reference so the
        # task isn't garbage-collected mid-flight (python asyncio caveat).
        self._poller_task = asyncio.create_task(self._poll_loop(), name="fim-poller")

    async def stop(self) -> None:
        log.info("bot.shutdown")
        self._stop.set()
        if self._app is not None:
            if self._app.updater is not None:
                await self._app.updater.stop()
            if self._app.running:
                await self._app.stop()
            await self._app.shutdown()
        if self._owns_client:
            await self.wazuh.aclose()
        if self._owns_notifier:
            await self.notifier.aclose()
        if self._owns_state:
            self.state.close()

    # --- handlers registration ----------------------------------------------

    def _register_handlers(self) -> None:
        assert self._app is not None
        for cmd, fn in [
            ("start", self._cmd_start),
            ("help", self._cmd_help),
            ("status", self._cmd_status),
            ("alerts", self._cmd_alerts),
            ("fim", self._cmd_fim),
            ("mute", self._cmd_mute),
            ("unmute", self._cmd_unmute),
            ("mutes", self._cmd_mutes),
            ("digest", self._cmd_digest),
        ]:
            self._app.add_handler(CommandHandler(cmd, fn))

    def _authorized(self, update: Update) -> bool:
        allowed = self.settings.allowed_user_ids()
        if not allowed:
            return True
        user = update.effective_user
        if user is None:
            return False
        return user.id in allowed

    @staticmethod
    def _msg(update: Update) -> Any:
        """Return the effective message, asserting it's present.

        Telegram guarantees an :class:`Update.message` for command handlers;
        this just narrows the Optional for mypy.
        """
        msg = update.effective_message
        assert msg is not None
        return msg

    # --- commands ------------------------------------------------------------

    async def _cmd_start(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        await self._msg(update).reply_text("Wazuh FIM bot is running. Try /help for commands.")

    async def _cmd_help(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        text = (
            "<b>Wazuh FIM bot — commands</b>\n\n"
            "/status — health + counters + last poll\n"
            "/alerts [n] — last n recent FIM alerts (default 10)\n"
            "/fim &lt;path&gt; — recent alerts matching path substring\n"
            "/mute &lt;rule_id&gt; [hours] — mute a rule (default 1h)\n"
            "/unmute &lt;rule_id&gt; — lift a rule mute\n"
            "/mutes — list active mutes\n"
            "/digest — send the daily digest now"
        )
        await self._msg(update).reply_text(text, parse_mode="HTML")

    async def _cmd_status(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        s = self.settings
        st = self.stats.as_dict()
        last_seen = self.state.get_last_seen_id(s.wazuh_source.value)
        mutes = self.state.list_muted_rules()
        msg = (
            "<b>Wazuh FIM bot status</b>\n\n"
            f"<b>Wazuh:</b> {s.wazuh_api_url}\n"
            f"<b>Source:</b> {s.wazuh_source.value}\n"
            f"<b>Poll interval:</b> {s.wazuh_poll_interval_sec}s\n"
            f"<b>Last seen id:</b> <code>{last_seen or 'none'}</code>\n"
            f"<b>Cycles:</b> {st['cycles']}  "
            f"seen={st['events_seen']}  fwd={st['events_forwarded']}  "
            f"dropped={st['events_dropped']}  muted={st['events_muted']}\n"
            f"<b>Last poll:</b> {st['last_poll_at'] or 'never'} "
            f"({st['last_poll_duration_ms']} ms)\n"
            f"<b>Active mutes:</b> {len(mutes)}\n"
            f"<b>Last error:</b> <code>{st['last_error'] or 'none'}</code>"
        )
        await self._msg(update).reply_text(msg, parse_mode="HTML")

    async def _cmd_alerts(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        n = _parse_int(ctx.args, 0, default=10, minimum=1, maximum=50)
        rows = self.state.recent_events(limit=n)
        if not rows:
            await self._msg(update).reply_text("No recent alerts.")
            return
        lines = ["<b>Recent FIM alerts</b>\n"]
        for r in rows:
            lines.append(
                f"• [{r['severity'].upper()}] <code>{r['file_path']}</code> "
                f"({r['action']}, agent={r['agent_id']}, rule=#{r['rule_id']})\n"
                f"  <i>{r['ts']}</i>"
            )
        await self._msg(update).reply_text("\n".join(lines), parse_mode="HTML")

    async def _cmd_fim(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        if not ctx.args:
            await self._msg(update).reply_text(
                "Usage: /fim &lt;path-substring&gt;", parse_mode="HTML"
            )
            return
        needle = ctx.args[0]
        rows = self.state.recent_events(limit=100)
        matches = [r for r in rows if needle in r["file_path"]][:10]
        if not matches:
            await self._msg(update).reply_text(
                f"No recent alerts matching <code>{needle}</code>.",
                parse_mode="HTML",
            )
            return
        lines = [f"<b>Alerts matching</b> <code>{needle}</code>\n"]
        for r in matches:
            lines.append(
                f"• [{r['severity'].upper()}] <code>{r['file_path']}</code> "
                f"({r['action']}, rule=#{r['rule_id']}, {r['ts']})"
            )
        await self._msg(update).reply_text("\n".join(lines), parse_mode="HTML")

    async def _cmd_mute(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        if not ctx.args:
            await self._msg(update).reply_text(
                "Usage: /mute &lt;rule_id&gt; [hours]", parse_mode="HTML"
            )
            return
        rule_id = ctx.args[0]
        hours = _parse_int(ctx.args, 1, default=1, minimum=1, maximum=24 * 30)
        until = self.state.mute_rule(
            rule_id,
            hours * 3600,
            reason=f"telegram:{update.effective_user.id if update.effective_user else 'unknown'}",
        )
        until_str = datetime.fromtimestamp(until, tz=timezone.utc).isoformat()
        await self._msg(update).reply_text(
            f"Muted rule <code>{rule_id}</code> for {hours}h (until {until_str}).",
            parse_mode="HTML",
        )

    async def _cmd_unmute(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        if not ctx.args:
            await self._msg(update).reply_text("Usage: /unmute &lt;rule_id&gt;", parse_mode="HTML")
            return
        rule_id = ctx.args[0]
        ok = self.state.unmute_rule(rule_id)
        await self._msg(update).reply_text(
            f"{'Lifted' if ok else 'No'} mute for rule <code>{rule_id}</code>.",
            parse_mode="HTML",
        )

    async def _cmd_mutes(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        mutes = self.state.list_muted_rules()
        if not mutes:
            await self._msg(update).reply_text("No active mutes.")
            return
        lines = ["<b>Active mutes</b>\n"]
        for m in mutes:
            until = datetime.fromtimestamp(m["until_ts"], tz=timezone.utc).isoformat()
            lines.append(
                f"• rule <code>{m['rule_id']}</code> until {until}"
                f" (reason: {m['reason'] or '—'})"
            )
        await self._msg(update).reply_text("\n".join(lines), parse_mode="HTML")

    async def _cmd_digest(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update):
            return
        await self._msg(update).reply_text("Sending digest to default chat…")
        # Imported lazily to avoid a circular import at module load.
        from .digest import DigestJob

        job = DigestJob(self.settings, self.state, self.notifier)
        await job.run_now()

    # --- poller --------------------------------------------------------------

    async def _poll_loop(self) -> None:
        interval = self.settings.wazuh_poll_interval_sec
        source_key = self.settings.wazuh_source.value
        log.info("poller.start", interval_sec=interval, source=source_key)

        while not self._stop.is_set():
            t0 = time.monotonic()
            request_id_ctx.set(f"poll-{self.stats.cycles + 1}")
            try:
                since = self.state.get_last_seen_id(source_key)
                raw_events = await self.wazuh.fetch_fim_events(since)
                events = parse_many(raw_events)
                await self._process_events(events)
                self.stats.last_error = ""
            except (WazuhAPIError, httpx.HTTPError) as exc:
                self.stats.last_error = str(exc)
                log.warning("poller.cycle.error", error=str(exc))
            finally:
                self.stats.cycles += 1
                self.stats.last_poll_at = datetime.now(tz=timezone.utc).isoformat()
                self.stats.last_poll_duration_ms = int((time.monotonic() - t0) * 1000)
                request_id_ctx.set(None)

            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=interval)

        log.info("poller.stop")

    async def _process_events(self, events: list[FimEvent]) -> None:
        if not events:
            log.debug("poller.cycle.empty")
            return

        self.stats.events_seen += len(events)
        log.info("poller.events.received", count=len(events))

        last_id: str | None = None
        for ev in events:
            decision = self.rules.evaluate(ev)

            # Rule-level mute + ad-hoc mute (from /mute command).
            if decision.action == "mute" or self.state.is_rule_muted(ev.rule_id):
                self.stats.events_muted += 1
                log.info(
                    "fim.event.muted",
                    event_id=ev.event_id,
                    rule_id=ev.rule_id,
                    path=ev.file_path,
                    reason=decision.reason,
                )
                continue

            if decision.action == "drop":
                self.stats.events_dropped += 1
                log.info(
                    "fim.event.dropped",
                    event_id=ev.event_id,
                    reason=decision.reason,
                )
                continue

            # pass
            self.state.record_event(ev)
            chat_id = decision.chat_id_override or self.settings.telegram_chat_id
            if not chat_id:
                log.warning("fim.event.no_chat", event_id=ev.event_id)
                continue
            result = await self.notifier.send_alert(ev, chat_id)
            if result.ok:
                self.stats.events_forwarded += 1
            else:
                log.warning(
                    "fim.event.forward_failed",
                    event_id=ev.event_id,
                    error=result.error,
                )
            last_id = ev.event_id

        if last_id:
            self.state.set_last_seen_id(self.settings.wazuh_source.value, last_id)


def _parse_int(
    args: list[str] | None,
    index: int,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if args is None or index >= len(args):
        return default
    try:
        v = int(args[index])
    except ValueError:
        return default
    return max(minimum, min(maximum, v))
