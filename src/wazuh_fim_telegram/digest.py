"""Daily digest scheduler.

Uses APScheduler to fire the digest at ``settings.digest_cron``. The digest:
  1. Pulls today's summary from :class:`State`.
  2. Renders it via :func:`Notifier.format_digest`.
  3. Sends it to the default Telegram chat.

The scheduler runs in the same asyncio loop as the bot.
"""

from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from .config import Settings
from .logging_setup import get_logger
from .notifier import Notifier, format_digest
from .state import State

log = get_logger(__name__)


class DigestJob:
    """Wraps the scheduler + the actual digest task."""

    def __init__(
        self,
        settings: Settings,
        state: State,
        notifier: Notifier,
        *,
        scheduler: AsyncIOScheduler | None = None,
    ) -> None:
        self._settings = settings
        self._state = state
        self._notifier = notifier
        self._scheduler = scheduler or AsyncIOScheduler(timezone=settings.digest_timezone)

    def start(self) -> None:
        trigger = CronTrigger.from_crontab(self._settings.digest_cron)
        self._scheduler.add_job(
            self.run_now,
            trigger=trigger,
            id="daily-digest",
            replace_existing=True,
            misfire_grace_time=3600,
            coalesce=True,
        )
        self._scheduler.start()
        log.info(
            "digest.scheduled",
            cron=self._settings.digest_cron,
            tz=self._settings.digest_timezone,
        )

    async def run_now(self) -> None:
        """Run the digest immediately. Public so the bot's /digest can call it."""
        summary = self._state.daily_summary()
        log.info("digest.run", total=summary["total"])
        if not self._settings.telegram_chat_id:
            log.warning("digest.no_chat_id")
            return
        text = format_digest(summary)
        result = await self._notifier.send_text(text, self._settings.telegram_chat_id)
        if not result.ok:
            log.error("digest.send_failed", error=result.error)

    def shutdown(self, wait: bool = True) -> None:
        try:
            self._scheduler.shutdown(wait=wait)
        except Exception as exc:
            log.warning("digest.shutdown.error", error=str(exc))
