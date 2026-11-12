"""Telegram notifier.

Formats a :class:`FimEvent` into a compact Telegram message (HTML) and sends
it via the Bot API. Uses ``httpx`` directly rather than python-telegram-bot
so the notifier can be used standalone (e.g. from ``send-test-alert.sh``)
without spinning up the full bot.

The notifier is responsible for:
  - HTML escaping
  - Severity emoji + monospace path formatting
  - Optional diff-style "before/after" summary for changed fields
  - Retry with exponential backoff on Telegram 5xx / network errors

It does NOT decide who to send to — that's the bot's job using the rule
engine's ``chat_id_override`` or the default chat from settings.
"""

from __future__ import annotations

import asyncio
import html
import time
from dataclasses import dataclass

import httpx

from .logging_setup import get_logger
from .models import FimEvent, Severity

log = get_logger(__name__)

_SEVERITY_EMOJI = {
    Severity.INFO: "🟢",
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
    Severity.UNKNOWN: "⚪",
}
_SEVERITY_TAG = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
    Severity.UNKNOWN: "UNKNOWN",
}

# Telegram hard limit per message. We leave headroom for the wrapper.
_MAX_MSG_CHARS = 3800
_TRUNCATED_TAIL = "\n…[truncated]"


@dataclass
class SendResult:
    ok: bool
    message_id: int | None = None
    error: str = ""


class Notifier:
    """Send formatted FIM alerts to Telegram."""

    API_BASE = "https://api.telegram.org"

    def __init__(
        self,
        bot_token: str,
        *,
        timeout: float = 10.0,
        max_retries: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not bot_token:
            raise ValueError("bot_token is required")
        self._token = bot_token
        self._timeout = timeout
        self._max_retries = max_retries
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "Notifier":
        self._client = self._make_client()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.API_BASE,
            timeout=httpx.Timeout(self._timeout),
            transport=self._transport,
        )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._make_client()
        return self._client

    # --- formatting ----------------------------------------------------------

    @staticmethod
    def format_event(event: FimEvent) -> str:
        return _format_event(event)

    # --- sending -------------------------------------------------------------

    async def send_alert(self, event: FimEvent, chat_id: str) -> SendResult:
        return await self.send_text(self.format_event(event), chat_id)

    async def send_text(self, text: str, chat_id: str) -> SendResult:
        if not chat_id:
            return SendResult(ok=False, error="chat_id is empty")
        body = text[:_MAX_MSG_CHARS]
        if len(text) > _MAX_MSG_CHARS:
            body += _TRUNCATED_TAIL

        client = await self._ensure_client()
        url = f"/bot{self._token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": body,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        last_err = ""
        for attempt in range(self._max_retries):
            try:
                resp = await client.post(url, json=payload)
            except httpx.HTTPError as exc:
                last_err = f"network: {exc}"
                await asyncio.sleep(0.5 * (2 ** attempt))
                continue

            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    msg_id = (data.get("result") or {}).get("message_id")
                    log.info(
                        "telegram.sent",
                        chat_id=chat_id,
                        message_id=msg_id,
                        chars=len(body),
                    )
                    return SendResult(ok=True, message_id=msg_id)
                last_err = f"telegram ok=false: {data.get('description')}"
            elif resp.status_code in (400, 403):
                # Bad request / chat not found / bot blocked — don't retry.
                log.warning(
                    "telegram.send.bad_request",
                    chat_id=chat_id,
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return SendResult(
                    ok=False, error=f"telegram {resp.status_code}: {resp.text[:200]}"
                )
            else:
                last_err = f"telegram status {resp.status_code}"
                await asyncio.sleep(0.5 * (2 ** attempt))

        log.error("telegram.send.failed", chat_id=chat_id, error=last_err)
        return SendResult(ok=False, error=last_err)


def _format_event(event: FimEvent) -> str:
    emoji = _SEVERITY_EMOJI.get(event.severity, _SEVERITY_EMOJI[Severity.UNKNOWN])
    tag = _SEVERITY_TAG.get(event.severity, "UNKNOWN")

    lines: list[str] = []
    lines.append(f"{emoji} <b>FIM alert</b>  <b>[{tag}]</b>")
    lines.append("")
    if event.rule_description:
        lines.append(f"<b>Rule:</b> #{html.escape(event.rule_id)} — "
                     f"{html.escape(event.rule_description)}")
    else:
        lines.append(f"<b>Rule:</b> #{html.escape(event.rule_id)}")
    lines.append(f"<b>Action:</b> {html.escape(event.action.value.upper())}")
    lines.append(f"<b>Agent:</b> {html.escape(event.agent_name)} "
                 f"(<code>{html.escape(event.agent_id)}</code>)")
    lines.append(f"<b>Path:</b> <code>{html.escape(event.file_path)}</code>")

    changed = event.changed_fields()
    if changed:
        lines.append("")
        lines.append("<b>Changed fields:</b> " + ", ".join(html.escape(f) for f in changed))
        if "hash" in changed:
            before = event.file_before_hash[:16] or "—"
            after = event.file_after_hash[:16] or "—"
            lines.append(f"  hash: <code>{html.escape(before)}</code> → "
                         f"<code>{html.escape(after)}</code>")
        if "perm" in changed:
            lines.append(f"  perm: <code>{html.escape(event.file_before_perm)}</code> → "
                         f"<code>{html.escape(event.file_after_perm)}</code>")
        if "owner" in changed:
            lines.append(f"  owner: <code>{html.escape(event.file_owner_before)}</code> → "
                         f"<code>{html.escape(event.file_owner_after)}</code>")
        if "size" in changed and event.file_size_before is not None \
                and event.file_size_after is not None:
            lines.append(f"  size: <code>{event.file_size_before}</code> → "
                         f"<code>{event.file_size_after}</code>")

    if event.timestamp:
        lines.append("")
        lines.append(f"<i>ts: {html.escape(event.timestamp)}</i>")

    return "\n".join(lines)


def format_digest(summary: dict) -> str:
    """Render a daily digest payload (from State.daily_summary) as HTML."""
    day = summary.get("day", "—")
    total = int(summary.get("total", 0))
    by_sev = summary.get("by_severity", {}) or {}
    by_agent = summary.get("by_agent", {}) or {}

    lines: list[str] = []
    lines.append("📊 <b>Daily FIM digest</b>")
    lines.append(f"<i>{html.escape(str(day))}</i>")
    lines.append("")
    lines.append(f"<b>Total events:</b> {total}")

    if by_sev:
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        rendered = []
        for sev in sev_order:
            n = by_sev.get(sev)
            if n:
                rendered.append(f"{sev}={n}")
        for sev, n in by_sev.items():
            if sev not in sev_order:
                rendered.append(f"{sev}={n}")
        if rendered:
            lines.append("<b>By severity:</b> " + ", ".join(html.escape(r) for r in rendered))

    if by_agent:
        agents_sorted = sorted(by_agent.items(), key=lambda kv: kv[1], reverse=True)
        rendered = ", ".join(f"{a}={n}" for a, n in agents_sorted[:8])
        lines.append("<b>Top agents:</b> " + html.escape(rendered))

    lines.append("")
    lines.append("<i>Mute noisy rules with /mute &lt;rule_id&gt; &lt;hours&gt;</i>")
    return "\n".join(lines)


def epoch_now() -> int:
    return int(time.time())

