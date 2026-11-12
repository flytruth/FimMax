"""Async Wazuh API client.

Handles:
  - JWT authentication (POST /security/user/authenticate) with token caching
    and automatic refresh on 401.
  - Pagination via Wazuh's ``offset`` / ``limit`` convention.
  - Polling for new FIM events since the last seen ID, using the configured
    :class:`Source`.

The client is intentionally thin: it does not interpret payloads. Parsing is
done by :func:`wazuh_fim_telegram.models.parse_many`.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .config import AuthStrategy, Settings, Source
from .logging_setup import get_logger

log = get_logger(__name__)

# Wazuh returns 401 with this body when the JWT token has expired.
_TOKEN_EXPIRED_HINT = "token"


class WazuhAPIError(RuntimeError):
    """Raised when the Wazuh API returns an unrecoverable error."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Wazuh API error {status}: {body[:200]}")
        self.status = status
        self.body = body


class WazuhClient:
    """Async client for the Wazuh REST API."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._client: httpx.AsyncClient | None = None
        self._transport = transport  # for tests (respx); None = real transport
        self._auth_lock = asyncio.Lock()

    async def __aenter__(self) -> "WazuhClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._settings.wazuh_api_url.rstrip("/"),
                timeout=httpx.Timeout(self._settings.wazuh_request_timeout_sec),
                verify=self._settings.wazuh_api_verify_tls,
                transport=self._transport,
                headers={"Accept": "application/json"},
            )
        return self._client

    # --- Auth ----------------------------------------------------------------

    async def _authenticate(self) -> str:
        """Obtain (or return cached) a bearer token."""
        if self._token and time.monotonic() < self._token_expires_at - 30:
            return self._token

        async with self._auth_lock:
            # Re-check inside the lock to avoid duplicate logins.
            if self._token and time.monotonic() < self._token_expires_at - 30:
                return self._token

            client = await self._ensure_client()
            if self._settings.wazuh_auth_strategy is AuthStrategy.BASIC:
                # Basic strategy: store credentials for every request.
                self._token = ""  # sentinel meaning "use basic auth"
                return ""

            log.info("wazuh.auth.request", user=self._settings.wazuh_api_user)
            resp = await client.post(
                "/security/user/authenticate",
                auth=(self._settings.wazuh_api_user, self._settings.wazuh_api_password),
            )
            if resp.status_code != 200:
                raise WazuhAPIError(resp.status_code, resp.text)
            body = resp.json()
            token = body.get("data", {}).get("token") or body.get("token")
            if not token:
                raise WazuhAPIError(resp.status_code, "no token in auth response")
            self._token = token
            # Wazuh tokens default to 900s; refresh 60s early.
            self._token_expires_at = time.monotonic() + 840
            log.info("wazuh.auth.success", ttl_sec=840)
            return token

    def _auth_headers(self) -> dict[str, str]:
        if self._settings.wazuh_auth_strategy is AuthStrategy.BASIC:
            return {}
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        client = await self._ensure_client()
        token = await self._authenticate()
        headers = self._auth_headers() if token != "" else {}
        if not token:
            # Basic strategy: pass auth on every request.
            headers = {}

        if self._settings.wazuh_auth_strategy is AuthStrategy.BASIC:
            auth = (self._settings.wazuh_api_user, self._settings.wazuh_api_password)
        else:
            auth = None

        resp = await client.request(
            method, path, params=params, headers=headers, auth=auth
        )

        if resp.status_code == 401 and self._settings.wazuh_auth_strategy is AuthStrategy.JWT:
            log.warning("wazuh.auth.expired", path=path)
            self._token = None
            self._token_expires_at = 0.0
            token = await self._authenticate()  # retry once
            resp = await client.request(
                method,
                path,
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )

        if resp.status_code >= 400:
            raise WazuhAPIError(resp.status_code, resp.text)
        return resp.json()

    # --- Public API ----------------------------------------------------------

    async def ping(self) -> bool:
        """Return True if the Wazuh API is reachable and credentials work."""
        try:
            body = await self._request("GET", "/")
            return bool(body)
        except (WazuhAPIError, httpx.HTTPError) as exc:
            log.warning("wazuh.ping.failed", error=str(exc))
            return False

    async def fetch_fim_events(self, since_id: str | None) -> list[dict[str, Any]]:
        """Fetch FIM events strictly newer than ``since_id``.

        Returns events in ascending order (oldest first). Pagination is
        transparent. The number of events returned is bounded by
        ``settings.wazuh_max_events_per_cycle``.
        """
        if self._settings.wazuh_source is Source.EVENTS:
            return await self._fetch_from_events(since_id)

        return await self._fetch_from_syscheck()

    async def _fetch_from_events(self, since_id: str | None) -> list[dict[str, Any]]:
        page_size = self._settings.wazuh_page_size
        max_events = self._settings.wazuh_max_events_per_cycle

        out: list[dict[str, Any]] = []
        offset = 0

        while len(out) < max_events:
            params: dict[str, Any] = {
                "limit": page_size,
                "offset": offset,
                # Filter: only events from the syscheck rule group.
                "rule.groups": "syscheck",
                # Most recent first; we reverse below to process oldest-first.
                "sort": "-id",
            }
            body = await self._request("GET", "/events", params=params)
            affected = _affected_items(body)
            if not affected:
                break

            # If we already know the last seen id, drop everything <= it.
            if since_id:
                kept = [e for e in affected if _id_of(e) > since_id]
            else:
                kept = list(affected)

            out.extend(kept)

            if len(affected) < page_size:
                break
            offset += page_size

            if not kept:
                # We're past the cursor window with no new events — stop.
                break

        out.sort(key=_id_of)
        return out[:max_events]

    async def _fetch_from_syscheck(self) -> list[dict[str, Any]]:
        agent_ids = self._settings.agent_ids()
        if not agent_ids:
            log.warning("wazuh.syscheck.no_agents")
            return []

        page_size = self._settings.wazuh_page_size
        out: list[dict[str, Any]] = []
        for agent_id in agent_ids:
            offset = 0
            while len(out) < self._settings.wazuh_max_events_per_cycle:
                params = {"limit": page_size, "offset": offset}
                body = await self._request(
                    "GET", f"/syscheck/{agent_id}", params=params
                )
                affected = _affected_items(body)
                if not affected:
                    break
                # Annotate each item with the agent id so parsing works.
                for item in affected:
                    item.setdefault("agent_id", agent_id)
                out.extend(affected)
                if len(affected) < page_size:
                    break
                offset += page_size
        return out[: self._settings.wazuh_max_events_per_cycle]


def _affected_items(body: dict[str, Any]) -> list[dict[str, Any]]:
    data = body.get("data") or {}
    if isinstance(data, dict):
        items = data.get("affected_items")
        if isinstance(items, list):
            return items
    # Some Wazuh endpoints return the list directly under "data".
    if isinstance(data, list):
        return data
    return []


def _id_of(payload: dict[str, Any]) -> str:
    return str(payload.get("id") or payload.get("_id") or "")
