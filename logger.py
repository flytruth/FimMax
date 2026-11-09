"""Write one FIM event per line and optionally forward the same object."""
from __future__ import annotations
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
import requests
EVENT_TYPES = ("CREATED", "MODIFIED", "DELETED", "RENAMED")
_FIELD_ORDER = (
    "timestamp",
    "event_type",
    "file_path",
    "sha256_before",
    "sha256_after",
    "hostname",
    "severity",
)
_LOCK = threading.Lock()
_LOG = logging.getLogger("fim.logger")
def utc_now() -> str:
    """UTC timestamp with a Z suffix and no fractional seconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def build_event(
    event_type: str,
    file_path: str,
    sha256_before: str,
    sha256_after: str,
    hostname: str,
    severity: str,
    timestamp: str | None = None,
) -> dict[str, str]:
    """Return an event dict whose keys match the required SIEM schema."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unsupported event type: {event_type}")
    return {
        "timestamp": timestamp or utc_now(),
        "event_type": event_type,
        "file_path": file_path,
        "sha256_before": sha256_before,
        "sha256_after": sha256_after,
        "hostname": hostname,
        "severity": severity,
    }
def write_event(event: dict[str, str], log_file: Path, siem: dict) -> None:
    """Append ``event`` as one JSON object and forward it when configured."""
    ordered = {key: event[key] for key in _FIELD_ORDER}
    line = json.dumps(ordered, ensure_ascii=True, separators=(", ", ": "))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        _allow_wazuh_read(log_file)
    _forward(ordered, siem)
def _allow_wazuh_read(log_file: Path) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(log_file, 0o640)
    except OSError as exc:
        _LOG.warning("could not set permissions on %s: %s", log_file, exc)
def _forward(event: dict[str, str], siem: dict) -> None:
    if not siem.get("forward_enabled"):
        return
    url = str(siem.get("forward_url") or "").strip()
    if not url:
        _LOG.warning("SIEM forwarding is enabled but forward_url is empty")
        return
    try:
        response = requests.post(
            url,
            json=event,
            timeout=float(siem.get("timeout_seconds") or 5),
            verify=bool(siem.get("verify_tls", True)),
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        _LOG.warning("SIEM forward failed for %s: %s", event.get("file_path"), exc)
