"""Poll configured paths, compare them with the baseline, and emit FIM events.
The watchdog observer requests an immediate comparison. The poll interval
catches changes the observer misses, including edits made while this process
was stopped.
"""
from __future__ import annotations
import argparse
import json
import logging
import signal
import threading
from pathlib import Path
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from hasher import FileRecord, records_from_json, records_to_json, snapshot
from logger import build_event, write_event
_LOG = logging.getLogger("fim")
_EVENT_TYPES = ("CREATED", "MODIFIED", "DELETED", "RENAMED")
class Monitor:
    def __init__(self, config: dict, config_dir: Path):
        monitor = config["monitor"]
        self.hostname = str(config["agent"]["hostname"]).strip()
        self.interval = int(monitor["poll_interval_seconds"])
        self.paths = [_resolve(item, config_dir) for item in monitor["paths"]]
        self.baseline_file = _resolve(monitor["baseline_file"], config_dir)
        self.log_file = _resolve(monitor["log_file"], config_dir)
        self.severity = {key: str(value) for key, value in config["severity"].items()}
        self.siem = dict(config["siem"])
        self.baseline: dict[str, FileRecord] = {}
        self._lock = threading.Lock()
        self._scanning = False
        self._pending = False
    def load_baseline(self) -> bool:
        if not self.baseline_file.exists():
            return False
        payload = json.loads(self.baseline_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{self.baseline_file} must contain a JSON object")
        self.baseline = records_from_json(payload)
        return True
    def establish_baseline(self) -> int:
        records, warnings = self._capture()
        self._report_warnings(warnings)
        self.baseline = records
        self._save_baseline()
        return len(records)
    def scan(self) -> int:
        """Compare the filesystem with the baseline. Overlapping calls coalesce."""
        with self._lock:
            if self._scanning:
                self._pending = True
                return 0
            self._scanning = True
        emitted = 0
        try:
            while True:
                emitted += self._scan_once()
                with self._lock:
                    if not self._pending:
                        self._scanning = False
                        return emitted
                    self._pending = False
        except Exception:
            with self._lock:
                self._scanning = False
                self._pending = False
            raise
    def _scan_once(self) -> int:
        current, warnings = self._capture()
        self._report_warnings(warnings)
        events = diff_records(self.baseline, current)
        for event_type, file_path, before, after in events:
            write_event(
                build_event(
                    event_type=event_type,
                    file_path=file_path,
                    sha256_before=before,
                    sha256_after=after,
                    hostname=self.hostname,
                    severity=self.severity[event_type],
                ),
                self.log_file,
                self.siem,
            )
            _LOG.warning("%s %s", event_type, file_path)
        self.baseline = current
        self._save_baseline()
        return len(events)
    def _capture(self) -> tuple[dict[str, FileRecord], list[str]]:
        return snapshot(
            self.paths,
            retain=self.baseline,
            exclude={self.baseline_file, self.log_file, _temp_baseline(self.baseline_file)},
        )
    def _save_baseline(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = _temp_baseline(self.baseline_file)
        temporary.write_text(
            json.dumps(records_to_json(self.baseline), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.baseline_file)
    @staticmethod
    def _report_warnings(warnings: list[str]) -> None:
        for warning in warnings:
            _LOG.warning("%s", warning)
def diff_records(
    previous: dict[str, FileRecord],
