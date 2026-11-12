"""Structured logging setup.

Uses structlog to emit JSON lines on stdout by default, with a human-readable
fallback for local development controlled by the ``LOG_FORMAT`` env var.

Every log record carries:
  - ``ts``     ISO-8601 timestamp in UTC
  - ``level``  log level
  - ``event``  short event name (snake_case)
  - ``logger`` logger name
  - any extra structured fields the caller passes

A ``request_id`` context var is propagated so a single FIM event poll cycle can
be traced through client → rules → notifier → bot.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog
import structlog.types

request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def _add_request_id(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    rid = request_id.get()
    if rid:
        event_dict["request_id"] = rid
    return event_dict


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure structlog + stdlib logging.

    Args:
        level: logging level name (DEBUG, INFO, WARNING, ERROR).
        fmt:   ``json`` (default, for production) or ``console`` (colored,
               human-readable, for local development).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Renderers
    if fmt == "console":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_request_id,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib logging so libraries (httpx, telegram) also emit JSON.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared_processors,
            processor=renderer,
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(log_level)

    # Silence chatty libs that we re-log ourselves.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.INFO)


def get_logger(name: str | None = None) -> Any:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
