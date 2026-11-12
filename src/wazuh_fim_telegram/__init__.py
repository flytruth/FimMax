"""wazuh-fim-telegram — Wazuh FIM alerts to Telegram.

A small, opinionated bridge that polls the Wazuh REST API for File Integrity
Monitoring (syscheck) events, applies user-defined rules, and forwards the
matching ones to a Telegram chat. Ships an interactive bot, a daily digest,
structured JSON logs and Docker packaging.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__ = "1.0.0"
