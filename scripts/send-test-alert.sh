#!/usr/bin/env bash
#
# send-test-alert.sh — quick smoke test for the Telegram integration.
#
# Sends a synthetic high-severity FIM alert to the configured chat without
# contacting Wazuh. Use this after first setup to confirm the bot token and
# chat id are correct.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

CHAT_ID="${1:-${TELEGRAM_CHAT_ID:-}}"
if [[ -z "${CHAT_ID}" ]]; then
  echo "usage: $0 [chat_id]" >&2
  echo "  (or set TELEGRAM_CHAT_ID)" >&2
  exit 64
fi

cd "${REPO_ROOT}"
export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PYTHON:-python3}" -m wazuh_fim_telegram send-test --chat-id "${CHAT_ID}"
