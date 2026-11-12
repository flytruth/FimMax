#!/usr/bin/env bash
#
# fim-watcher.sh — thin wrapper around the Python entrypoint.
#
# Loads .env (if present) in a pure-bash way (no dotenv dependency), then
# execs the Python module. Designed to be the Docker CMD and the systemd
# ExecStart.
#
# Usage:
#   ./scripts/fim-watcher.sh run             # start bot + poller (default)
#   ./scripts/fim-watcher.sh validate-config
#   ./scripts/fim-watcher.sh send-test
#   ./scripts/fim-watcher.sh digest-now
#
# Env vars (all optional, see .env.example for the full list):
#   WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,
#   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ...

set -Eeuo pipefail

# --- resolve repo root -------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
cd "${REPO_ROOT}"

# --- load .env if present ----------------------------------------------------
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a
  . "${ENV_FILE}"
  set +a
fi

# --- sanity checks -----------------------------------------------------------
command -v python3 >/dev/null 2>&1 || {
  echo "fatal: python3 not found on PATH" >&2
  exit 127
}

PYTHON="${PYTHON:-python3}"

# Make sure the package is importable when running from a source checkout.
if [[ -z "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="${REPO_ROOT}/src"
else
  export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH}"
fi

# --- exec --------------------------------------------------------------------
SUBCOMMAND="${1:-run}"
case "${SUBCOMMAND}" in
  run|validate-config|send-test|digest-now|version)
    :
    ;;
  *)
    echo "unknown subcommand: ${SUBCOMMAND}" >&2
    echo "see: ${0} run|validate-config|send-test|digest-now|version" >&2
    exit 64
    ;;
esac

exec "${PYTHON}" -m wazuh_fim_telegram "$@"
