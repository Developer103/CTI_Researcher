#!/usr/bin/env bash
# CTI Pipeline runner — safe to call manually or from cron.
# Usage:  ./run.sh          (normal run)
#         ./run.sh --output  (also print report to stdout)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python3"
LOG_DIR="${SCRIPT_DIR}/data/logs"
LOG_FILE="${LOG_DIR}/cti_$(date +%Y-%m-%d).log"

mkdir -p "${LOG_DIR}"

# Cron strips PATH to bare minimum — put everything needed back in
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"

# Pass all extra flags through (e.g. --mode hourly, --mode daily, --output)

echo "──────────────────────────────────────────────────────" | tee -a "${LOG_FILE}"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] CTI Pipeline started" | tee -a "${LOG_FILE}"

# Confirm Ollama is reachable before burning time on feeds
if ! curl -sf --max-time 5 http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Ollama not reachable at localhost:11434 — aborting" | tee -a "${LOG_FILE}"
    exit 1
fi

"${PYTHON}" "${SCRIPT_DIR}/main.py" \
    --email-en msky.ito@gmail.com \
    --email-en mizutai061213@gmail.com \
    --email-ja msky.ito@gmail.com \
    --email-ja mizutai061213@gmail.com \
    "$@" \
    2>&1 | tee -a "${LOG_FILE}"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] CTI Pipeline finished" | tee -a "${LOG_FILE}"
