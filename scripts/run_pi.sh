#!/usr/bin/env bash
# Start the Llama service (if it is not already running) and then the app.
# Run on the Pi from the repo root:   bash scripts/run_pi.sh
# Stop with Ctrl+C (stops the app); the Llama service keeps running in the
# background so the next start is instant. Stop it with:  pkill -f advisor.llm_service
set -euo pipefail

ET_DIR="${ET_DIR:-$HOME/executorch-deployment}"
VENV="${VENV:-$HOME/ps3-venv}"
THREADS="${LLAMA_THREADS:-4}"
SERVER_BIN="${LLAMA_SERVER_BIN:-$ET_DIR/advisor_server}"

# shellcheck disable=SC1091
source "$VENV/bin/activate"
mkdir -p logs

ENGINE_ARGS=()
if [ -x "$SERVER_BIN" ]; then
  ENGINE_ARGS=(--server-bin "$SERVER_BIN")
else
  echo "No $SERVER_BIN: using the ExecuTorch Python runtime (needs an Armv8.2+ CPU)."
  echo "On a Raspberry Pi 4 build advisor_server first: see deploy/advisor_server/."
fi

if ! curl -sf http://127.0.0.1:8765/health > /dev/null; then
  echo "Starting the Llama service (model load + reading the fixed prompt takes 1-2 minutes) ..."
  nohup python -m advisor.llm_service \
    --pte "$ET_DIR/llama3_2.pte" --tokenizer "$ET_DIR/tokenizer.model" \
    --threads "$THREADS" "${ENGINE_ARGS[@]}" > logs/llm_service.log 2>&1 &
  until curl -sf http://127.0.0.1:8765/health > /dev/null; do
    if ! pgrep -f advisor.llm_service > /dev/null; then
      echo "The Llama service stopped. Last lines of logs/llm_service.log:"
      tail -n 20 logs/llm_service.log
      exit 1
    fi
    sleep 3; printf "."
  done
  echo " ready"
fi
grep "^\[llm\]" logs/llm_service.log 2>/dev/null || true

IP="$(hostname -I | awk '{print $1}')"
echo "App: open http://$IP:8000 on a phone on the same network"

# Pairing token for the Android companion (POST /sms). Created once, kept in a file.
TOKEN_FILE="$HOME/.ps3_guardian_token"
if [ ! -s "$TOKEN_FILE" ]; then
  python -c 'import secrets; print(secrets.token_hex(4))' > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi
export GUARDIAN_TOKEN="${GUARDIAN_TOKEN:-$(cat "$TOKEN_FILE")}"
echo "Android app: Pi address http://$IP:8000, pairing token $GUARDIAN_TOKEN"

ADVISOR_BACKEND=service exec uvicorn app.server:app --host 0.0.0.0 --port 8000
