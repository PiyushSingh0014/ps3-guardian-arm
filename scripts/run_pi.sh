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

# Pairing tokens, created once and kept in files (never printed in the log):
#   ~/.ps3_guardian_token     the phones and the page; every request needs it (128 bits)
#   ~/.ps3_lab_device_token   lab devices (the ESP32): good only for posting readings (POST /iot)
# Before update 36 there was one short token for everything. It becomes the lab-device token, so the
# ESP32 keeps working without a new upload, and the phones get a new, long token.
TOKEN_FILE="$HOME/.ps3_guardian_token"
DEVICE_TOKEN_FILE="$HOME/.ps3_lab_device_token"
new_token() { python -c 'import secrets; print(secrets.token_urlsafe(16))' > "$1"; chmod 600 "$1"; }
if [ -s "$TOKEN_FILE" ] && [ "$(tr -d '[:space:]' < "$TOKEN_FILE" | wc -c)" -lt 20 ] && [ ! -s "$DEVICE_TOKEN_FILE" ]; then
  mv "$TOKEN_FILE" "$DEVICE_TOKEN_FILE"
  echo "The old short pairing token is now the lab-device token (ESP32 only); the phones need the new one."
fi
[ -s "$TOKEN_FILE" ] || new_token "$TOKEN_FILE"
[ -s "$DEVICE_TOKEN_FILE" ] || new_token "$DEVICE_TOKEN_FILE"
export GUARDIAN_TOKEN="${GUARDIAN_TOKEN:-$(tr -d '[:space:]' < "$TOKEN_FILE")}"
export GUARDIAN_DEVICE_TOKEN="${GUARDIAN_DEVICE_TOKEN:-$(tr -d '[:space:]' < "$DEVICE_TOKEN_FILE")}"
echo "Phones and page: Pi address http://$IP:8000; pairing token: cat $TOKEN_FILE"

ADVISOR_BACKEND=service exec uvicorn app.server:app --host 0.0.0.0 --port 8000
