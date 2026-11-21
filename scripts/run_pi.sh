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
# The Llama model and its tokenizer: read by the Llama service, and sent to a paired phone that asks
# for them (GET /llama, update 44), so that Phone Guard can explain alerts away from the Pi's Wi-Fi.
export LLAMA_PTE="${LLAMA_PTE:-$ET_DIR/llama3_2.pte}"
export LLAMA_TOKENIZER="${LLAMA_TOKENIZER:-$ET_DIR/tokenizer.model}"

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
    --pte "$LLAMA_PTE" --tokenizer "$LLAMA_TOKENIZER" \
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
echo "Phones and page: the pairing token is in $TOKEN_FILE (cat it)"

# HTTPS (update 39): a self-signed certificate, made once and kept. A phone pins it when it pairs: its
# owner compares the fingerprint the app shows with the one printed here (and in ~/.ps3_tls_fingerprint).
# The phones and the page use https://<Pi>:8443. Plain HTTP on port 8000 stays for the Pi itself
# (curl http://127.0.0.1:8000/health) and for lab devices' readings (POST /iot), which cannot pin.
CERT="$HOME/.ps3_tls_cert.pem"
KEY="$HOME/.ps3_tls_key.pem"
if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  command -v openssl > /dev/null || { echo "openssl is missing: sudo apt install openssl"; exit 1; }
  (umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=ps3-guardian" -addext "subjectAltName=IP:10.42.0.1,DNS:ps3-guardian.local" \
    -keyout "$KEY" -out "$CERT" 2> /dev/null)
  chmod 600 "$KEY"
  echo "Made a new HTTPS certificate: pair the phones again (the app shows its fingerprint)."
fi
FINGERPRINT="$(python -m app.serve --fingerprint "$CERT")"
echo "$FINGERPRINT" > "$HOME/.ps3_tls_fingerprint"
echo "App: https://$IP:8443 for the phones and the page; certificate fingerprint: $FINGERPRINT"
echo "Lab devices post readings to http://$IP:8000/iot"

ADVISOR_BACKEND=service exec python -m app.serve --cert "$CERT" --key "$KEY"
