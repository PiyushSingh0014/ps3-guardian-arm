#!/usr/bin/env bash
# Start PS3 Guardian (the Llama service and the app) automatically whenever the Pi boots,
# and again if it stops with an error. Run once on the Pi, from the repo root:
#   bash scripts/install_service.sh
# Afterwards:
#   restart (for example after an update):  sudo systemctl restart ps3-guardian
#   is it running?                          systemctl status ps3-guardian --no-pager
#   log (appended, not overwritten):        tail -n 30 logs/app.log
#   stop starting at boot:                  sudo systemctl disable --now ps3-guardian
# Don't also start scripts/run_pi.sh by hand: a second copy cannot use ports 8000 and 8443.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="$(id -un)"
BIN="${LLAMA_SERVER_BIN:-}"

if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "LLAMA_SERVER_BIN must point to the advisor_server binary (see llama-engine/advisor_server/)."
  echo "It is set in ~/.bashrc on the Pi; open a new SSH session or run: source ~/.bashrc"
  exit 1
fi

mkdir -p "$REPO/logs"
sudo tee /etc/systemd/system/ps3-guardian.service > /dev/null <<EOF
[Unit]
Description=PS3 Guardian: Llama service and app
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
User=$USER_NAME
WorkingDirectory=$REPO
Environment=LLAMA_SERVER_BIN=$BIN
ExecStart=/bin/bash scripts/run_pi.sh
Restart=on-failure
RestartSec=10
StandardOutput=append:$REPO/logs/app.log
StandardError=inherit

[Install]
WantedBy=multi-user.target
EOF

pkill -f "uvicorn app.server|app.serve" || true   # a copy started by hand would hold ports 8000 and 8443
sudo systemctl daemon-reload
sudo systemctl enable --now ps3-guardian
echo "Installed. Llama takes 1-2 minutes to load; then: curl -s http://127.0.0.1:8000/health"
