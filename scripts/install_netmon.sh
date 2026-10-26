#!/usr/bin/env bash
# Run the network monitor (detectors/net/monitor.py) at every boot, as a systemd service.
#
#   bash scripts/install_netmon.sh            # watch wlan0 (the Pi's Wi-Fi)
#   bash scripts/install_netmon.sh usb0       # or another interface
#
# Live capture needs two Linux capabilities (CAP_NET_RAW, CAP_NET_ADMIN). The service
# gets only those two, runs as your user, and cannot gain more (NoNewPrivileges).
# Alerts: logs/net_alerts.jsonl (shown on the Pi page); messages: logs/netmon.log.
set -euo pipefail

IFACE="${1:-wlan0}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${VENV:-$HOME/ps3-venv}"
ME="$(id -un)"

if ! "$VENV/bin/python" -c "import nfstream" 2>/dev/null; then
  echo "Installing NFStream into $VENV ..."
  "$VENV/bin/pip" install nfstream
fi
mkdir -p "$REPO/logs" "$REPO/data/net"

sudo tee /etc/systemd/system/ps3-netmon.service > /dev/null <<EOF
[Unit]
Description=PS3 Guardian network monitor ($IFACE)
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
User=$ME
WorkingDirectory=$REPO
ExecStart=$VENV/bin/python -m detectors.net.monitor --iface $IFACE
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
Restart=always
RestartSec=10
StandardOutput=append:$REPO/logs/netmon.log
StandardError=append:$REPO/logs/netmon.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ps3-netmon > /dev/null
sudo systemctl restart ps3-netmon
sleep 8
if systemctl is-active --quiet ps3-netmon; then
  echo "The network monitor is running on $IFACE."
  tail -n 3 "$REPO/logs/netmon.log"
else
  echo "The network monitor did not start. Last lines of its log:"
  tail -n 20 "$REPO/logs/netmon.log"
  exit 1
fi
