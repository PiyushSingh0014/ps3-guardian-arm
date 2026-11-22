#!/usr/bin/env bash
# Run the network monitor (detectors/net/monitor.py) at every boot, as a systemd service.
#
#   bash scripts/install_netmon.sh            # watch wlan0 (the Pi's Wi-Fi)
#   bash scripts/install_netmon.sh usb0       # or another interface
#
# Live capture needs two Linux capabilities (CAP_NET_RAW, CAP_NET_ADMIN). The service
# gets only those two, runs as your user, and cannot gain more (NoNewPrivileges).
# Alerts: logs/net_alerts.jsonl (shown on the Pi page); messages: logs/netmon.log.
# Also installs ps3-leases, which gives the monitor the names of devices on the Pi's hotspot.
# Running it again is safe: it rewrites the services and restarts the monitor.
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

# Device names in alerts. When the Pi is the hotspot (setup_gateway.sh), its DHCP server keeps
# the list of devices in a folder only root may read. ps3-leases copies just "address name" from
# it, whenever it changes, to /run/ps3-guardian/leases, readable by this user's group.
sudo install -d -m 755 /usr/local/lib/ps3-guardian
sudo tee /usr/local/lib/ps3-guardian/copy-leases > /dev/null <<'EOF'
#!/bin/sh
# Installed by ps3-guardian scripts/install_netmon.sh; run as root by ps3-leases.service.
# Copies each device's address and the name it gave itself (nothing else) for the monitor.
SRC=/var/lib/NetworkManager/dnsmasq-wlan0.leases
DIR=/run/ps3-guardian
[ -r "$SRC" ] || exit 0
mkdir -p "$DIR"
TMP="$DIR/.leases.$$"
if awk 'NF >= 4 && $4 != "*" {print $3, $4}' "$SRC" > "$TMP"; then
  chgrp "${PS3_GROUP:-root}" "$TMP" && chmod 640 "$TMP" && mv -f "$TMP" "$DIR/leases"
fi
rm -f "$TMP"
EOF
sudo chmod 755 /usr/local/lib/ps3-guardian/copy-leases
sudo tee /etc/systemd/system/ps3-leases.service > /dev/null <<EOF
[Unit]
Description=PS3 Guardian: device names from the hotspot for the network monitor
After=NetworkManager.service

[Service]
Type=oneshot
Environment=PS3_GROUP=$(id -gn)
ExecStart=/usr/local/lib/ps3-guardian/copy-leases

[Install]
WantedBy=multi-user.target
EOF
sudo tee /etc/systemd/system/ps3-leases.path > /dev/null <<'EOF'
[Unit]
Description=PS3 Guardian: watch the hotspot's list of devices

[Path]
PathModified=/var/lib/NetworkManager/dnsmasq-wlan0.leases

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ps3-leases.path > /dev/null 2>&1
sudo systemctl enable ps3-leases.service > /dev/null 2>&1
sudo systemctl start ps3-leases.service || true
sudo systemctl enable ps3-netmon > /dev/null
sudo systemctl restart ps3-netmon
sleep 8
if systemctl is-active --quiet ps3-netmon; then
  echo "The network monitor is running on $IFACE."
  systemctl is-active --quiet ps3-leases.path && echo "Device names for alerts: on (ps3-leases)."
  tail -n 3 "$REPO/logs/netmon.log"
else
  echo "The network monitor did not start. Last lines of its log:"
  tail -n 20 "$REPO/logs/netmon.log"
  exit 1
fi
