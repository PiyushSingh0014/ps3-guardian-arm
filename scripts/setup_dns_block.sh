#!/usr/bin/env bash
# DNS blocking on the Pi's hotspot (update 40): the websites of dangerous messages, the phishing
# sites devices look up and the websites you block on the Pi's page stop opening on every device on
# PS3-Guardian-Lab. How it works and how to undo a block: docs/dns-blocking.md.
#
#   bash scripts/setup_dns_block.sh          # install, restart the hotspot once, test (asks first)
#   bash scripts/setup_dns_block.sh --keep   # keep it (within 10 minutes, or it removes itself)
#   bash scripts/setup_dns_block.sh --undo   # remove it: the hotspot's DNS answers everything again
#   bash scripts/setup_dns_block.sh --status
#
# The app and the network monitor write data/net/blocklist.json. systemd notices each change
# (ps3-dnsblock.path) and runs a small root helper (/usr/local/lib/ps3-guardian/dns-block) that writes
# the names for the hotspot's dnsmasq and makes it read them: no restart, no sudo for the app. Only
# this set-up restarts the hotspot, once, so that its dnsmasq reads one new setting.
#
# Safety net: the restart drops the devices on the hotspot for a few seconds, an SSH session over it
# too. If you do not run --keep within 10 minutes, the setting is removed and the hotspot restarts
# with plain DNS, so a mistake cannot leave the lab without DNS.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ME="$(id -un)"
LAB=ps3-lab                                # the hotspot's NetworkManager connection (setup_gateway.sh)
SHARED_D="${PS3_SHARED_D:-/etc/NetworkManager/dnsmasq-shared.d}"
BLOCK_CONF="$SHARED_D/ps3-block.conf"
HELPER=/usr/local/lib/ps3-guardian/dns-block
CONF_DIR=/etc/ps3-guardian
SERVERS=/var/lib/ps3-guardian/blocked.servers
LIST="$REPO/data/net/blocklist.json"
UNITS=/etc/systemd/system
UNDO=ps3-dnsblock-undo
UNDO_MINUTES=10
TEST_LOG="$REPO/logs/dns_block_test.log"

say() { printf '%s\n' "$*"; }
die() { say "STOP: $*"; exit 1; }
lab_on() { nmcli -t -f NAME con show --active 2>/dev/null | grep -qx "$LAB"; }

status() {
  if [ -f "$BLOCK_CONF" ]; then say "DNS blocking: set up"; else say "DNS blocking: not set up"; fi
  if systemctl is-active --quiet ps3-dnsblock.path 2>/dev/null; then
    say "Applying changes to the list: yes (ps3-dnsblock.path)"
  else
    say "Applying changes to the list: no"
  fi
  [ ! -r "$SERVERS" ] || say "Websites blocked now: $(grep -c '^server=' "$SERVERS" || true)"
  if systemctl list-timers --all 2>/dev/null | grep -q "$UNDO"; then
    say "Automatic undo: scheduled. If the test below passed and phones still open websites, run --keep."
  fi
  if [ -f "$TEST_LOG" ]; then
    say "Last test (logs/dns_block_test.log):"
    sed 's/^/  /' "$TEST_LOG"
  fi
  if lab_on; then
    say "The hotspot's DNS now: $(cd "$REPO" && python3 -m app.dns_block check example.org 2>&1)"
  else
    say "Hotspot: off"
  fi
}

restart_hotspot() {             # in its own systemd unit, so it finishes even if this SSH session drops
  # shellcheck disable=SC2016                 # expanded by the unit's shell, not here
  sudo systemd-run --quiet --unit "ps3-dnsblock-restart-$$" --setenv=LAB="$LAB" /bin/bash -c \
    'sleep 2; nmcli con up "$LAB" > /dev/null'
}

undo_now() {
  sudo systemctl stop "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
  sudo systemctl disable --now ps3-dnsblock.path ps3-dnsblock.timer > /dev/null 2>&1 || true
  sudo rm -f "$BLOCK_CONF" "$UNITS/ps3-dnsblock.service" "$UNITS/ps3-dnsblock.path" "$UNITS/ps3-dnsblock.timer" \
    "$HELPER" "$CONF_DIR/dns-block.json" "$SERVERS"
  sudo systemctl daemon-reload
  if lab_on; then
    restart_hotspot
    say "Removed. The hotspot restarts with plain DNS; devices reconnect by themselves."
  else
    say "Removed."
  fi
  say "The list (data/net/blocklist.json) stays, and does nothing without the setting."
}

case "${1:-}" in
  --status) status; exit 0 ;;
  --keep)
    [ -f "$BLOCK_CONF" ] || die "DNS blocking is not set up; nothing to keep."
    sudo systemctl stop "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
    say "Kept: DNS blocking stays on, also after a restart. Remove it with: bash scripts/setup_dns_block.sh --undo"
    exit 0 ;;
  --undo) undo_now; exit 0 ;;
  "") ;;
  *) die "unknown option $1 (use --keep, --undo or --status)" ;;
esac

# --- 1. checks: nothing changes until all of them pass ----------------------------------
command -v nmcli > /dev/null || die "NetworkManager (nmcli) not found."
command -v python3 > /dev/null || die "python3 not found."
lab_on || die "the hotspot \"$LAB\" is not on. DNS blocking works on the Pi's own Wi-Fi: bash scripts/setup_gateway.sh"
[ -d "$SHARED_D" ] || die "$SHARED_D is missing: the hotspot was not set up by scripts/setup_gateway.sh."
[ -f "$REPO/scripts/dns_block_helper.py" ] || die "scripts/dns_block_helper.py is missing: apply update 40 first."

# --- 2. the helper, its settings and the systemd units ---------------------------------
mkdir -p "$REPO/data/net" "$REPO/logs"
sudo install -d -m 755 /usr/local/lib/ps3-guardian "$CONF_DIR" /var/lib/ps3-guardian
sudo install -m 755 -o root -g root "$REPO/scripts/dns_block_helper.py" "$HELPER"
python3 -c 'import json, sys; print(json.dumps({"list": sys.argv[1], "owner": sys.argv[2], "servers": sys.argv[3]}))' \
  "$LIST" "$ME" "$SERVERS" | sudo tee "$CONF_DIR/dns-block.json" > /dev/null
sudo chmod 644 "$CONF_DIR/dns-block.json"
sudo tee "$UNITS/ps3-dnsblock.service" > /dev/null <<EOF
[Unit]
Description=PS3 Guardian: apply the DNS block list to the hotspot

[Service]
Type=oneshot
ExecStart=$HELPER
EOF
sudo tee "$UNITS/ps3-dnsblock.path" > /dev/null <<EOF
[Unit]
Description=PS3 Guardian: watch the DNS block list

[Path]
PathModified=$LIST

[Install]
WantedBy=multi-user.target
EOF
sudo tee "$UNITS/ps3-dnsblock.timer" > /dev/null <<'EOF'
[Unit]
Description=PS3 Guardian: end DNS blocks on time

[Timer]
OnCalendar=hourly
OnBootSec=2min

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ps3-dnsblock.path ps3-dnsblock.timer > /dev/null 2>&1
sudo systemctl start ps3-dnsblock.service
printf '%s\n' "# Written by ps3-guardian scripts/setup_dns_block.sh: websites the Pi does not look up for the" \
  "# devices on its hotspot, and every name under them. ps3-dnsblock.service keeps the file up to date." \
  "servers-file=$SERVERS" | sudo tee "$BLOCK_CONF" > /dev/null
say "Installed: the helper, ps3-dnsblock.path and ps3-dnsblock.timer, and $BLOCK_CONF."

# --- 3. restart the hotspot once; the automatic undo first ------------------------------
say ""
say "Now the hotspot restarts so that its DNS reads the new setting: the devices on it lose the Wi-Fi"
say "for a few seconds, and an SSH session over it may stop responding. Then, from the laptop on"
say "PS3-Guardian-Lab:"
say "  1. ssh $ME@10.42.0.1   (if the session stopped)"
say "  2. cd ~/ps3-guardian && bash scripts/setup_dns_block.sh --status   (shows the test)"
say "  3. if the test passed and a phone still opens websites: bash scripts/setup_dns_block.sh --keep"
say "If step 3 does not happen within $UNDO_MINUTES minutes, the setting is removed by itself."
if [ -t 0 ]; then
  read -r -p "Restart the hotspot now? [y/N] " ok
  if [ "$ok" != "y" ] && [ "$ok" != "Y" ]; then
    sudo rm -f "$BLOCK_CONF"
    say "Not restarted, and the setting is removed again: nothing changed for the hotspot."
    exit 0
  fi
fi
sudo systemctl stop "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
sudo systemctl reset-failed "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
# shellcheck disable=SC2016
sudo systemd-run --quiet --unit "$UNDO" --on-active="${UNDO_MINUTES}m" \
  --setenv=CONF="$BLOCK_CONF" --setenv=LAB="$LAB" /bin/bash -c 'rm -f "$CONF"; nmcli con up "$LAB" > /dev/null'
# The restart, then the test as this user (the list must stay this user's file); its output goes
# to logs/dns_block_test.log, so it survives a dropped SSH session.
# shellcheck disable=SC2016
sudo systemd-run --quiet --unit "ps3-dnsblock-restart-$$" --setenv=LAB="$LAB" --setenv=REPO="$REPO" \
  --setenv=ME="$ME" --setenv=LOG="$TEST_LOG" /bin/bash -c \
  'sleep 2; nmcli con up "$LAB" > /dev/null; sleep 5;
   cd "$REPO" && runuser -u "$ME" -- sh -c "python3 -m app.dns_block selftest > \"\$LOG\" 2>&1" || true'
say "Restarting the hotspot... (the test takes about 30 seconds)"
