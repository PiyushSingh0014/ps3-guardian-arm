#!/usr/bin/env bash
# Make the Pi a Wi-Fi hotspot for the ESP32 and other lab devices, with internet from the
# phone over USB, so the network monitor can watch every device on that Wi-Fi.
#
#   bash scripts/setup_gateway.sh          # check everything, then switch (asks first)
#   bash scripts/setup_gateway.sh --keep   # after switching: keep the hotspot for good
#   bash scripts/setup_gateway.sh --undo   # go back to the phone's Wi-Fi hotspot
#   bash scripts/setup_gateway.sh --status
#
# Before you start: plug the phone into a USB port of the Pi and switch on USB tethering
# on the phone (Settings > Connections > Mobile Hotspot and Tethering > USB tethering).
#
# Safety net: switching ends your SSH session, because the Pi's Wi-Fi stops being a client
# of the phone's hotspot and becomes a hotspot itself. If you do not run --keep from the new
# network within 10 minutes, the Pi switches back to the phone's hotspot by itself.
set -euo pipefail

LAB=ps3-lab                               # NetworkManager connection for the Pi's hotspot
SSID="${SSID:-PS3-Guardian-Lab}"
ADDR=10.42.0.1
PASS_FILE="$HOME/.ps3_lab_wifi"
STATE="$HOME/.ps3_gateway"                # name of the phone-hotspot connection, for --undo
UNDO=ps3-gateway-undo
UNDO_MINUTES=10

say() { printf '%s\n' "$*"; }
die() { say "STOP: $*"; exit 1; }

phone_con() {                             # the Wi-Fi connection the Pi uses as a client
  local c
  c="$(nmcli -t -f NAME,TYPE,DEVICE con show --active \
       | awk -F: '$2=="802-11-wireless" && $3=="wlan0"{print $1}' | head -n1)"
  if [ -n "$c" ] && [ "$c" != "$LAB" ]; then echo "$c"; elif [ -f "$STATE" ]; then cat "$STATE"; fi
}

tether_dev() {                            # the phone's USB tethering, seen as an Ethernet device
  nmcli -t -f DEVICE,TYPE,STATE device \
    | awk -F: '$2=="ethernet" && $3 ~ /^connected/ && $1!="eth0"{print $1}' | head -n1
}

addr_of() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1; }

undo_now() {
  local p; p="$(phone_con || true)"
  sudo systemctl stop "$UNDO.timer" 2>/dev/null || true
  sudo nmcli con modify "$LAB" connection.autoconnect no 2>/dev/null || true
  sudo nmcli con down "$LAB" 2>/dev/null || true
  if [ -n "$p" ]; then
    sudo nmcli con modify "$p" connection.autoconnect yes
    sudo nmcli con up "$p" || true
  fi
}

status() {
  say "Wi-Fi (wlan0): $(nmcli -t -f GENERAL.CONNECTION device show wlan0 | cut -d: -f2-)"
  local t; t="$(tether_dev || true)"
  say "Phone over USB: ${t:-not found} ${t:+($(addr_of "$t"))}"
  if nmcli -t -f NAME con show --active | grep -qx "$LAB"; then
    say "Hotspot: ON, \"$SSID\", the Pi is $ADDR on it"
  else
    say "Hotspot: off"
  fi
  systemctl list-timers --all 2>/dev/null | grep -q "$UNDO" && say "Automatic undo: scheduled" || true
}

case "${1:-}" in
  --status) status; exit 0 ;;
  --undo)
    undo_now
    say "Back on the phone's Wi-Fi hotspot. The hotspot \"$SSID\" is off."
    exit 0 ;;
  --keep)
    nmcli -t -f NAME con show --active | grep -qx "$LAB" || die "the hotspot is not on; nothing to keep."
    sudo systemctl stop "$UNDO.timer" 2>/dev/null || true
    sudo nmcli con modify "$LAB" connection.autoconnect yes
    t="$(tether_dev || true)"
    say "Kept. The Pi is now a hotspot, also after a restart."
    say "  Devices on \"$SSID\" reach the Pi at http://$ADDR:8000"
    if [ -n "$t" ]; then
      say "  Your phone (USB) reaches it at http://$(addr_of "$t"):8000  <- put this in the phone app"
    fi
    if systemctl is-enabled --quiet ps3-netmon 2>/dev/null; then
      sudo systemctl restart ps3-netmon            # watch wlan0 again, now as the hotspot
      say "The network monitor restarted on the hotspot (logs/netmon.log)."
    else
      say "Next: bash scripts/install_netmon.sh   (starts the network monitor on wlan0)"
    fi
    exit 0 ;;
  "") ;;
  *) die "unknown option $1 (use --keep, --undo or --status)" ;;
esac

# --- 1. checks: nothing is changed until all of them pass -------------------------
command -v nmcli > /dev/null || die "NetworkManager (nmcli) not found."
if nmcli -t -f NAME con show --active | grep -qx "$LAB"; then
  die "the hotspot is already on. Use --keep, --undo or --status."
fi
PHONE="$(phone_con || true)"
[ -n "$PHONE" ] || die "the Pi is not on a Wi-Fi network now, so there is nothing to switch back to."
echo "$PHONE" > "$STATE"
T="$(tether_dev || true)"
[ -n "$T" ] || die "no USB tethering found. Plug the phone into the Pi, switch on USB tethering on the phone,
then run this again."
say "Phone over USB: $T, the Pi is $(addr_of "$T") there"
code="$(sudo curl -s -m 10 --interface "$T" -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 || true)"
[ "$code" = "204" ] || die "no internet through the phone's USB tethering (got '$code'). Is mobile data on?"
say "Internet through USB: OK"
if [ ! -x /usr/sbin/dnsmasq ]; then
  say "Installing dnsmasq-base (gives addresses to devices on the hotspot) ..."
  sudo apt-get install -y dnsmasq-base > /dev/null
fi
if [ -x /usr/sbin/iw ] && /usr/sbin/iw reg get 2>/dev/null | grep -q "country 00"; then
  say "Setting the Wi-Fi country to India (needed for a hotspot) ..."
  sudo raspi-config nonint do_wifi_country IN
fi
if [ ! -s "$PASS_FILE" ]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(9))' > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
fi
PASS="$(cat "$PASS_FILE")"

# --- 2. prepare the hotspot (2.4 GHz, WPA2: what an ESP32 can join) ---------------
sudo nmcli con delete "$LAB" > /dev/null 2>&1 || true
sudo nmcli con add type wifi ifname wlan0 con-name "$LAB" autoconnect no ssid "$SSID" \
  802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
  ipv4.method shared ipv4.addresses "$ADDR/24" ipv6.method disabled \
  wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASS" \
  wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp > /dev/null
say "Hotspot prepared: \"$SSID\", password $PASS (also in $PASS_FILE)"

say ""
say "Switching now ends this SSH session. Then, on the laptop:"
say "  1. join the Wi-Fi \"$SSID\" (password $PASS)"
say "  2. ssh $(id -un)@$ADDR"
say "  3. cd ~/ps3-guardian && bash scripts/setup_gateway.sh --keep"
say "If step 3 does not happen within $UNDO_MINUTES minutes, the Pi goes back to \"$PHONE\" by itself."
read -r -p "Switch now? [y/N] " ok
[ "$ok" = "y" ] || [ "$ok" = "Y" ] || { say "Nothing switched."; exit 0; }

# --- 3. the automatic undo, then the switch; both run on their own (systemd), so they ---
# --- finish even though this SSH session drops. Names travel as environment variables, ---
# --- so a hotspot name with spaces or quotes cannot break the commands. -----------------
sudo systemctl stop "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
sudo systemctl reset-failed "$UNDO.timer" "$UNDO.service" 2>/dev/null || true
# shellcheck disable=SC2016                 # $LAB and $PHONE are expanded by the unit, not here
sudo systemd-run --quiet --unit "$UNDO" --on-active="${UNDO_MINUTES}m" \
  --setenv=LAB="$LAB" --setenv=PHONE="$PHONE" /bin/bash -c \
  'nmcli con modify "$LAB" connection.autoconnect no; nmcli con down "$LAB";
   nmcli con modify "$PHONE" connection.autoconnect yes; nmcli con up "$PHONE"'
# shellcheck disable=SC2016
sudo systemd-run --quiet --unit "ps3-gateway-switch-$$" \
  --setenv=LAB="$LAB" --setenv=PHONE="$PHONE" /bin/bash -c \
  'sleep 2; nmcli con modify "$PHONE" connection.autoconnect no;
   nmcli con up "$LAB" || { nmcli con modify "$PHONE" connection.autoconnect yes; nmcli con up "$PHONE"; }'
say "Switching... this session will now stop responding."
