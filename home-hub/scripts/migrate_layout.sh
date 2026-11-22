#!/usr/bin/env bash
# Moves a Pi from the old layout (app/, detectors/, advisor/, scripts/ ... at the top of the repository)
# to home-hub/ (update 53). Run it once, from the repository's top folder, after bringing in the new layout:
#
#   cd ~/ps3-guardian && git merge --ff-only layout && bash home-hub/scripts/migrate_layout.sh
#
# It stops ps3-guardian and ps3-netmon, moves the files git does not track (data/, logs/, the trained SMS
# model) into home-hub/, keeps whatever else is left in the old folders in ~/ps3-guardian-old-layout/,
# re-installs both services with the new paths, points DNS blocking at the new list, and starts everything
# again. Nothing is deleted.
set -euo pipefail

TOP="$(cd "$(dirname "$0")/../.." && pwd)"
HUB="$TOP/home-hub"
KEEP="${KEEP:-$HOME/ps3-guardian-old-layout}"
say() { echo "== $*"; }
die() { echo "!! $*" >&2; exit 1; }

[ -d "$HUB/app" ] && [ -d "$HUB/detectors" ] || die "home-hub/ is not here yet: bring in the new layout first (git merge --ff-only layout)."
[ -e "$TOP/.git" ] || die "$TOP is not a git checkout."

BIN="$(systemctl show ps3-guardian -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^LLAMA_SERVER_BIN=//p')"
BIN="${LLAMA_SERVER_BIN:-$BIN}"
[ -n "$BIN" ] || die "LLAMA_SERVER_BIN is unknown: run it as LLAMA_SERVER_BIN=/path/to/advisor_server bash $0"

say "Stopping ps3-guardian and ps3-netmon"
sudo systemctl stop ps3-guardian ps3-netmon 2>/dev/null || true

say "Moving data/ and logs/ into home-hub/"
for d in data logs; do
  [ -d "$TOP/$d" ] || continue
  if [ ! -e "$HUB/$d" ]; then
    mv "$TOP/$d" "$HUB/$d"
  else
    cp -an "$TOP/$d/." "$HUB/$d/"
    mkdir -p "$KEEP"
    mv "$TOP/$d" "$KEEP/$d"
  fi
  echo "   $d/ -> home-hub/$d/"
done

say "Moving the files git does not track out of the old folders (the trained SMS model, local files)"
for pair in app:home-hub/app detectors:home-hub/detectors advisor:home-hub/advisor scripts:home-hub/scripts \
            tests:home-hub/tests deploy:home-hub/llama-engine android:phone-app esp32:iot-lab-device eval:results; do
  old="${pair%%:*}"
  new="${pair#*:}"
  [ -d "$TOP/$old" ] || continue
  while IFS= read -r -d '' f; do
    rel="${f#"$TOP/$old/"}"
    case "$rel" in *__pycache__*|*.pyc) continue ;; esac
    if [ ! -e "$TOP/$new/$rel" ]; then
      mkdir -p "$(dirname "$TOP/$new/$rel")"
      mv "$f" "$TOP/$new/$rel"
      echo "   $old/$rel -> $new/$rel"
    fi
  done < <(find "$TOP/$old" -type f -print0)
  mkdir -p "$KEEP"
  mv "$TOP/$old" "$KEEP/$old"
done

say "Re-installing the services with the new paths"
LLAMA_SERVER_BIN="$BIN" bash "$HUB/scripts/install_service.sh"
bash "$HUB/scripts/install_netmon.sh"

if [ -f /etc/ps3-guardian/dns-block.json ]; then
  say "Pointing DNS blocking at home-hub/data/net/blocklist.json"
  LIST="$HUB/data/net/blocklist.json"
  sudo python3 -c 'import json, sys
p = "/etc/ps3-guardian/dns-block.json"
c = json.load(open(p))
c["list"] = sys.argv[1]
open(p, "w").write(json.dumps(c))' "$LIST"
  if [ -f /etc/systemd/system/ps3-dnsblock.path ]; then
    sudo sed -i "s#^PathModified=.*#PathModified=$LIST#" /etc/systemd/system/ps3-dnsblock.path
    sudo systemctl daemon-reload
    sudo systemctl restart ps3-dnsblock.path
    sudo systemctl start ps3-dnsblock.service || true
  fi
fi

say "Waiting for the app server (Llama loads for about a minute)"
ok=""
for _ in $(seq 1 60); do
  if curl -s --max-time 2 http://127.0.0.1:8000/health > /dev/null; then ok=1; break; fi
  sleep 3
done
if [ -n "$ok" ]; then say "The app server answers."; else echo "!! The app server does not answer yet: tail -n 30 $HUB/logs/app.log"; fi
if systemctl is-active --quiet ps3-netmon; then say "The network monitor is running."; else echo "!! ps3-netmon is not running: journalctl -u ps3-netmon -n 20"; fi
say "Done. What was left in the old folders is in $KEEP: delete it once everything works."
