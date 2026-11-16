#!/usr/bin/env bash
# Download IoT-23 captures for detectors/net/replay.py (update 40). IoT-23: Garcia, Parmisano and
# Erquiaga, Stratosphere Laboratory, CTU Prague, 2020, CC BY 4.0 (doi:10.5281/zenodo.4743746).
#
#   bash scripts/get_iot23.sh                    # the default set: labelled Zeek logs only (small)
#   bash scripts/get_iot23.sh 34-1 hp-4-1        # chosen scenarios (malware 34-1, honeypot 4-1)
#   bash scripts/get_iot23.sh --pcap 34-1        # also the capture itself (for replay.py --pcap)
#   MAX_MB=1000 bash scripts/get_iot23.sh 1-1    # allow bigger files (default: 400 MB per file)
#
# Files go to ~/iot23/<scenario>/ (outside the repo: data, not code). Only the dataset's public
# files are read; nothing is run from them. The sizes are checked before anything is downloaded.
# Most scenarios keep their log in bro/; the Somfy door lock (hp-7-1) keeps six captures in
# Somfy-01/ ... Somfy-06/, each with its own bro/, and they are downloaded the same way.
set -euo pipefail

BASE="${IOT23_BASE:-https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios}"
DEST="${IOT23_DIR:-$HOME/iot23}"
MAX_MB="${MAX_MB:-400}"
# Mirai (34-1, 44-1), Torii (20-1), a trojan (42-1), Hakai (8-1), and the three real smart-home
# devices: Philips Hue (4-1), Amazon Echo (5-1), Somfy door lock (7-1).
DEFAULT="34-1 44-1 20-1 42-1 8-1 hp-4-1 hp-5-1 hp-7-1"

say() { printf '%s\n' "$*"; }
name_of() {
  case "$1" in
    CTU-*) echo "$1" ;;
    hp-*) echo "CTU-Honeypot-Capture-${1#hp-}" ;;
    [0-9]*-[0-9]*) echo "CTU-IoT-Malware-Capture-$1" ;;
    *) say "unknown scenario: $1 (write 34-1, hp-4-1 or the full folder name)" >&2; return 1 ;;
  esac
}
size_mb() {                       # the file's size in MB from the server, or "?" if it does not say
  local b
  b="$(curl -sIL --max-time 30 "$1" | tr -d '\r' | awk 'tolower($1)=="content-length:"{v=$2} END{print v}')"
  if [ -n "$b" ]; then echo $(( (b + 1048575) / 1048576 )); else echo "?"; fi
}
status() {                        # the HTTP status of a URL after redirects (000: no answer)
  curl -sIL --max-time 30 -o /dev/null -w '%{http_code}' "$1" 2> /dev/null || true
}
subfolders() {                    # the folders listed at a folder URL (ending in /), bro/ aside
  curl -fsL --max-time 60 "$1" 2> /dev/null | grep -o 'href="[^"/?.][^"?]*/"' | cut -d'"' -f2 | grep -vx 'bro/' || true
}
fetch() {                         # url, file: download if it fits under MAX_MB
  local mb
  mb="$(size_mb "$1")"
  if [ "$mb" != "?" ] && [ "$mb" -gt "$MAX_MB" ]; then
    say "  skipped $(basename "$2"): $mb MB, more than MAX_MB=$MAX_MB"
    return 0
  fi
  say "  $(basename "$2"): $mb MB"
  curl -fL -# --retry 3 --max-time 3600 -C - -o "$2" "$1"
}

PCAP=0
ARGS=()
for a in "$@"; do
  if [ "$a" = "--pcap" ]; then PCAP=1; else ARGS+=("$a"); fi
done
[ "${#ARGS[@]}" -gt 0 ] || read -r -a ARGS <<< "$DEFAULT"
command -v curl > /dev/null || { say "curl is needed: sudo apt install curl"; exit 1; }

for s in "${ARGS[@]}"; do
  n="$(name_of "$s")"
  say "$n"
  url="$BASE/$n/"
  if [ "$(status "${url}bro/conn.log.labeled")" = 200 ]; then
    dirs=("")
  else
    mapfile -t dirs < <(subfolders "$url")
    if [ "${#dirs[@]}" -eq 0 ]; then
      say "  no labelled log found in its folder (is the name right? the list: $BASE/)"
      continue
    fi
  fi
  for d in "${dirs[@]}"; do
    [ -z "$d" ] || say "  ${d%/}"
    if [ -n "$d" ] && [ "$(status "${url}${d}bro/conn.log.labeled")" != 200 ]; then
      say "    no labelled log in it"
      continue
    fi
    dd="$DEST/$n/${d%/}"
    dd="${dd%/}"
    mkdir -p "$dd/bro"
    fetch "${url}${d}bro/conn.log.labeled" "$dd/bro/conn.log.labeled" || say "  could not download its labelled log"
    if [ "$PCAP" = 1 ]; then
      p="$(curl -fsL --max-time 60 "${url}${d}" | grep -o 'href="[^"/]*\.pcap"' | head -n1 | cut -d'"' -f2 || true)"
      if [ -n "$p" ]; then
        fetch "${url}${d}$p" "$dd/$p" || say "  could not download $p"
      else
        say "  no .pcap file found in its folder"
      fi
    fi
  done
  [ ! -d "$DEST/$n" ] || curl -fsL --max-time 60 -o "$DEST/$n/README.md" "${url}README.md" || true
done
say ""
say "Next: cd ~/ps3-guardian && source ~/ps3-venv/bin/activate && python -m detectors.net.replay $DEST/*"
