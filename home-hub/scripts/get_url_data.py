"""Download the link checker's lists (and, if asked, its training data) into data/url/.

    python scripts/get_url_data.py              # the lists the checker uses: about 20 MB to download
    python scripts/get_url_data.py --training   # also PhiUSIIL (15 MB zip), to retrain the link model
    python scripts/get_url_data.py --extra openphish=feed.txt   # add a list you downloaded yourself

What it writes:
  data/url/intel.sqlite      public lists of phishing and malware sites, for detectors/url/intel.py
  data/url/top_sites.txt     the 10,000 most visited websites, as registered domains
  data/url/crux-top-1m.csv.gz, phishing-domains-ACTIVE.txt   the downloads they were built from
  data/url/PhiUSIIL_Phishing_URL_Dataset.csv                with --training

Sources and licences:
  Phishing.Database  github.com/Phishing-Database/Phishing.Database        MIT
  Chrome UX Report   developer.chrome.com/docs/crux, monthly copy at
                     github.com/zakird/crux-top-lists                       public Google data
  PhiUSIIL           archive.ics.uci.edu/dataset/967                        CC BY 4.0
Other feeds (OpenPhish's community feed, abuse.ch URLhaus with a free account) have their
own terms: download them yourself and add them with --extra name=path (one domain or link
per line).

The lists change every day. The app picks up a new intel.sqlite within 10 minutes, so to keep
it fresh, run this weekly, e.g. from cron (crontab -e):
  17 4 * * 1  cd ~/ps3-guardian && ~/ps3-venv/bin/python scripts/get_url_data.py >> logs/url_data.log 2>&1
"""
import argparse
import gzip
import io
import os
import sys
import time
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detectors.url import intel                                                    # noqa: E402
from detectors.url.links import parse_link                                         # noqa: E402
from detectors.url.lists import CHAT_HOSTS, FREE_HOSTING, SHARED_CONTENT, SHORTENERS, within   # noqa: E402

OUT = os.path.join(ROOT, "data", "url")
URLS = {
    "phishing_db": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                   "phishing-domains-ACTIVE.txt",
    "crux": "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
    "phiusiil": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
}
FILES = {"phishing_db": "phishing-domains-ACTIVE.txt", "crux": "crux-top-1m.csv.gz",
         "phiusiil": "PhiUSIIL_Phishing_URL_Dataset.csv"}
TOP_RANK = 10000          # CrUX ranks are buckets: 1000, 5000, 10000, 50000, ...
_ANYONE_PUBLISHES = FREE_HOSTING | SHARED_CONTENT | SHORTENERS | CHAT_HOSTS
MAX_BYTES = 200_000_000


def download(name, timeout=120):
    """Fetch one source into data/url/. Returns the file path, or None (and a message) on failure."""
    url, path = URLS[name], os.path.join(OUT, FILES[name])
    print(f"  {name}: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ps3-guardian/1.0 (link checker lists)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_BYTES + 1)
    except Exception as e:                       # network down, site blocked, HTTP error
        print(f"    failed: {e}")
        return path if os.path.exists(path) else None
    if len(data) > MAX_BYTES:
        print("    failed: larger than expected")
        return None
    if name == "phiusiil":                       # a zip with one CSV; take only that member
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            member = next((n for n in z.namelist() if n.endswith(FILES[name])), None)
            if member is None:
                print("    failed: the zip has no " + FILES[name])
                return None
            data = z.read(member)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    print(f"    saved {len(data) / 1e6:.1f} MB -> {os.path.relpath(path, ROOT)}")
    return path


def lines(path):
    if not path:
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def top_sites(crux_path, max_rank=TOP_RANK):
    """Registered domains of the most visited websites, without services where anyone publishes."""
    with gzip.open(crux_path, "rt", encoding="utf-8") as f:
        next(f)                                   # origin,rank
        out = []
        for row in f:
            origin, _, rank = row.strip().rpartition(",")
            if not rank.isdigit() or int(rank) > max_rank:
                continue
            link = parse_link(origin)
            if link and link.registered and not within(link.host, _ANYONE_PUBLISHES):
                out.append(link.registered)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--training", action="store_true", help="also download PhiUSIIL, to retrain the link model")
    ap.add_argument("--extra", action="append", default=[], metavar="NAME=PATH",
                    help="also use a list you downloaded (one domain or link per line)")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()

    print("Downloading:")
    got = {n: download(n) for n in ["crux", "phishing_db"] + (["phiusiil"] if a.training else [])}
    for item in a.extra:
        name, _, path = item.partition("=")
        if not name.isidentifier() or not os.path.exists(path):
            sys.exit(f"--extra {item}: use name=path with an existing file")
        got[name] = path

    allow = []
    if got.get("crux"):
        allow = top_sites(got["crux"])
        with open(os.path.join(OUT, "top_sites.txt"), "w", encoding="utf-8") as f:
            f.write(f"# {len(allow)} registered domains among the top {TOP_RANK:,} websites of the Chrome UX Report\n")
            f.write("\n".join(allow) + "\n")
        print(f"\nTop sites: {len(allow)} registered domains -> data/url/top_sites.txt")

    lists = {n: lines(p) for n, p in got.items() if p and n not in ("crux", "phiusiil")}
    if not lists:
        sys.exit("No list could be downloaded; the link checker keeps its rules and model. Check the internet "
                 "connection and run this again.")
    counts = intel.build(lists, allow=allow)
    print("Blocklist: " + ", ".join(f"{n} {c:,} hosts" for n, c in counts.items()) + " -> data/url/intel.sqlite")
    print(f"Done in {time.time() - t0:.0f} s. The app picks up the new lists within 10 minutes.")


if __name__ == "__main__":
    main()
