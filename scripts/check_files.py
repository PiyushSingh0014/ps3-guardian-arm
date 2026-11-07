"""Run the file checker over a folder: how many normal files does it flag (false alarms), and
does it catch the harmful test files? Everything stays on this machine.

    python scripts/check_files.py ~/ps3-file-samples          # the harmless test files
    python scripts/check_files.py ~/normal-files --quiet      # your own everyday PDFs and documents

Prints one line per file (verdict, kind, the first reason) and a table per file type. With
--quiet only the flagged files are listed. Names are shown only here, on your screen.
"""
import argparse
import os
import sys
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detectors.files.checker import MAX_BYTES, FileChecker  # noqa: E402
from detectors.url.detector import UrlDetector  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--quiet", action="store_true", help="list only the files that were flagged")
    a = ap.parse_args()
    checker = FileChecker(UrlDetector())
    rows, table = [], defaultdict(Counter)
    t0 = time.time()
    for dirpath, _, names in os.walk(os.path.expanduser(a.folder)):
        for name in sorted(names):
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    print(f"too big     {name}")
                    continue
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                print(f"not read    {name}: {e}")
                continue
            finding = checker.check(data, name)
            table[finding.entities.get("file_type", "?")][finding.verdict] += 1
            rows.append(finding.verdict)
            if not a.quiet or finding.verdict != "safe":
                print(f"{finding.verdict:10s}  {finding.category:18s}  {name}: {(finding.reasons or [''])[0]}")
    if not rows:
        print("No files found.")
        return 1
    print(f"\n{len(rows)} files in {time.time() - t0:.1f} s: " + ", ".join(f"{v} {n}" for v, n in Counter(rows).most_common()))
    print("\n| File type | Files | Safe | Suspicious | Dangerous |\n|---|---|---|---|---|")
    for kind, c in sorted(table.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"| {kind} | {sum(c.values())} | {c['safe']} | {c['suspicious']} | {c['dangerous']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
