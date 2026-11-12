"""Run the file checker over a folder: how many normal files does it flag (false alarms), and
does it catch the harmful test files? Everything stays on this machine.

    python scripts/check_files.py ~/ps3-file-samples          # the harmless test files
    python scripts/check_files.py ~/normal-files --quiet      # your own everyday PDFs and documents
    python scripts/check_files.py ~/normal-files --quiet --details

Prints one line per file (verdict, kind, the first reason) and a table per file type. With
--quiet only the flagged files are listed; --details adds what was found inside (for a PDF:
its keys and the start of a script). Copies of a file (the same bytes, a name with the same
ending) are counted once. Names are shown only here, on your screen.
"""
import argparse
import hashlib
import os
import sys
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detectors.files.checker import MAX_BYTES, FileChecker  # noqa: E402
from detectors.files.names import extension, name_tricks  # noqa: E402
from detectors.url.detector import UrlDetector  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--quiet", action="store_true", help="list only the files that were flagged")
    ap.add_argument("--details", action="store_true", help="also print what was found inside each listed file")
    a = ap.parse_args(argv)
    checker = FileChecker(UrlDetector())
    rows, table, seen = [], defaultdict(Counter), {}
    copies = too_big = 0
    spent = 0.0
    for dirpath, _, names in os.walk(os.path.expanduser(a.folder)):
        for name in sorted(names):
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    print(f"too big     {name}")
                    too_big += 1
                    continue
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                print(f"not read    {name}: {e}")
                continue
            # A copy is the same bytes under a name with the same ending: the checker would say the same.
            digest = (hashlib.sha256(data).hexdigest(), extension(name), tuple(name_tricks(name)))
            if digest in seen:
                copies += 1
                if not a.quiet:
                    print(f"copy        {name}: the same file as {seen[digest]}")
                continue
            seen[digest] = name
            evidence = []
            t0 = time.perf_counter()
            finding = checker.check(data, name, evidence=evidence)
            spent += time.perf_counter() - t0
            table[finding.entities.get("file_type", "?")][finding.verdict] += 1
            rows.append(finding.verdict)
            if not a.quiet or finding.verdict != "safe":
                print(f"{finding.verdict:10s}  {finding.category:18s}  {name}: {(finding.reasons or [''])[0]}")
                if a.details and evidence:
                    print("            " + "; ".join(evidence))
    if not rows:
        print("No files found.")
        return 1
    extra = "".join([f", {copies} {'copy' if copies == 1 else 'copies'} of another file left out" if copies else "",
                     f", {too_big} too big (over {MAX_BYTES // 2**20} MB)" if too_big else ""])
    print(f"\n{len(rows)} different files in {spent:.1f} s ({1000 * spent / len(rows):.0f} ms each){extra}: "
          + ", ".join(f"{v} {n}" for v, n in Counter(rows).most_common()))
    print("\n| File type | Files | Safe | Suspicious | Dangerous |\n|---|---|---|---|---|")
    for kind, c in sorted(table.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"| {kind} | {sum(c.values())} | {c['safe']} | {c['suspicious']} | {c['dangerous']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
