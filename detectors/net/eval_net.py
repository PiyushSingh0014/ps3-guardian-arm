"""Measure the network detector on CIC-IDS2017: five days of a company network with
labelled attacks (Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018).

    python detectors/net/eval_net.py --data path/to/TrafficLabelling   # the unzipped GeneratedLabelledFlows

The days are fed in order, as one Pi would see them: Monday (normal traffic only) is
where each device's normal is learned; Tuesday to Friday hold the attacks. For each kind
of attack the script reports whether an alert named the attacking address (or its target)
while the attack ran, and how long after its first flow; and how many alerts fired that
match no attack (false alarms), per day.

The CSV timestamps have one-minute resolution. Flows within a minute are spread evenly in
file order, which keeps their order but makes 10-second counts approximate.
"""
import argparse
import glob
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.net.engine import NetEngine          # noqa: E402
from detectors.net.flows import read_cic_csv        # noqa: E402

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday-WorkingHours-Morning", "Thursday-WorkingHours-Afternoon",
        "Friday-WorkingHours-Morning", "Friday-WorkingHours-Afternoon-PortScan", "Friday-WorkingHours-Afternoon-DDos"]
# What a good detector should say for each attack (alerts of other kinds still count as detection).
EXPECTED = {"PortScan": "port_scan", "SSH-Patator": "brute_force", "FTP-Patator": "brute_force",
            "DoS Hulk": "dos_flood", "DoS GoldenEye": "dos_flood", "DoS slowloris": "dos_flood",
            "DoS Slowhttptest": "dos_flood", "DDoS": "dos_flood", "Bot": "malware_beacon",
            "Infiltration": "port_scan"}
GRACE_MS = 5 * 60_000
# The attackers' own machine (the Kali box, also the botnet's controller) in the CIC-IDS2017
# network description. The bots keep calling it after the labelled Bot hour, where CIC's
# labels say BENIGN; alerts naming it are counted apart, not as false alarms.
ATTACKER = {"205.174.165.73"}


def day_files(folder):
    files = sorted(glob.glob(os.path.join(folder, "*.csv")))
    order = []
    for d in DAYS:
        order += [f for f in files if os.path.basename(f).lower().startswith(d.lower()) and f not in order]
    return order + [f for f in files if f not in order]


def load_day(path):
    """Flows of one file, in time order, spread within each minute (see the docstring)."""
    flows = list(read_cic_csv(path))
    by_minute = defaultdict(list)
    for i, r in enumerate(flows):
        by_minute[r.start_ms // 60_000].append(i)
    if sum(1 for r in flows if r.start_ms % 60_000) < 0.01 * max(1, len(flows)):     # minute resolution
        for idx in by_minute.values():
            n = len(idx)
            for k, i in enumerate(idx):
                r = flows[i]
                shift = int(k * 60_000 / n)
                r.start_ms += shift
                r.end_ms += shift
    flows.sort(key=lambda r: r.start_ms)
    return flows


def attacks_in(flows):
    """label -> pairs, addresses, flow count, and the attack's main period.

    The main period is from the 5th to the 95th percentile of the labelled flows' start
    times: a few stray labelled flows long before or after the attack (CIC's labels have
    those) do not stretch it.
    """
    out = {}
    for r in flows:
        lab = r.label
        if not lab or lab.upper() == "BENIGN":
            continue
        a = out.setdefault(lab, {"pairs": set(), "addrs": set(), "starts": [], "flows": 0})
        a["pairs"].add((r.src, r.dst))
        a["addrs"].update((r.src, r.dst))
        a["starts"].append(r.start_ms)
        a["flows"] += 1
    for a in out.values():
        t = sorted(a.pop("starts"))
        a["first"], a["last"] = t[int(0.05 * (len(t) - 1))], t[int(0.95 * (len(t) - 1))]
    return out


def clock(ms):
    import datetime
    return datetime.datetime.fromtimestamp(ms / 1000).strftime("%H:%M")


def matches(f, a):
    """Does alert f name this attack's addresses during its main period (give or take 5 minutes)?"""
    e = f.entities
    t = e.get("time_ms", 0)
    if not (a["first"] - GRACE_MS <= t <= a["last"] + GRACE_MS):
        return False
    dev, peer = e.get("device"), e.get("peer")
    return (dev, peer) in a["pairs"] or (peer, dev) in a["pairs"] or (dev in a["addrs"] and f.category != "dga_domains")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True, help="folder with the CIC-IDS2017 GeneratedLabelledFlows CSV files")
    ap.add_argument("--learn-hours", type=float, default=2.0)
    ap.add_argument("--show", type=int, default=5, help="false alarms to list per day")
    a = ap.parse_args()

    engine = NetEngine(learn_ms=int(a.learn_hours * 3600_000), leases=None)
    results, false_by_day = {}, {}
    for path in day_files(a.data):
        name = os.path.basename(path).split(".pcap")[0]
        flows = load_day(path)
        attacks = attacks_in(flows)
        alerts = []
        for r in flows:
            alerts += engine.feed(r)
        unmatched = [f for f in alerts if not any(matches(f, at) for at in attacks.values())]
        about_attacker = [f for f in unmatched if {f.entities.get("device"), f.entities.get("peer")} & ATTACKER]
        false = [f for f in unmatched if f not in about_attacker]
        false_by_day[name] = false
        hours = (flows[-1].start_ms - flows[0].start_ms) / 3_600_000 if flows else 0
        print(f"\n{name}: {len(flows):,} flows over {hours:.1f} h, {len(alerts)} alerts, "
              f"{len(false)} false alarms ({Counter(f.category for f in false).most_common(4)}), "
              f"{len(about_attacker)} about the attackers' machine outside labelled times")
        for lab, at in sorted(attacks.items(), key=lambda kv: kv[1]["first"]):
            hit = [f for f in alerts if matches(f, at)]
            good = [f for f in hit if f.category == EXPECTED.get(lab)]
            first = min((f.entities["time_ms"] for f in (good or hit)), default=None)
            delay = (f"{clock(at['first'])}-{clock(at['last'])}, first alert {clock(first)} "
                     f"({max(0, first - at['first']) / 1000:.0f} s)" if first is not None
                     else f"{clock(at['first'])}-{clock(at['last'])}, no alert")
            kinds = Counter(f.category for f in hit)
            results[lab] = (bool(good), bool(hit), kinds, at["flows"], delay)
            state = "DETECTED" if good else ("other alert" if hit else "missed")
            print(f"  {lab:28s} {at['flows']:7,} flows  {state:11s}  {delay:40s} {dict(kinds.most_common(3))}")
        for f in false[:a.show]:
            print(f"    false alarm: {f.category} {f.entities.get('device')} -> {f.entities.get('peer')}: "
                  f"{f.reasons[0][:110]}")

    print("\nSummary (detected = an alert of the expected kind naming the attack's addresses while it ran)")
    for lab, (good, hit, kinds, n, delay) in sorted(results.items()):
        want = EXPECTED.get(lab, "-")
        state = "detected" if good else ("other alert" if hit else "missed")
        print(f"  {lab:28s} {state:11s} expected {want:15s} {delay:40s} got {dict(kinds)}")
    total_false = sum(len(v) for v in false_by_day.values())
    print(f"  alerts matching no attack, all days: {total_false} "
          f"(Monday, normal traffic only: {sum(len(v) for k, v in false_by_day.items() if k.startswith('Monday'))})")


if __name__ == "__main__":
    main()
