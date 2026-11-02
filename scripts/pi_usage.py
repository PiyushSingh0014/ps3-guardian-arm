"""CPU, memory and temperature of PS3 Guardian on the Pi, for the report.

Run it on the Pi while it does what you want to measure (idle, an ESP32 test, a Llama
explanation); Ctrl+C stops it early:

    python scripts/pi_usage.py --minutes 30

Every 5 s it reads /proc (no extra packages) for three groups of processes:
    monitor  the network monitor (detectors.net.monitor and its capture processes)
    app      the app (uvicorn app.server)
    llama    the Llama service (advisor.llm_service and the native advisor_server)
plus the whole Pi: CPU, free memory, temperature and the power/heat flags of
`vcgencmd get_throttled`. Every sample goes to logs/pi_usage-<date>-<time>.csv; the end prints
a table of averages and peaks. CPU is a share of all 4 cores: 25% is one core fully busy.
"""
import argparse
import csv
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPS = {"monitor": ("detectors.net.monitor",), "app": ("app.server",),
          "llama": ("advisor.llm_service", "advisor_server")}


def cpu_total(proc="/proc"):
    """(busy, total) jiffies of all cores together."""
    with open(os.path.join(proc, "stat")) as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return v[0] + v[1] + v[2] + v[5] + v[6] + v[7], sum(v)


def group_of(cmdline):
    for name, keys in GROUPS.items():
        if any(k in cmdline for k in keys):
            return name
    return None


def processes(proc="/proc"):
    """{pid: (group, jiffies used, resident MB)} for the processes of the three groups."""
    out = {}
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc, pid, "cmdline"), "rb") as f:
                group = group_of(f.read().replace(b"\0", b" ").decode("utf-8", "replace"))
            if group is None:
                continue
            with open(os.path.join(proc, pid, "stat")) as f:
                fields = f.read().rsplit(")", 1)[1].split()     # after "(name)", which may hold spaces
            used = int(fields[11]) + int(fields[12])           # utime + stime
            rss = 0.0
            with open(os.path.join(proc, pid, "status")) as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) / 1024
            out[int(pid)] = (group, used, rss)
        except (OSError, IndexError, ValueError):
            continue                                           # the process just ended
    return out


def mem_available_mb(proc="/proc"):
    with open(os.path.join(proc, "meminfo")) as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024
    return 0.0


def temperature(path="/sys/class/thermal/thermal_zone0/temp"):
    try:
        with open(path) as f:
            return int(f.read().strip()) / 1000
    except (OSError, ValueError):
        return None


def throttled():
    try:
        out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=5).stdout
        return int(out.strip().split("=")[1], 16)
    except (OSError, IndexError, ValueError, subprocess.SubprocessError):
        return None


def sample(prev, proc="/proc", thermal="/sys/class/thermal/thermal_zone0/temp"):
    """One row of usage since `prev` (the state returned last time), and the new state."""
    busy, total = cpu_total(proc)
    procs = processes(proc)
    row = None
    if prev is not None:
        pbusy, ptotal, pprocs = prev
        dt = max(1, total - ptotal)
        row = {"time": time.strftime("%H:%M:%S"), "pi_cpu": round(100 * (busy - pbusy) / dt, 1),
               "mem_free_mb": round(mem_available_mb(proc)), "temp_c": temperature(thermal), "throttled": throttled()}
        for name in GROUPS:
            used = sum(u - pprocs[pid][1] for pid, (g, u, _) in procs.items() if g == name and pid in pprocs)
            row[f"{name}_cpu"] = round(100 * used / dt, 1)
            row[f"{name}_mb"] = round(sum(m for g, _, m in procs.values() if g == name))
    return row, (busy, total, procs)


def summary(rows):
    """Markdown table: average and peak per group, and for the whole Pi."""
    def stat(key):
        vals = [r[key] for r in rows if r.get(key) is not None]
        return (sum(vals) / len(vals), max(vals)) if vals else (0, 0)
    lines = [f"{len(rows)} samples", "", "| | CPU, average | CPU, peak | Memory, average | Memory, peak |",
             "|---|---|---|---|---|"]
    for name in GROUPS:
        c, m = stat(f"{name}_cpu"), stat(f"{name}_mb")
        lines.append(f"| {name} | {c[0]:.1f}% | {c[1]:.1f}% | {m[0]:.0f} MB | {m[1]:.0f} MB |")
    c = stat("pi_cpu")
    free = [r["mem_free_mb"] for r in rows if r.get("mem_free_mb") is not None]
    lines.append(f"| whole Pi | {c[0]:.1f}% | {c[1]:.1f}% | free memory at least {min(free) if free else 0} MB | |")
    temps = [r["temp_c"] for r in rows if r.get("temp_c") is not None]
    seen = [r["throttled"] for r in rows if r.get("throttled") is not None]
    flags = 0
    for v in seen:
        flags |= v
    lines += ["", f"Temperature: {min(temps):.1f} to {max(temps):.1f} °C" if temps else "Temperature: not readable",
              f"vcgencmd get_throttled: 0x{flags:x} (0x0: no power dip or heat limit since the Pi started)" if seen
              else "vcgencmd get_throttled: not available"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--every", type=float, default=5.0, help="seconds between samples")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or os.path.join(ROOT, "logs", time.strftime("pi_usage-%Y%m%d-%H%M.csv"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    rows, state, end = [], None, time.time() + a.minutes * 60
    print(f"Sampling every {a.every:g} s for {a.minutes:g} minutes (Ctrl+C stops early) -> {out}")
    try:
        with open(out, "w", newline="") as f:
            w = None
            while time.time() < end:
                row, state = sample(state)
                if row:
                    if w is None:
                        w = csv.DictWriter(f, fieldnames=list(row))
                        w.writeheader()
                    w.writerow(row)
                    f.flush()
                    rows.append(row)
                    print(f"{row['time']}  Pi {row['pi_cpu']:5.1f}%  monitor {row['monitor_cpu']:5.1f}%  "
                          f"app {row['app_cpu']:5.1f}%  llama {row['llama_cpu']:5.1f}%  {row['temp_c']} °C", flush=True)
                time.sleep(a.every)
    except KeyboardInterrupt:
        pass
    if rows:
        print("\n" + summary(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
