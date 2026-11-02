"""Measuring on the Pi: false alarms per day (scripts/net_traffic.py) and CPU, memory and
temperature (scripts/pi_usage.py, run here on a made-up /proc)."""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import net_traffic  # noqa: E402
import pi_usage  # noqa: E402

T = 1_793_000_000_000          # ms


def alert(ip, kind, t_ms, verdict="suspicious", name=""):
    e = {"device": ip, "time_ms": t_ms, "peer": "x"}
    if name:
        e["device_name"] = name
    return {"time": "2026-11-03 10:%02d:00" % ((t_ms - T) // 60_000 % 60), "finding": {
        "source": "net", "verdict": verdict, "score": 0.9, "category": kind, "reasons": [f"{ip} did something"],
        "entities": e, "language": "en"}}


def test_alerts_from_the_esp32_test_modes_are_labelled_test(tmp_path, capsys):
    alerts, tests, sheet = tmp_path / "net_alerts.jsonl", tmp_path / "lab_tests.jsonl", tmp_path / "alerts.csv"
    alerts.write_text("\n".join(json.dumps(a) for a in [
        alert("10.42.0.170", "dga_domains", T + 40_000, "dangerous", "esp32-lab"),     # during its DGA test
        alert("10.42.0.170", "malware_beacon", T + 25 * 60_000),                       # after the test: not labelled
        alert("10.42.0.214", "network_scan", T + 50_000, name="laptop"),               # another device
    ]) + "\n")
    tests.write_text("\n".join(json.dumps(x) for x in [
        {"time_ms": T, "device": "esp32-lab", "ip": "10.42.0.170", "mode": "dga", "seconds": 300},
        {"time_ms": T + 120_000, "device": "esp32-lab", "ip": "10.42.0.170", "mode": "normal", "seconds": 0},
    ]) + "\n")
    net_traffic.export(str(alerts), str(tests), str(sheet))
    with open(sheet, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert [(r["kind"], r["label"]) for r in rows] == [("dga_domains", "test"), ("malware_beacon", ""),
                                                      ("network_scan", "")]
    assert rows[0]["notes"] == "ESP32 test mode dga" and len(rows[0]["id"]) == 16

    rows[1]["label"], rows[2]["label"] = "false", "test"          # what the person labels
    with open(sheet, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=net_traffic.COLUMNS)
        w.writeheader()
        w.writerows(rows)
    days = tmp_path / "days.json"
    days.write_text(json.dumps({"2026-11-03": {"minutes": 720, "flows": 50_000, "alerts": 3}}))
    net_traffic.measure(str(sheet), str(days))
    out = capsys.readouterr().out
    assert "Alerts: 3: test 2, false 1, real 0, not labelled 0" in out
    assert "12.0 hours" in out and "| 2026-11-03 | 12.0 | 50,000 | 3 | 2 | 1 | 0 | 0 |" in out
    assert "1 in 12.0 hours = 2.0 per day" in out and "{'malware_beacon': 1}" in out


def fake_proc(root, busy, idle, procs, mem_free_kb=1_500_000):
    """A /proc with the given CPU counters and processes {pid: (cmdline, jiffies, rss kB)}."""
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "stat"), "w") as f:
        f.write(f"cpu  {busy} 0 0 {idle} 0 0 0 0 0 0\ncpu0 1 2 3 4\n")
    with open(os.path.join(root, "meminfo"), "w") as f:
        f.write(f"MemTotal:        3884000 kB\nMemAvailable:    {mem_free_kb} kB\n")
    for pid, (cmd, used, rss) in procs.items():
        d = os.path.join(root, str(pid))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cmdline"), "wb") as f:
            f.write(cmd.replace(" ", "\0").encode())
        with open(os.path.join(d, "stat"), "w") as f:
            f.write(f"{pid} (python3 x) S 1 1 1 0 -1 0 0 0 0 0 {used} 0 0 0 20 0 1 0 100 0 0\n")
        with open(os.path.join(d, "status"), "w") as f:
            f.write(f"Name:\tpython3\nVmRSS:\t{rss} kB\n")


def test_usage_per_group_is_a_share_of_all_cores(tmp_path, monkeypatch):
    monkeypatch.setattr(pi_usage, "throttled", lambda: 0x80000)
    proc, thermal = str(tmp_path / "proc"), tmp_path / "temp"
    thermal.write_text("58900\n")
    llama = "python -m advisor.llm_service --pte x.pte"
    procs = {10: ("python -m detectors.net.monitor --iface wlan0", 100, 80_000),
             11: (llama, 1000, 900_000), 12: ("/home/x/advisor_server --model_path=x", 500, 1_000_000),
             13: ("uvicorn app.server:app --port 8000", 50, 150_000), 14: ("bash", 999, 1000)}
    fake_proc(proc, busy=10_000, idle=30_000, procs=procs)
    row, state = pi_usage.sample(None, proc, str(thermal))
    assert row is None                                   # the first reading only starts the clock
    procs[10] = (procs[10][0], 120, 80_000)              # +20 jiffies
    procs[12] = (procs[12][0], 800, 1_000_000)           # +300: Llama is writing
    fake_proc(proc, busy=10_400, idle=30_600, procs=procs)
    row, _ = pi_usage.sample(state, proc, str(thermal))
    assert row["pi_cpu"] == 40.0                         # 400 busy of 1000
    assert row["monitor_cpu"] == 2.0 and row["llama_cpu"] == 30.0 and row["app_cpu"] == 0.0
    assert row["llama_mb"] == round((900_000 + 1_000_000) / 1024) and row["temp_c"] == 58.9
    text = pi_usage.summary([row])
    assert "| llama | 30.0% | 30.0% |" in text and "0x80000" in text and "58.9 to 58.9" in text
