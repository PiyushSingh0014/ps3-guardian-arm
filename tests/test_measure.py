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
    labels = tmp_path / "labels.json"
    net_traffic.export(str(alerts), str(tests), str(sheet), str(labels))
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
    net_traffic.measure(str(sheet), str(days), str(alerts), str(tests), str(labels))
    out = capsys.readouterr().out
    assert "Alerts: 3: test 2, false 1, real 0, not labelled 0" in out
    assert "12.0 hours" in out and "| 2026-11-03 | 12.0 | 50,000 | 3 | 2 | 1 | 0 | 0 |" in out
    assert "1 in 12.0 hours = 2.0 per day" in out and "{'malware_beacon': 1}" in out
    assert "3 rows matched to the alert log by id" in out


def files(tmp_path):
    return [str(tmp_path / n) for n in ("net_alerts.jsonl", "lab_tests.jsonl", "labels.json", "days.json")]


def test_labelling_in_the_terminal_saves_each_answer_and_carries_on_later(tmp_path, capsys):
    alerts, tests, labels, days = files(tmp_path)
    old = alert("10.42.0.99", "malware_beacon", T - 3 * 86_400_000)
    old["time"] = "2026-10-31 10:00:00"                                              # before watching
    with open(alerts, "w", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(a) for a in [
            old,
            alert("10.42.0.170", "dga_domains", T + 40_000, "dangerous", "esp32-lab"),  # during its DGA test
            alert("10.42.0.214", "network_scan", T + 50_000, name="laptop"),
            alert("10.42.0.214", "scam_link_opened", T + 60_000, "dangerous", "laptop"),
        ]) + "\nnot json\n")
    with open(tests, "w", encoding="utf-8") as f:
        f.write(json.dumps({"time_ms": T, "device": "esp32-lab", "ip": "10.42.0.170", "mode": "dga",
                            "seconds": 300}) + "\n")
    with open(days, "w", encoding="utf-8") as f:
        json.dump({"2026-11-03": {"minutes": 720, "flows": 50_000, "alerts": 3}}, f)

    answers, said = iter(["maybe", "F", "q"]), []
    net_traffic.label(alerts, tests, labels, days, ask=lambda _: next(answers), say=said.append)
    text = "\n".join(said)
    assert "3 alerts on the day the monitor watched (2026-11-03)" in text
    assert "Labelled already: 1 during ESP32 tests, 0 by you. To go: 2." in text
    assert "[1 of 2]  2026-11-03 10:00:00   laptop (10.42.0.214)" in text
    assert "SUSPICIOUS: Device scanning other machines (worm or botnet)" in text     # the playbook's title
    assert "Type t, f or r" in text and "[2 of 2]" in text and "Stopped." in text
    assert "Saved 1 answer in" in text and "1 alert still without a label" in text
    with open(labels, encoding="utf-8") as f:
        assert list(json.load(f).values()) == ["false"]

    answers, said = iter(["t"]), []                     # later: only the one left is asked
    net_traffic.label(alerts, tests, labels, days, ask=lambda _: next(answers), say=said.append)
    text = "\n".join(said)
    assert "To go: 1." in text and "Link from a scam message opened" in text and "still without" not in text

    said = []
    net_traffic.label(alerts, tests, labels, days, ask=lambda _: "", say=said.append)
    assert "Nothing to label." in "\n".join(said)

    net_traffic.measure(None, days, alerts, tests, labels)
    out = capsys.readouterr().out
    assert "Alerts: 3: test 2, false 1, real 0, not labelled 0" in out
    assert "| 2026-11-03 | 12.0 | 50,000 | 3 | 2 | 1 | 0 | 0 |" in out and "2026-10-31" not in out
    assert "Not counted: 1 alert on 1 day with no watched time" in out
    net_traffic.measure(None, days, alerts, tests, labels, everything=True)
    assert "| 2026-10-31 | ? | ? | 1 | 0 | 0 | 0 | 1 |" in capsys.readouterr().out


def test_labelling_waits_for_watched_time_unless_asked_for_all(tmp_path):
    alerts, tests, labels, days = files(tmp_path)
    with open(alerts, "w", encoding="utf-8") as f:
        f.write(json.dumps(alert("10.42.0.214", "network_scan", T, name="laptop")) + "\n")
    said = []
    net_traffic.label(alerts, tests, labels, days, ask=lambda _: "f", say=said.append)
    assert "no watched days yet" in said[0] and not os.path.exists(labels)
    net_traffic.label(alerts, tests, labels, days, everything=True, ask=lambda _: "r", say=said.append)
    with open(labels, encoding="utf-8") as f:
        assert list(json.load(f).values()) == ["real"]
    asked = []                                          # --again shows the label and Enter keeps it
    net_traffic.label(alerts, tests, labels, days, everything=True, again=True,
                      ask=lambda p: asked.append(p) or "", say=said.append)
    assert len(asked) == 1 and "Label now: real (Enter keeps it)" in "\n".join(said)
    with open(labels, encoding="utf-8") as f:
        assert list(json.load(f).values()) == ["real"]


def test_measure_reads_a_sheet_that_went_through_excel(tmp_path, capsys):
    # Excel re-writes dates in the PC's own format, turns "false" into FALSE, may turn an id into a
    # number, and "CSV (Comma delimited)" saves in the Windows code page, not UTF-8.
    alerts, tests, labels, days = files(tmp_path)
    sheet = str(tmp_path / "alerts.csv")
    items = [alert("10.42.0.214", "network_scan", T + 50_000, name="laptop"),
             alert("10.42.0.214", "malware_beacon", T + 70_000, name="laptop"),
             alert("10.42.0.50", "dns_tunnel", T + 90_000, name="phone")]
    items[2]["finding"]["reasons"] = ["10.42.0.50 sent data hidden in look-ups … ±"]
    with open(alerts, "w", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(a, ensure_ascii=False) for a in items) + "\n")
    with open(days, "w", encoding="utf-8") as f:
        json.dump({"2026-11-03": {"minutes": 720, "flows": 50_000, "alerts": 3}}, f)
    net_traffic.export(alerts, tests, sheet, labels)
    with open(sheet, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    rows[0]["time"], rows[0]["label"] = "03-11-2026 10:00", "FALSE"     # India: day first
    rows[1]["time"], rows[1]["label"] = "11/3/2026 10:01 AM", "f"       # US: month first...
    rows[1]["id"] = "1.23457E+15"                                       # ...and its id lost
    rows[2]["label"] = "flase"                                          # a typo
    with open(sheet, "w", newline="", encoding="cp1252") as f:
        w = csv.DictWriter(f, fieldnames=net_traffic.COLUMNS)
        w.writeheader()
        w.writerows(rows)
        f.write(",,,,,,,,,\n")                                          # an empty row Excel kept
    capsys.readouterr()
    net_traffic.measure(sheet, days, alerts, tests, labels)
    out = capsys.readouterr().out
    assert "| 2026-11-03 | 12.0 | 50,000 | 3 | 0 | 2 | 0 | 1 |" in out
    assert "2 in 12.0 hours = 4.0 per day" in out
    assert "2 rows matched to the alert log by id, 1 placed by their time" in out and "{'flase': 1}" in out


def test_days_as_excel_writes_them():
    assert net_traffic.day_of("2026-11-03 10:05:00") == "2026-11-03"
    assert net_traffic.day_of("03-11-2026 10:05") == "2026-11-03"                # day first by default
    assert net_traffic.day_of("11/3/2026 10:05 AM", {"2026-11-03"}) == "2026-11-03"
    assert net_traffic.day_of("13/11/2026") == "2026-11-13" and net_traffic.day_of("11/13/2026") == "2026-11-13"
    assert net_traffic.day_of("3-Nov-26") == "2026-11-03" and net_traffic.day_of("Nov 3, 2026") == "2026-11-03"
    assert net_traffic.day_of("") == "" and net_traffic.day_of("soon") == "" and net_traffic.day_of("31/31/2026") == ""


def test_the_table_comes_back_from_a_saved_run(tmp_path, monkeypatch, capsys):
    logs = tmp_path / "logs"
    logs.mkdir()
    keys = ["time", "pi_cpu", "mem_free_mb", "temp_c", "throttled", "monitor_cpu", "monitor_mb", "app_cpu",
            "app_mb", "llama_cpu", "llama_mb"]
    samples = [["01:44:00", 30.0, 1500, 55.0, 0x80000, 1.0, 80, 0.5, 150, 25.0, 1800],
               ["01:44:05", 98.0, 1400, None, None, 1.0, 80, 0.5, 150, 95.0, 1810]]
    for name in ("pi_usage-20261103-0110.csv", "pi_usage-20261103-0143.csv"):
        with open(logs / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(dict(zip(keys, s)) for s in (samples if "0143" in name else samples[:1]))
    monkeypatch.setattr(pi_usage, "ROOT", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["pi_usage.py", "--from", "last"])
    assert pi_usage.main() == 0
    out = capsys.readouterr().out
    assert "pi_usage-20261103-0143.csv" in out and "2 samples" in out
    assert "| llama | 60.0% | 95.0% | 1805 MB | 1810 MB |" in out and "at least 1400 MB" in out
    assert "55.0 to 55.0" in out and "0x80000" in out
    monkeypatch.setattr(sys, "argv", ["pi_usage.py", "--from", str(tmp_path / "missing.csv")])
    assert pi_usage.main() == 1


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
