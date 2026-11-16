"""Update 40: replaying IoT-23 captures (their labelled Zeek logs) through the network monitor. The
logs here are made up in IoT-23's own format, including its space-separated label columns."""
import os

from detectors.net import replay
from detectors.net.replay import flow_from_zeek, read_zeek, zeek_rows

HEADER = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
          "#open\t2018-12-21-15-50-14\n"
          "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\t"
          "resp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\t"
          "resp_pkts\tresp_ip_bytes\ttunnel_parents   label   detailed-label\n"
          "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\t"
          "count\tstring\tcount\tcount\tcount\tcount\tset[string]   string   string\n")
T0 = 1545403816.0
DEV = "192.168.1.195"


def row(t, dst, dport, label="Benign   -", proto="tcp", state="SF", history="ShADadfF", opk=6, rpk=5, ob=300, rb=900,
        src=DEV, service="-", dur="1.5"):
    fields = [f"{T0 + t:.6f}", "Cxyz", src, "40000", dst, str(dport), proto, service, dur, str(ob), str(rb), state,
              "-", "-", "0", history, str(opk), str(ob + 40 * opk), str(rpk), str(rb + 40 * rpk)]
    return "\t".join(fields) + "\t-   " + label + "\n"


def mirai_log():
    lines = [row(i * 10, f"151.101.{i}.10", 443, service="ssl") for i in range(6)]          # ordinary traffic
    for i in range(60):                                                                     # a Telnet sweep
        lines.append(row(600 + i * 0.5, f"45.{i}.{i}.7", 23, "Malicious   PartOfAHorizontalPortScan",
                         state="S0", history="S", opk=1, rpk=0, ob=0, rb=0, dur="-"))
    for i in range(400):                                                                    # a SYN flood
        lines.append(row(1200 + i * 0.01, "203.0.113.9", 80, "Malicious   DDoS",
                         state="S0", history="S", opk=1, rpk=0, ob=0, rb=0, dur="-"))
    for i in range(12):                                                                     # IRC controller
        lines.append(row(1800 + i * 60, "185.244.25.235", 6667, "Malicious   C&C-HeartBeat", ob=60, rb=120, dur="0.4"))
    return HEADER + "".join(lines)


def scenario(tmp_path, name, text):
    folder = tmp_path / name / "bro"
    folder.mkdir(parents=True)
    (folder / "conn.log.labeled").write_text(text)
    return str(tmp_path / name)


def test_iot23s_space_separated_labels_are_read():
    text = mirai_log()
    rows = list(zeek_rows_from(text))
    assert rows[0]["label"] == "Benign" and rows[0]["detailed-label"] == "-"
    assert rows[6]["detailed-label"] == "PartOfAHorizontalPortScan" and rows[6]["id.resp_p"] == "23"
    tabs = text.replace("   ", "\t")                                                 # the plain Zeek form
    assert [r["detailed-label"] for r in zeek_rows_from(tabs)] == [r["detailed-label"] for r in rows]
    r = flow_from_zeek(rows[6])
    assert (r.src, r.dport, r.proto, r.syn_out, r.pkts_in, r.failed, r.label) == (
        DEV, 23, 6, 1, 0, True, "PartOfAHorizontalPortScan")
    rejected = flow_from_zeek(dict(rows[6], history="Sr", resp_pkts="1"))
    assert rejected.rst_in == 1 and not rejected.answered
    assert flow_from_zeek({"ts": "not a time"}) is None


def zeek_rows_from(text, _n=[0]):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".labeled", delete=False) as f:
        f.write(text)
    try:
        return list(zeek_rows(f.name))
    finally:
        os.unlink(f.name)


def test_a_mirai_like_capture_is_caught_and_scored(tmp_path):
    folder = scenario(tmp_path, "CTU-IoT-Malware-Capture-99-1", mirai_log())
    said = []
    res = replay.replay(folder, say=said.append)
    by = {r["label"]: r for r in res["rows"]}
    assert set(by) == {"PartOfAHorizontalPortScan", "DDoS", "C&C-HeartBeat"}
    assert by["PartOfAHorizontalPortScan"]["fitting"] and "network_scan" in by["PartOfAHorizontalPortScan"]["kinds"]
    assert by["DDoS"]["fitting"] and by["DDoS"]["after_s"] <= 5
    assert by["C&C-HeartBeat"]["fitting"] and "risky_port" in by["C&C-HeartBeat"]["kinds"]
    assert res["false"] == 0 and res["flows"] == 478 and not res["benign"]
    assert any("PartOfAHorizontalPortScan" in s and "detected after" in s for s in said)


def test_a_benign_capture_counts_every_alert_as_false(tmp_path):
    lines = [row(i * 30, f"52.94.{i % 3}.20", 443, src="192.168.1.132", service="ssl") for i in range(40)]
    folder = scenario(tmp_path, "CTU-Honeypot-Capture-5-1", HEADER + "".join(lines))
    res = replay.replay(folder, say=lambda _: None)
    assert res["benign"] and res["rows"] == [] and res["false"] == res["alerts"] == 0
    md = replay.report_md([res])
    assert "| CTU-Honeypot-Capture-5-1 | 40 |" in md and "benign | – | 0 false alarms" in md


def test_the_command_writes_a_report_and_skips_empty_folders(tmp_path, capsys):
    folder = scenario(tmp_path, "CTU-IoT-Malware-Capture-99-1", mirai_log())
    (tmp_path / "empty").mkdir()
    out = tmp_path / "report.md"
    assert replay.main([folder, str(tmp_path / "empty"), "--report", str(out)]) == 0
    text = out.read_text()
    assert "| CTU-IoT-Malware-Capture-99-1 | 478 |" in text and "DDoS | 400 | detected, after" in text
    assert "skipped:" in capsys.readouterr().out
    assert replay.main([str(tmp_path / "empty")]) == 1


def test_the_flows_stream_from_the_file(tmp_path):
    folder = scenario(tmp_path, "s", mirai_log())
    flows = read_zeek(os.path.join(folder, "bro", "conn.log.labeled"))
    assert next(flows).label == "Benign"                    # a generator: big logs are never held whole


# --- update 41: what the Pi's first run showed -------------------------------------------------------

def test_other_header_names_and_separators_keep_the_detailed_label(tmp_path):
    rows = [row(0, "45.1.1.7", 23, "Malicious   PartOfAHorizontalPortScan", state="S0", history="S", opk=1, rpk=0)]
    det = HEADER.replace("label   detailed-label\n", "label\tdet_label\n")          # 34-1's header
    tabs = det + rows[0].replace("   ", "\t")
    plain = HEADER.replace("\ttunnel_parents   label   detailed-label\n", "\ttunnel_parents\n") + rows[0]
    stray_tab = HEADER + rows[0].replace("\n", "\t\n")
    for text in (det + rows[0], tabs, plain, stray_tab):
        (r,) = zeek_rows_from(text)
        assert (r["label"], r["detailed-label"], r["id.resp_p"]) == ("Malicious", "PartOfAHorizontalPortScan", "23")


def test_a_label_without_a_kind_is_reported_as_such(tmp_path):
    text = HEADER + "".join(row(1200 + i * 0.01, "203.0.113.9", 80, "Malicious   -", state="S0", history="S",
                                opk=1, rpk=0, ob=0, rb=0, dur="-") for i in range(400))
    said = []
    res = replay.replay(scenario(tmp_path, "CTU-IoT-Malware-Capture-98-1", text), say=said.append)
    (r,) = res["rows"]
    assert r["label"] == "Malicious" and r["detected"] and r["fitting"] is None
    assert any("(the label names no kind)" in s for s in said)
    assert "detected (the label names no kind), after" in replay.report_md([res])


def test_each_behaviour_says_what_its_traffic_looks_like(tmp_path):
    res = replay.replay(scenario(tmp_path, "CTU-IoT-Malware-Capture-99-1", mirai_log()), say=lambda _: None)
    by = {r["label"]: r for r in res["rows"]}
    assert by["C&C-HeartBeat"]["traffic"] == "port 6667/tcp (100%), 1 internet address, 0% unanswered, every 60 s"
    assert by["PartOfAHorizontalPortScan"]["traffic"] == "port 23/tcp (100%), 60 internet addresses, 100% unanswered, 2 a second"
    assert "| port 6667/tcp (100%)" in replay.report_md([res])


def test_folders_with_several_captures_and_stray_files(tmp_path, capsys):
    for sub in ("Somfy-01", "Somfy-02"):                                  # IoT-23's door lock (7-1) has six
        d = tmp_path / "CTU-Honeypot-Capture-7-1" / sub / "bro"
        d.mkdir(parents=True)
        (d / "conn.log.labeled").write_text(HEADER + "".join(
            row(i * 30, "52.94.3.20", 443, src="192.168.1.150", service="ssl") for i in range(5)))
    (tmp_path / "CTU-Honeypot-Capture-7-1" / "bro").mkdir()             # left empty by an earlier download
    (tmp_path / "results.md").write_text("an earlier report\n")
    folders = [str(p) for p in sorted(tmp_path.iterdir())]
    assert replay.main(folders) == 0
    out = capsys.readouterr().out
    assert "CTU-Honeypot-Capture-7-1/Somfy-01: 5 flows (0 labelled malicious)" in out
    assert "CTU-Honeypot-Capture-7-1/Somfy-02" in out and "results.md" not in out
    assert "smart-home captures: 2, 0.1 h, 0 false alarms" in out


def test_get_iot23_finds_logs_in_subfolders_and_skips_missing_ones(tmp_path):
    import functools
    import http.server
    import shutil
    import subprocess
    import threading
    import pytest
    if not shutil.which("curl") or not shutil.which("bash"):
        pytest.skip("needs bash and curl")
    site = tmp_path / "site" / "IndividualScenarios"
    (site / "CTU-IoT-Malware-Capture-99-1" / "bro").mkdir(parents=True)
    (site / "CTU-IoT-Malware-Capture-99-1" / "bro" / "conn.log.labeled").write_text(mirai_log())
    for sub in ("Somfy-01", "Somfy-02"):
        (site / "CTU-Honeypot-Capture-7-1" / sub / "bro").mkdir(parents=True)
        (site / "CTU-Honeypot-Capture-7-1" / sub / "bro" / "conn.log.labeled").write_text(HEADER)
    (site / "CTU-Honeypot-Capture-7-1" / "README.md").write_text("Somfy door lock\n")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(tmp_path / "site")))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env.update(IOT23_BASE=f"http://127.0.0.1:{server.server_address[1]}/IndividualScenarios",
               IOT23_DIR=str(tmp_path / "out"))
    try:
        r = subprocess.run(["bash", os.path.join(replay.ROOT, "scripts", "get_iot23.sh"), "99-1", "hp-7-1", "77-1"],
                           env=env, capture_output=True, text=True, timeout=120)
    finally:
        server.shutdown()
    assert r.returncode == 0, r.stdout + r.stderr
    out = tmp_path / "out"
    assert (out / "CTU-IoT-Malware-Capture-99-1" / "bro" / "conn.log.labeled").read_text() == mirai_log()
    for sub in ("Somfy-01", "Somfy-02"):
        assert (out / "CTU-Honeypot-Capture-7-1" / sub / "bro" / "conn.log.labeled").exists()
    assert not (out / "CTU-Honeypot-Capture-7-1" / "bro").exists()
    assert "no labelled log found" in r.stdout and not (out / "CTU-IoT-Malware-Capture-77-1" / "bro").exists()
