"""Network detector (detectors/net): rules, names, baseline, engine, monitor and the app's alert list.

The flows here are written by hand as records (no packets are made or sent): each test
describes what a scan, a flood or a beacon looks like as connection summaries.
"""
import json

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.server import create_app
from detectors.net import monitor
from detectors.net.baseline import BUCKET_MS, Baselines
from detectors.net.engine import NetEngine
from detectors.net.flows import TCP, UDP, FlowRec, from_cic_row
from detectors.url import intel
from detectors.url.detector import UrlDetector

T0 = 1_790_000_000_000
DEV, PI = "10.42.0.23", "10.42.0.1"


def flow(t, dst, dport, src=DEV, proto=TCP, pin=0, pout=1, bout=0, bin_=0, dur=5, syn=1, rst=0, name="", app=""):
    return FlowRec(start_ms=t, end_ms=t + dur, src=src, dst=dst, sport=40000 + t % 20000, dport=dport, proto=proto,
                   pkts_out=pout, pkts_in=pin, bytes_out=bout, bytes_in=bin_, syn_out=syn, rst_in=rst,
                   server_name=name, app=app)


def engine(**kw):
    kw.setdefault("url_detector", UrlDetector(model_path=None, intel_path=None, top_sites=None))
    kw.setdefault("dga_model", None)
    kw.setdefault("leases", None)
    return NetEngine(**kw)


def run(e, flows):
    out = []
    for f in flows:
        out += e.feed(f)
    return out


def test_port_scan_is_reported_once_then_escalated():
    e = engine()
    found = run(e, [flow(T0 + i * 200, PI, 1000 + i, pin=1, rst=1) for i in range(150)])
    cats = [(f.category, f.verdict) for f in found]
    assert cats == [("port_scan", "suspicious"), ("port_scan", "dangerous")]     # at 20 ports, then at 100
    assert found[0].entities["device"] == DEV and found[0].entities["peer"] == PI
    assert "tried 20 different ports" in found[0].reasons[0]


def test_normal_browsing_raises_nothing():
    e = engine()
    flows = []
    for i in range(300):                       # 300 answered connections to a few servers over 50 minutes
        flows.append(flow(T0 + i * 10_000, f"142.250.{i % 4}.10", 443, pin=12, pout=10, bout=900, bin_=40_000))
        flows.append(flow(T0 + i * 10_000 + 1, PI, 53, proto=UDP, pin=1, bout=40, bin_=90, name="www.google.com"))
    assert run(e, flows) == []


def test_telnet_sweep_is_a_botnet_sign():
    e = engine()
    found = run(e, [flow(T0 + i * 500, f"45.{i}.3.9", 23) for i in range(20)])
    assert [f.category for f in found] == ["risky_port", "network_scan"]     # the first try, then the sweep
    assert found[1].verdict == "dangerous" and "Mirai" in " ".join(found[1].reasons)


def test_flood_and_password_guessing():
    e = engine()
    flood = run(e, [flow(T0 + i * 20, "10.42.0.50", 80, syn=1, pout=1) for i in range(400)])
    assert [f.category for f in flood] == ["dos_flood"]
    guess = run(e, [flow(T0 + 60_000 + i * 2000, PI, 22, pin=8, pout=10, bout=1500, bin_=2000, dur=1500, syn=1)
                    for i in range(20)])
    assert [f.category for f in guess] == ["brute_force"] and "SSH" in guess[0].reasons[0]


def test_risky_port_and_beacon_after_learning():
    e = engine(learn_ms=60_000)
    run(e, [flow(T0, "8.8.4.4", 443, pin=5, pout=5)])                 # the device is seen, learning starts
    found = run(e, [flow(T0 + 120_000 + i * 60_000, "52.95.110.1", 8443, pin=4, pout=4, bout=200, bin_=300)
                    for i in range(10)])
    assert [f.category for f in found] == ["malware_beacon"]
    assert "every 60 seconds" in found[0].reasons[0]
    risky = run(e, [flow(T0 + 2_000_000, "52.95.110.2", 6667, pin=3, pout=3)])
    assert [f.category for f in risky] == ["risky_port"]


def test_beacon_to_a_learned_server_is_normal():
    e = engine(learn_ms=30 * 60_000)
    flows = [flow(T0 + i * 60_000, "52.95.110.1", 8443, pin=4, pout=4, bout=200, bin_=300) for i in range(60)]
    assert run(e, flows) == []                 # the sensor's own cloud, learned while learning


def test_phishing_lookup_names_stay_out_of_the_reasons(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    intel.build({"test": ["evil-login.com"]}, out=db)
    e = engine(url_detector=UrlDetector(model_path=None, intel_path=db, top_sites=None))
    found = run(e, [flow(T0, PI, 53, proto=UDP, pin=1, bout=40, bin_=80, name="pay.evil-login.com", app="DNS"),
                    flow(T0 + 1000, PI, 53, proto=UDP, pin=1, bout=40, bin_=80, name="sbi-kyc-update.xyz", app="DNS")])
    assert [f.category for f in found] == ["phishing_lookup", "phishing_lookup"]
    assert found[0].entities["peer"] == "evil-login[.]com" and found[0].entities["name"] == "pay[.]evil-login[.]com"
    text = " ".join(r for f in found for r in f.reasons)
    assert "evil-login" not in text and "sbi-kyc" not in text and "SBI" in text


class FakeDga:
    def score(self, domain, suffix):
        return 0.99 if domain.startswith("qz") else 0.01


def test_dga_names_and_dns_tunnel():
    e = engine(dga_model=FakeDga())
    names = [f"qz{i}kxwvbtrpl{i}.com" for i in range(6)] + ["wikipedia.org", "github.com"]
    found = run(e, [flow(T0 + i * 10_000, PI, 53, proto=UDP, pin=1, bout=40, bin_=80, name=n, app="DNS")
                    for i, n in enumerate(names)])
    assert [f.category for f in found] == ["dga_domains"]
    assert found[0].entities["names"] == 5 and all("[.]" in x for x in found[0].entities["examples"])
    tunnel = [f"a{i:04d}{'x' * 30}.files.exfil-test.net" for i in range(30)]
    found = run(e, [flow(T0 + 200_000 + i * 1000, PI, 53, proto=UDP, pin=1, bout=120, bin_=80, name=n, app="DNS")
                    for i, n in enumerate(tunnel)])
    assert [f.category for f in found] == ["dns_tunnel"]


def test_device_anomaly_after_learning(tmp_path):
    b = Baselines(learn_ms=3 * 3600_000, path=str(tmp_path / "devices.json"))
    t, hits = T0 - T0 % BUCKET_MS, []
    for k in range(48):                        # 4 hours: 10 connections per 5 minutes to two servers
        for i in range(10):
            hits += b.update(flow(t + k * BUCKET_MS + i * 1000, "52.1.1.1" if i % 2 else "52.1.1.2", 443,
                                  pin=5, pout=5, bout=500, bin_=2000))
    assert hits == []
    burst = t + 48 * BUCKET_MS
    for i in range(400):                       # then 400 connections to 40 new servers, 8 MB sent
        hits += b.update(flow(burst + i * 500, f"185.7.{i % 40}.1", 443, pin=5, pout=20, bout=20_000, bin_=500))
    hits += b.update(flow(burst + BUCKET_MS + 1000, "52.1.1.1", 443, pin=5, pout=5))
    assert [h.category for h in hits] == ["device_anomaly"]
    assert "40 servers it never used before" in hits[0].reasons[1]
    b.save()
    again = Baselines(path=str(tmp_path / "devices.json"))
    assert again.knows(DEV, "52.1.1.1") and not again.learning(DEV, burst)


def test_cic_rows_and_the_monitor_file(tmp_path):
    row = {" Source IP": "172.16.0.1", " Destination IP": "192.168.10.50", " Source Port": "41000",
           " Destination Port": "22", " Protocol": "6", " Timestamp": "4/7/2017 2:10", " Flow Duration": "1500000",
           " Total Fwd Packets": "10", " Total Backward Packets": "8", "Total Length of Fwd Packets": "1200",
           " Total Length of Bwd Packets": "1800", " SYN Flag Count": "1", " RST Flag Count": "0",
           " Label": "SSH-Patator"}
    r = from_cic_row(row)
    assert r.dport == 22 and r.label == "SSH-Patator" and r.duration_ms == 1500
    assert __import__("datetime").datetime.fromtimestamp(r.start_ms / 1000).hour == 14   # "2:10" is 14:10
    out = tmp_path / "alerts.jsonl"
    e = engine()
    flows = [FlowRec(**{**r.__dict__, "start_ms": r.start_ms + i * 2000, "end_ms": r.end_ms + i * 2000})
             for i in range(20)]
    assert monitor.run(iter(flows), e, str(out), show=False) == 1
    line = json.loads(out.read_text().splitlines()[0])
    assert line["finding"]["category"] == "brute_force" and line["finding"]["entities"]["label"] == "SSH-Patator"

    c = TestClient(create_app(detector=__import__("detectors.sms.detector", fromlist=["SmsDetector"]).SmsDetector(
        url_detector=None), advisor=Advisor(), net_alerts=str(out)))
    body = c.get("/alerts").json()
    assert len(body["alerts"]) == 1
    a = body["alerts"][0]
    assert a["advice"]["headline"] == "DANGEROUS: Password guessing" and len(a["advice"]["steps"]) == 3
    assert c.get("/health").json()["net"]["alerts_file"] is True


@pytest.mark.parametrize("cat", ["port_scan", "network_scan", "dos_flood", "brute_force", "risky_port",
                                 "malware_beacon", "phishing_lookup", "dga_domains", "dns_tunnel", "device_anomaly"])
def test_every_network_alert_has_a_playbook(cat):
    from advisor.playbooks import load_playbooks
    books = load_playbooks()
    assert cat in books and books[cat].steps and books[cat].fact


def test_device_names_from_the_copy_or_the_original_list(tmp_path):
    copy, original = tmp_path / "leases", tmp_path / "dnsmasq-wlan0.leases"
    original.write_text("1793460000 aa:bb:cc:dd:ee:01 10.42.0.23 sensor-esp32 01:aa\n"
                        "1793460100 aa:bb:cc:dd:ee:02 10.42.0.50 * *\n")
    e = engine(leases=(str(copy), str(original)))           # no copy yet: the original is read
    assert e.device_name(DEV) == "sensor-esp32" and e.device_name("10.42.0.50") == ""
    copy.write_text("10.42.0.23 kitchen-cam\n")
    e = engine(leases=(str(copy), str(original)))           # the copy wins when it exists
    hits = run(e, [flow(T0 + i * 100, PI, 1000 + i, rst=1, pin=1) for i in range(25)])
    assert hits and hits[0].entities["device_name"] == "kitchen-cam"
    assert "kitchen-cam" not in " ".join(hits[0].reasons)     # self-chosen names never reach Llama


def test_monitor_prints_status_and_learns_the_pi_address(monkeypatch, capsys):
    monkeypatch.setattr(monitor, "FIRST_STATUS_S", 0)
    monkeypatch.setattr(monitor, "STATUS_EVERY_S", 0)
    monkeypatch.setattr(monitor, "iface_address", lambda iface: PI)
    e = engine()
    assert e.gateway is None                                 # the Wi-Fi had no address at start
    monitor.run(iter([flow(T0, "52.1.1.1", 443, syn=1, pin=5, bin_=900)]), e, None, show=True, iface="wlan0")
    assert e.gateway == PI and e.base.gateway == PI
    printed = capsys.readouterr().out
    assert "1 flows so far (1 in the last 1 min), 0 alerts" in printed
