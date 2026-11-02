"""Messages meet network traffic: websites from flagged messages watched on the lab Wi-Fi, and
the list of devices with a risk level. The flows are written by hand; nothing is sent."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.server import create_app
from detectors.net.baseline import Baselines
from detectors.net.engine import NetEngine
from detectors.net.flows import TCP, UDP, FlowRec
from detectors.net.scamlinks import ScamLinks
from detectors.sms.detector import SmsDetector
from detectors.url.detector import UrlDetector

TOKEN = "pair1234"
SCAM = ("Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc-verify-ps3lab.xyz/login "
        "also https://onlinesbi.sbi and bit.ly/3xYz12")
PARCEL = "Your parcel is held. Pay Rs 25 fee: http://po9.in/Ab12 or call now"
PHONE, LAPTOP, ESP32, PI = "10.42.0.97", "10.42.0.214", "10.42.0.170", "10.42.0.1"


@pytest.fixture(scope="module")
def detector():
    return SmsDetector()


def client(detector, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_TOKEN", TOKEN)
    return TestClient(create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                                 net_state=str(tmp_path / "devices.json"), net_watch=str(tmp_path / "watch.json"),
                                 leases=(str(tmp_path / "leases"),), net_explain_every_s=None))


def engine(tmp_path):
    return NetEngine(url_detector=UrlDetector(model_path=None, intel_path=None, top_sites=None), dga_model=None,
                     leases=None, watch_path=str(tmp_path / "watch.json"))


def lookup(t, name, src=LAPTOP):
    return FlowRec(start_ms=t, end_ms=t + 30, src=src, dst=PI, sport=50000, dport=53, proto=UDP, pkts_out=1,
                   pkts_in=1, bytes_out=40, bytes_in=90, server_name=name, app="DNS")


# --- the watch list --------------------------------------------------------------------
def test_flagged_messages_put_their_websites_on_the_watch_list(detector, tmp_path, monkeypatch):
    c, h = client(detector, tmp_path, monkeypatch), {"X-Guardian-Token": TOKEN}
    assert c.post("/sms", json={"message": SCAM, "sender": "9812345678", "test": True}, headers=h).status_code == 200
    c.post("/sms", json={"message": PARCEL, "sender": "9812345678", "test": True, "channel": "chat",
                         "app": "whatsapp"}, headers=h)
    c.post("/sms", json={"message": "Big sale! 50% off at http://www.flipkart.com today only",
                         "sender": "AX-FLPKRT-P", "test": True}, headers=h)
    watch = json.loads((tmp_path / "watch.json").read_text())
    # not the bank's official site, the link shortener, or the safe message's link:
    assert set(watch) == {"sbi-kyc-verify-ps3lab.xyz", "po9.in"}
    assert watch["sbi-kyc-verify-ps3lab.xyz"]["where"] == "an SMS from a mobile number"
    assert watch["po9.in"]["where"] == "a chat message from an unknown number"
    assert watch["po9.in"]["until_ms"] - watch["po9.in"]["at_ms"] == 24 * 3600_000


# --- the monitor's side ----------------------------------------------------------------------
def test_opening_a_link_from_a_scam_message_is_an_alert_for_that_device(tmp_path):
    ScamLinks(str(tmp_path / "watch.json")).add(["po9.in", "sbi-kyc-verify-ps3lab.xyz"], "dangerous",
                                                 "delivery_fee_scam", "an SMS from a mobile number")
    e, now_ms = engine(tmp_path), int(time.time() * 1000)
    found = e.feed(lookup(now_ms + 5_000, "po9.in"))       # the link checker alone rates po9.in safe
    assert [f.category for f in found] == ["scam_link_opened"] and found[0].verdict == "dangerous"
    assert "opened a website that came in a message the Pi flagged as a scam at" in found[0].reasons[0]
    assert "an SMS from a mobile number" in found[0].reasons[0] and "po9" not in found[0].reasons[0]
    assert found[0].entities["peer"] == "po9[.]in" and found[0].entities["device"] == LAPTOP
    # a phishing name that also came in a message: one alert, the one that says where it came from
    assert [f.category for f in e.feed(lookup(now_ms + 6_000, "sbi-kyc-verify-ps3lab.xyz"))] == ["scam_link_opened"]
    assert e.feed(lookup(now_ms + 20_000, "www.po9.in")) == []             # the same again: no repeat


def test_only_lookups_after_the_message_and_within_a_day_count(tmp_path):
    t = [1_793_000_000.0]
    ScamLinks(str(tmp_path / "watch.json"), clock=lambda: t[0]).add(["po9.in"], "dangerous", "delivery_fee_scam",
                                                                  "an SMS")
    msg_ms, e = int(t[0] * 1000), engine(tmp_path)
    assert e.feed(lookup(msg_ms - 5 * 60_000, "po9.in")) == []           # before the message came
    assert e.feed(lookup(msg_ms + 25 * 3600_000, "po9.in")) == []        # more than a day later
    assert e.feed(lookup(msg_ms + 60_000, "another-site.in")) == []
    assert e.feed(lookup(msg_ms + 60_000, "po9.in", src="45.33.32.156")) == []      # not a lab device
    assert [f.category for f in e.feed(lookup(msg_ms + 60_000, "po9.in"))] == ["scam_link_opened"]


def test_the_monitor_remembers_when_each_device_was_last_active(tmp_path):
    path, t0 = str(tmp_path / "devices.json"), 1_793_000_000_000
    b = Baselines(path=path)
    for t, src in ((t0, PHONE), (t0 + 5_000, PHONE), (t0, "0.0.0.0"), (t0, "169.254.10.20")):
        b.update(FlowRec(start_ms=t, end_ms=t + 10, src=src, dst="142.250.1.1", sport=40000, dport=443,
                         proto=TCP, pkts_out=3, pkts_in=3, bytes_out=500, bytes_in=900, syn_out=1))
    b.save()
    data = json.loads(open(path).read())
    assert data[PHONE]["last_ms"] == t0 + 5_000 and set(data) == {PHONE}     # not 0.0.0.0 or link-local
    assert Baselines(path=path).devices[PHONE].last_ms == t0 + 5_000


# --- the device list -------------------------------------------------------------------------
def test_devices_are_listed_riskiest_first(detector, tmp_path, monkeypatch):
    now = time.time()
    now_ms = int(now * 1000)

    def alert(ip, verdict, category, age_s, name=""):
        e = {"device": ip, "time_ms": now_ms - int(age_s * 1000)}
        if name:
            e["device_name"] = name
        f = {"source": "net", "verdict": verdict, "score": 0.9, "category": category,
             "reasons": [f"{ip} did something"], "entities": e, "language": "en"}
        return json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - age_s)), "finding": f})

    (tmp_path / "alerts.jsonl").write_text("\n".join([
        alert(LAPTOP, "suspicious", "network_scan", 3 * 86400),               # earlier this week
        alert(ESP32, "suspicious", "malware_beacon", 3600, "esp32-lab"),
        alert(LAPTOP, "dangerous", "scam_link_opened", 300, "Arrehnius11425"),
        alert(LAPTOP, "dangerous", "dga_domains", 600, "Arrehnius11425"),       # older, but written later
        alert("10.42.0.50", "dangerous", "dga_domains", 9 * 86400),            # more than a week ago
    ]) + "\n")
    (tmp_path / "devices.json").write_text(json.dumps({
        PHONE: {"first_ms": now_ms - 3 * 3600_000, "last_ms": now_ms - 120_000},
        "10.42.0.33": {"first_ms": now_ms - 600_000, "last_ms": now_ms - 60_000},           # new: learning
        "10.140.209.9": {"first_ms": now_ms - 20 * 86400_000, "last_ms": now_ms - 15 * 86400_000},  # long gone
        "10.140.209.154": {"first_ms": now_ms - 5 * 86400_000},       # saved before "last active" existed
        "0.0.0.0": {"first_ms": now_ms - 3600_000, "last_ms": now_ms - 60_000},    # asking for an address
    }))
    (tmp_path / "leases").write_text(f"{PHONE} Piyush-s-S25\n")
    d = client(detector, tmp_path, monkeypatch).get("/devices").json()["devices"]
    assert [x["ip"] for x in d] == [LAPTOP, ESP32, "10.42.0.33", PHONE]
    laptop, esp, new, phone = d
    assert laptop["risk"] == "at_risk" and laptop["name"] == "Arrehnius11425" and laptop["alerts_week"] == 3
    assert laptop["summary"].startswith("2 dangerous alerts in the last 24 hours. The latest: Link from a scam")
    assert [a["headline"].split(":")[0] for a in laptop["latest"]] == ["DANGEROUS", "DANGEROUS", "SUSPICIOUS"]
    assert laptop["latest"][0]["headline"].endswith("Link from a scam message opened")      # newest first
    assert laptop["alerts_24h"] == {"dangerous": 2, "suspicious": 0}
    assert esp["risk"] == "check" and esp["name"] == "esp32-lab" and esp["summary"].startswith("1 suspicious alert")
    assert new["risk"] == "ok" and new["learning_until"] and new["summary"] == "No alerts in the last 24 hours."
    assert phone["name"] == "Piyush-s-S25" and phone["learning_until"] is None and phone["last_active"]
