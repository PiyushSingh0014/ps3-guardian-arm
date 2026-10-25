"""POST /sms (Android companion): pairing token, text-only verdict, privacy of the traffic log, chats."""
import csv
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.server import create_app
from app.sms_log import SmsLog, mask_digits
from detectors.sms.detector import SmsDetector

SCAM = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify"
OTP = "482913 is your OTP for login. Do not share it with anyone."
CHAT = "ok see you at 6"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_TOKEN", "abc123")
    log = SmsLog(tmp_path / "sms.jsonl")
    c = TestClient(create_app(detector=SmsDetector(), advisor=Advisor(), sms_log=log))
    c.log_path = log.path
    return c


def entries(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def test_token_is_required(client, monkeypatch):
    assert client.post("/sms", json={"message": SCAM}).status_code == 401
    assert client.post("/sms", json={"message": SCAM}, headers={"X-Guardian-Token": "nope"}).status_code == 401
    monkeypatch.delenv("GUARDIAN_TOKEN")
    assert client.post("/sms", json={"message": SCAM}, headers={"X-Guardian-Token": "abc123"}).status_code == 503


def test_answer_has_both_verdicts_and_a_log_id(client):
    r = client.post("/sms", json={"message": SCAM, "sender": "9812345678"}, headers={"X-Guardian-Token": "abc123"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding"]["verdict"] in ("suspicious", "dangerous") and "raw_text" not in body["finding"]
    assert set(body["text_only"]) == {"verdict", "score"} and body["log_id"]
    e = entries(client.log_path)[-1]
    assert e["id"] == body["log_id"] and e["sender"] == "mobile" and e["sender_kind"] == "mobile"
    assert "9812345678" not in json.dumps(e)                    # no phone number in the log


def test_test_button_messages_are_not_logged(client):
    r = client.post("/sms", json={"message": SCAM, "sender": "9812345678", "test": True},
                    headers={"X-Guardian-Token": "abc123"})
    assert r.status_code == 200 and r.json()["log_id"] is None
    assert not client.log_path.exists()


def test_log_masks_digits_and_skips_safe_personal_texts(client):
    h = {"X-Guardian-Token": "abc123"}
    client.post("/sms", json={"message": OTP, "sender": "JD-HDFCBK-S"}, headers=h)
    client.post("/sms", json={"message": CHAT, "sender": "+91 98123 45678"}, headers=h)
    otp, chat = entries(client.log_path)[-2:]
    assert otp["sender"] == "JD-HDFCBK-S" and otp["text"] == mask_digits(OTP) and "482913" not in otp["text"]
    if chat["verdict"] == "safe":
        assert chat["text"] is None                              # personal and safe: text not kept


def label_rows(path, labels):
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
        fields = list(rows[0].keys())
    for r, lab in zip(rows, labels):
        r["label"] = lab
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def test_export_and_measure(client, tmp_path):
    h = {"X-Guardian-Token": "abc123"}
    for msg, snd in ((SCAM, "9812345678"), (OTP, "JD-HDFCBK-S")):
        client.post("/sms", json={"message": msg, "sender": snd}, headers=h)
    out = tmp_path / "traffic.csv"
    script = os.path.join(ROOT, "scripts", "sms_traffic.py")
    subprocess.run([sys.executable, script, "export", str(out), "--log", str(client.log_path)], check=True)
    label_rows(out, ["smishing"])                                       # label the first row only
    res = subprocess.run([sys.executable, script, "measure", str(out)], check=True, capture_output=True, text=True)
    assert "2 messages, 1 labelled" in res.stdout and "fraud" in res.stdout


def test_chat_from_an_unknown_number(client):
    h = {"X-Guardian-Token": "abc123"}
    r = client.post("/sms", json={"message": SCAM, "sender": "+91 98123 45678", "channel": "chat",
                                  "app": "whatsapp", "device": "A"}, headers=h)
    assert r.status_code == 200
    e = entries(client.log_path)[-1]
    assert (e["channel"], e["app"], e["device"], e["sender"]) == ("chat", "whatsapp", "A", "mobile")
    assert "98123" not in json.dumps(e)
    assert e["score"] >= e["text_score"]                  # a risky text from a number counts more, as for SMS


def test_chat_sender_names_are_not_trusted_or_stored(client):
    """A chat sender shown as a name ('AIRTEL') is not a registered sender ID: no discount, not logged."""
    h = {"X-Guardian-Token": "abc123"}
    client.post("/sms", json={"message": SCAM, "sender": "AIRTEL", "channel": "chat", "app": "messages"},
                headers=h)
    client.post("/sms", json={"message": CHAT, "sender": "Rahul", "channel": "chat", "app": "messages"},
                headers=h)
    scam, chat = entries(client.log_path)[-2:]
    assert scam["sender"] == "name" and scam["score"] == scam["text_score"]
    assert "AIRTEL" not in json.dumps(scam) and "Rahul" not in json.dumps(chat)
    if chat["verdict"] == "safe":
        assert chat["text"] is None                       # a safe chat is never stored


def test_sms_fields_default_and_device_is_cleaned(client):
    h = {"X-Guardian-Token": "abc123"}
    client.post("/sms", json={"message": OTP, "sender": "JD-HDFCBK-S", "device": "Phone <B>!"}, headers=h)
    e = entries(client.log_path)[-1]
    assert (e["channel"], e["app"], e["device"]) == ("sms", None, "Phone B")
    bad = client.post("/sms", json={"message": OTP, "channel": "email"}, headers=h)
    assert bad.status_code == 422


def test_measure_splits_sms_and_chats(client, tmp_path):
    h = {"X-Guardian-Token": "abc123"}
    client.post("/sms", json={"message": SCAM, "sender": "9812345678", "device": "A"}, headers=h)
    client.post("/sms", json={"message": SCAM, "sender": "+919812345670", "channel": "chat", "app": "messages",
                              "device": "B"}, headers=h)
    out = tmp_path / "traffic.csv"
    script = os.path.join(ROOT, "scripts", "sms_traffic.py")
    subprocess.run([sys.executable, script, "export", str(out), "--log", str(client.log_path)], check=True)
    label_rows(out, ["smishing", "smishing"])
    res = subprocess.run([sys.executable, script, "measure", str(out)], check=True, capture_output=True, text=True)
    assert "Phones: A 1, B 1" in res.stdout and "SMS only" in res.stdout and "CHAT only" in res.stdout
