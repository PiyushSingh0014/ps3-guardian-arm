"""POST /sms (Android companion): pairing token, text-only verdict, privacy of the traffic log."""
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


def test_export_and_measure(client, tmp_path):
    h = {"X-Guardian-Token": "abc123"}
    for msg, snd in ((SCAM, "9812345678"), (OTP, "JD-HDFCBK-S")):
        client.post("/sms", json={"message": msg, "sender": snd}, headers=h)
    out = tmp_path / "traffic.csv"
    script = os.path.join(ROOT, "scripts", "sms_traffic.py")
    subprocess.run([sys.executable, script, "export", str(out), "--log", str(client.log_path)], check=True)
    text = out.read_text(encoding="utf-8-sig").replace(",,", ",smishing,", 1)   # label the first row
    out.write_text(text, encoding="utf-8-sig")
    res = subprocess.run([sys.executable, script, "measure", str(out)], check=True, capture_output=True, text=True)
    assert "2 messages, 1 labelled" in res.stdout and "fraud" in res.stdout
