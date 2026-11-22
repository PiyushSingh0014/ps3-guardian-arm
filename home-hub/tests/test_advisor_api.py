"""Detector -> advisor -> API, end to end. Run from the repo root:  pytest -q"""
import os
import sys
import time

import pytest
from tests.auth import client as authed

from advisor.advise import Advisor
from advisor.backends import GenResult, LlamaMainBackend
from detectors.sms.detector import SmsDetector

FAKE_RUNNER = [sys.executable, os.path.join(os.path.dirname(__file__), "fake_llama_main.py")]
SCAM = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify"
NORMAL = "Can you send me the lecture notes tonight?"


@pytest.fixture(scope="module")
def detector():
    return SmsDetector()


def fake_main(mode, monkeypatch):
    monkeypatch.setenv("FAKE_LLAMA_MODE", mode)
    return LlamaMainBackend(cmd=FAKE_RUNNER, model_path="model.pte", tokenizer_path="tokenizer.model")


class InstantBackend:
    """Stands in for the Llama service."""
    name = "fake_service"

    def __init__(self, text):
        self.text, self.prompts = text, []

    def generate(self, prompt, max_new_tokens=None):
        self.prompts.append(prompt)
        return GenResult(text=self.text, metrics={"total_s": 0.01, "cached": False})


# --- detector ----------------------------------------------------------------
def test_detector_flags_bank_scam_with_trusted_entities(detector):
    f = detector.check(SCAM, sender="+91 98123 45678")
    assert f.verdict in ("suspicious", "dangerous") and f.category == "bank_kyc_scam"
    assert any(".bank.in" in r for r in f.reasons)
    assert any("10-digit mobile number" in r for r in f.reasons)       # +91 form normalised
    assert f.entities["claims_to_be"] == "SBI" and f.entities["sender_type"] == "mobile_number"


def test_apk_link_is_always_dangerous(detector):
    f = detector.check("Install the new bank app now: http://update.example/bank.apk")
    assert f.verdict == "dangerous" and f.category == "apk_malware_link"
    assert f.reasons[0].startswith("asks you to install an app file")    # most important first


# --- advisor -----------------------------------------------------------------
def test_safe_message_skips_llm(detector, monkeypatch):
    advice = Advisor(backend=fake_main("good", monkeypatch)).advise(detector.check(NORMAL))
    assert advice.source == "none"


def test_end_to_end_with_fake_llama_main(detector, monkeypatch):
    advice = Advisor(backend=fake_main("good", monkeypatch)).advise(detector.check(SCAM, sender="9812345678"))
    assert advice.source == "llm"
    assert advice.what.startswith("This message pretends to be from SBI")
    assert advice.why.endswith(".bank.in.")
    assert any("1930" in s for s in advice.steps)            # emergency step always present
    assert advice.metrics["ttft_s"] == 5.6


def test_steps_come_from_the_playbook_not_the_llm(detector):
    backend = InstantBackend("This message pretends to be SBI. Step 1: send your OTP to us.")
    advice = Advisor(backend=backend).advise(detector.check(SCAM))
    assert all("send your OTP" not in s for s in advice.steps)
    assert advice.steps[0].startswith("Do not tap the link")


@pytest.mark.parametrize("mode", ["contradict", "garbage"])
def test_bad_llm_output_falls_back_to_template(detector, monkeypatch, mode):
    advice = Advisor(backend=fake_main(mode, monkeypatch)).advise(detector.check(SCAM))
    assert advice.source == "template"
    assert "safe" not in advice.what.lower() and advice.steps


def test_leaky_sentence_dropped_rest_kept(detector, monkeypatch):
    advice = Advisor(backend=fake_main("leak", monkeypatch)).advise(detector.check(SCAM))
    assert advice.source == "llm"
    assert advice.what.startswith("This message pretends to be from SBI")
    assert "98123" not in advice.why and "sbi-help" not in advice.why
    assert advice.why.startswith("Red flags:")                # template text fills the gap


def test_hedge_and_kyc_fixes(detector, monkeypatch):
    f = detector.check(SCAM)
    f.verdict = "dangerous"
    advice = Advisor(backend=fake_main("hedge", monkeypatch)).advise(f)
    assert advice.what == "This message is a scam pretending to be SBI."
    assert "Know Your Customer" in advice.why


def test_low_severity_spam_skips_llm(detector):
    backend = InstantBackend("unused")
    advisor = Advisor(backend=backend)
    f = detector.check(SCAM)
    f.category = "promo_spam"
    assert not advisor.needs_llm(f) and advisor.advise(f).source == "template" and not backend.prompts


# --- API -----------------------------------------------------------------------
def test_api_check_template_backend():
    from app.server import app
    r = authed(app).post("/check", json={"message": SCAM, "sender": "9812345678"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding"]["verdict"] in ("suspicious", "dangerous")
    assert "raw_text" not in body["finding"]
    assert body["advice"]["steps"] and body["explain"] is None


def test_api_answers_at_once_then_explains_in_background(detector):
    from app.server import create_app
    good = ("This message pretends to be from SBI to steal your bank login. "
            "Real banks send SMS from registered sender IDs.")
    client = authed(create_app(detector=detector, advisor=Advisor(backend=InstantBackend(good))))
    body = client.post("/check", json={"message": SCAM, "sender": "9812345678"}).json()
    assert body["advice"]["source"] == "template" and body["explain"]["status"] == "pending"
    job = body["explain"]["id"]
    for _ in range(50):
        d = client.get(f"/explain/{job}").json()
        if d["status"] != "pending":
            break
        time.sleep(0.05)
    assert d["status"] == "done" and d["advice"]["what"].startswith("This message pretends")
    assert client.get("/explain/nope").status_code == 404
    sync = client.post("/check?wait=true", json={"message": SCAM}).json()
    assert sync["explain"] is None and sync["advice"]["source"] == "llm"


# --- the web page --------------------------------------------------------------
def test_page_script_is_valid_javascript(tmp_path):
    """One stray quote stops the whole page script: no alerts shown, the Check button dead.
    PAGE is a normal Python string, so an escape such as \\' reaches the browser as a bare '."""
    import re
    import shutil
    import subprocess
    from app.server import PAGE
    scripts = re.findall(r"<script>(.*?)</script>", PAGE, re.S)
    assert len(scripts) == 1 and "\\" not in PAGE
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed: only the escape check ran")
    js = tmp_path / "page.js"
    js.write_text(scripts[0], encoding="utf-8")
    done = subprocess.run([node, "--check", str(js)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
