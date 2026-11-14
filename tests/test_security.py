"""Update 36: the pairing token on every request, the lab device's own token, the limit on wrong
tokens, study phones, the SMS model guard, one pass per message on /sms, and the start script's
switch to a long token. Every message here is made up."""
import json
import os
import subprocess
import sys

import joblib
import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.server import PAGE, TokenGuard, create_app
from app.sms_log import SmsLog, StudyPhones
from detectors.sms import detector as det
from tests.auth import AUTH, TOKEN, client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAM = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc-ps3lab.xyz/verify"
READING = {"device": "esp32-lab", "mode": "normal", "readings": {"temp_c": 27.4}}
# Every route of the app, with a body it accepts when the token is right.
ROUTES = [("GET", "/health", {}), ("POST", "/check", {"json": {"message": "ok see you at 6"}}),
          ("POST", "/url", {"json": {"url": "https://onlinesbi.sbi"}}),
          ("POST", "/sms", {"json": {"message": "ok see you at 6", "test": True}}),
          ("POST", "/file?name=a.txt", {"content": b"hello"}), ("GET", "/explain/nope", {}),
          ("GET", "/alerts", {}), ("POST", "/iot", {"json": READING}), ("GET", "/iot", {}),
          ("GET", "/devices", {}), ("POST", "/iot/mode", {"json": {"device": "esp32-lab", "mode": "normal"}})]


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture(scope="module")
def detector():
    return det.SmsDetector(url_detector=None)


@pytest.fixture
def make(detector, tmp_path):
    clock = Clock()

    def build(**kw):
        return create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                          net_state=str(tmp_path / "devices.json"), net_watch=str(tmp_path / "watch.json"),
                          sms_log=SmsLog(tmp_path / "sms.jsonl"), net_explain_every_s=None,
                          token_guard=TokenGuard(clock=clock), **kw)
    build.clock, build.watch = clock, tmp_path / "watch.json"
    return build


def call(c, method, path, kw, token=None):
    headers = {"X-Guardian-Token": token} if token is not None else {}
    return c.request(method, path, headers=headers, **kw)


# --- the pairing token ---------------------------------------------------------------------------

def test_every_route_needs_the_token_but_the_page(make):
    c = TestClient(make())                                     # sends no token of its own
    assert c.get("/").status_code == 200                       # the page asks for the token itself
    for method, path, kw in ROUTES:
        assert call(c, method, path, kw).status_code == 401, path
        assert call(c, method, path, kw).json()["detail"] == "pairing token needed (X-Guardian-Token)"
    ok = client(make())
    for method, path, kw in ROUTES:
        assert call(ok, method, path, kw).status_code not in (401, 429, 503), path


def test_the_pis_own_requests_need_no_token(make, monkeypatch):
    local = TestClient(make(), client=("127.0.0.1", 50000))
    assert local.get("/health").status_code == 200
    monkeypatch.delenv("GUARDIAN_TOKEN")
    assert local.get("/health").status_code == 200
    assert TestClient(make()).get("/health").status_code == 503      # no token on the Pi: nobody else gets in


def test_a_lab_devices_token_only_posts_readings(make, monkeypatch):
    monkeypatch.setenv("GUARDIAN_DEVICE_TOKEN", "old1234a")
    c = TestClient(make())
    assert call(c, "POST", "/iot", {"json": READING}, token="old1234a").status_code == 200
    for method, path, kw in ROUTES:
        if (method, path) != ("POST", "/iot"):
            assert call(c, method, path, kw, token="old1234a").status_code == 401, path


def test_wrong_tokens_block_an_address_for_a_minute(make):
    app = make()
    c = TestClient(app)
    for _ in range(20):                                        # no token at all does not count
        assert c.get("/alerts").status_code == 401
    assert call(c, "GET", "/alerts", {}, token=TOKEN).status_code == 200
    for _ in range(TokenGuard.MAX_WRONG):
        assert call(c, "GET", "/alerts", {}, token="guess").status_code == 401
    r = call(c, "GET", "/alerts", {}, token=TOKEN)             # even the right token, for now
    assert r.status_code == 429 and "wait a minute" in r.json()["detail"]
    make.clock.t += TokenGuard.WINDOW_S + 1
    assert call(c, "GET", "/alerts", {}, token=TOKEN).status_code == 200
    other = TestClient(app, client=("10.42.0.50", 1))
    assert call(other, "GET", "/alerts", {}, token=TOKEN).status_code == 200    # per address


def test_a_check_without_the_token_cannot_fill_the_watch_list(tmp_path):
    from detectors.url.detector import UrlDetector
    d = det.SmsDetector(url_detector=UrlDetector(model_path=None, intel_path=None, top_sites=None))
    watch = tmp_path / "watch.json"
    app = create_app(detector=d, advisor=Advisor(), net_alerts=str(tmp_path / "a.jsonl"), net_watch=str(watch),
                     net_explain_every_s=None)
    assert TestClient(app).post("/check", json={"message": SCAM, "sender": "9812345678"}).status_code == 401
    assert not watch.exists()
    assert client(app).post("/check", json={"message": SCAM, "sender": "9812345678"}).status_code == 200
    assert "sbi-kyc-ps3lab.xyz" in watch.read_text()


def test_the_page_asks_for_the_token_and_sends_it():
    assert 'id="pair"' in PAGE and "cat ~/.ps3_guardian_token" in PAGE
    assert "opts.headers['X-Guardian-Token']=t" in PAGE and "fetch(" not in PAGE.replace("await fetch(path,opts)", "")


def test_the_start_script_moves_to_a_long_token(tmp_path):
    """The old 8-character token becomes the lab-device token; the phones get a new 22-character one."""
    block = tmp_path / "tokens.sh"
    with open(os.path.join(ROOT, "scripts", "run_pi.sh"), encoding="utf-8") as f:
        text = f.read()
    block.write_text(text[text.index("# Pairing tokens"):text.index('echo "Phones and page')]
                     + 'echo "$GUARDIAN_TOKEN|$GUARDIAN_DEVICE_TOKEN"\n')
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ps3_guardian_token").write_text("a1b2c3d4\n")
    env = {"HOME": str(home), "PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]}
    run = lambda: subprocess.run(["bash", "-c", f"set -euo pipefail; source {block}"], env=env,  # noqa: E731
                                 capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    first = run()
    token, device = first.split("|")
    assert len(token) == 22 and device == "a1b2c3d4"
    assert (home / ".ps3_guardian_token").read_text().strip() == token
    assert oct((home / ".ps3_guardian_token").stat().st_mode & 0o777) == "0o600"
    assert run() == first                                       # the next start changes nothing
    assert "a1b2c3d4" not in text and "pairing token $GUARDIAN_TOKEN" not in text   # never printed


# --- study phones --------------------------------------------------------------------------------

def test_texts_are_kept_only_for_study_phones(tmp_path, detector, capsys):
    study = tmp_path / "study.json"
    study.write_text(json.dumps({"phones": ["B"]}))
    log = SmsLog(tmp_path / "sms.jsonl", study=StudyPhones(study))
    otp, chat = "Your OTP is 482913. Do not share it.", SCAM
    for device in ("B", "C"):
        f, alone = detector.check_pair(otp, sender="JD-HDFCBK-T")
        log.add(otp, "JD-HDFCBK-T", f, alone, device=device)
        f, alone = detector.check_pair(chat, sender="9812345678")
        log.add(chat, "9812345678", f, alone, device=device)
    rows = [json.loads(line) for line in open(tmp_path / "sms.jsonl", encoding="utf-8")]
    assert [(r["device"], r["study"], r["text"] is not None) for r in rows] == [
        ("B", True, True), ("B", True, True), ("C", False, False), ("C", False, False)]
    assert rows[0]["text"] == "Your OTP is ######. Do not share it."
    assert rows[2]["verdict"] and rows[2]["sender_kind"] == "business"      # the rest is still logged
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import sms_traffic
    sms_traffic.measure_log(str(tmp_path / "sms.jsonl"), str(tmp_path / "labels.json"))
    out = capsys.readouterr().out
    assert "4 messages, 0 labelled; 2 without text" in out and "; 2 from phones not in the study)" in out
    study.write_text(json.dumps({"phones": ["*"]}))
    os.utime(study, (1, 1))                                     # a new modification time: re-read
    assert log.study.includes("C") and log.study.includes(None)


def test_study_phones_start_as_the_phones_already_in_the_log(tmp_path, capsys):
    log_path = tmp_path / "sms.jsonl"
    log_path.write_text("\n".join(json.dumps({"device": d}) for d in ("B", "C", None, "B")) + "\n")
    study = StudyPhones(tmp_path / "data" / "study.json", log_path=log_path)
    assert study.includes("C") and study.includes(None) and not study.includes("D")
    assert json.loads((tmp_path / "data" / "study.json").read_text())["phones"] == ["-", "B", "C"]
    assert "created" in capsys.readouterr().out
    (tmp_path / "data" / "study.json").write_text("not json")
    os.utime(tmp_path / "data" / "study.json", (2, 2))
    assert not study.includes("B")                              # unreadable: keep no texts


# --- the SMS model -------------------------------------------------------------------------------

def test_the_app_refuses_a_missing_or_toy_model(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDIAN_ALLOW_SAMPLE_MODEL")
    with pytest.raises(RuntimeError, match="train_baseline.py --data ~/merged_sms.csv"):
        det.SmsDetector(model_path=str(tmp_path / "missing.joblib"), url_detector=None)
    with pytest.raises(RuntimeError, match="trained on the 30-message sample"):
        det.SmsDetector(model_path=det.tb.SAMPLE_MODEL, url_detector=None)
    bundle = joblib.load(det.tb.SAMPLE_MODEL)
    bundle.update(data="merged_sms.csv", messages=4237)
    joblib.dump(bundle, tmp_path / "real.joblib")
    d = det.SmsDetector(model_path=str(tmp_path / "real.joblib"), url_detector=None)
    assert d.info["messages"] == 4237 and d.info["data"] == "merged_sms.csv" and d.info["features"] > 0


def test_health_says_what_the_model_learned_from(make):
    info = client(make()).get("/health").json()["sms_model"]
    assert info["version"] == 1 and info["file"] == "sms_sample.joblib" and info["data"] == "sample_messages.csv"
    assert info["messages"] > 0 and info["date"]
    v2 = det.model_info("x/sms_v2.joblib", {"vec": None, "version": 2, "trained_on": {"fraud": 3, "normal": 5},
                                            "date": "2026-11-14 10:00"})
    assert (v2["version"], v2["messages"], v2["features"]) == (2, 8, 0)


# --- one pass per message ------------------------------------------------------------------------

class CountingLinks:
    def __init__(self):
        from detectors.url.detector import UrlDetector
        self.real, self.calls = UrlDetector(model_path=None, intel_path=None, top_sites=None), 0

    def check_text(self, text):
        self.calls += 1
        return self.real.check_text(text)

    def __getattr__(self, name):
        return getattr(self.real, name)


def test_sms_checks_each_message_once(tmp_path):
    links = CountingLinks()
    d = det.SmsDetector(url_detector=links)
    for msg, snd in ((SCAM, "9812345678"), ("Your OTP is 482913", "JD-HDFCBK-T"), (SCAM, None)):
        pair = d.check_pair(msg, sender=snd)
        assert (pair[0].verdict, pair[0].score) == (d.check(msg, sender=snd).verdict, d.check(msg, sender=snd).score)
        assert (pair[1].verdict, pair[1].score) == (d.check(msg).verdict, d.check(msg).score)
    app = create_app(detector=d, advisor=Advisor(), url_detector=links.real, sms_log=SmsLog(tmp_path / "s.jsonl"),
                     net_alerts=str(tmp_path / "a.jsonl"), net_explain_every_s=None)
    links.calls = 0
    r = TestClient(app, headers=AUTH).post("/sms", json={"message": SCAM, "sender": "9812345678"})
    assert r.status_code == 200 and links.calls == 1
    assert r.json()["text_only"]["verdict"] in ("suspicious", "dangerous")
