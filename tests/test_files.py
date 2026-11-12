"""Files that come in chats: the checks, the page's and the phone's way in (POST /file), and the
chat warning for app files. Every test file is made here and harmless (scripts/make_file_samples.py)."""
import io
import json
import os
import sys
import zipfile
import zlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import make_file_samples as samples  # noqa: E402

from advisor.advise import Advisor  # noqa: E402
from advisor.playbooks import get_playbook, load_playbooks  # noqa: E402
from advisor.prompt import build_prompt  # noqa: E402
from app.server import create_app  # noqa: E402
from detectors.files.checker import FileChecker, real_type  # noqa: E402
from detectors.sms.detector import SmsDetector  # noqa: E402
from detectors.url.detector import UrlDetector  # noqa: E402


@pytest.fixture(scope="module")
def checker():
    return FileChecker(UrlDetector(model_path=None, intel_path=None, top_sites=None))


@pytest.mark.parametrize("name", list(samples.samples()))
def test_each_sample_gets_the_expected_verdict(checker, name):
    data, expect = samples.samples()[name]
    f = checker.check(data, name)
    assert f.verdict == expect, (name, f.reasons)
    assert f.source == "file" and (f.category == "none") == (expect == "safe")
    text = " ".join(f.reasons)
    stem = name.rsplit(".", 1)[0]
    assert stem not in text and "ps3lab" not in text and "http" not in text      # sender-chosen text stays out


def test_what_each_bad_sample_is_called(checker):
    expect = {"Wedding_Invitation.pdf": "app_file", "Wedding_Card.pdf.apk": "app_file", "ps3-test-photos.zip": "app_file",
              "ps3-test-attachment.pdf": "app_file", "ps3-test-setup.exe": "app_file",
              "ps3-test-autorun.pdf": "harmful_document", "ps3-test-launch.pdf": "harmful_document",
              "ps3-test-hidden-code.pdf": "harmful_document", "ps3-test-macro.docm": "harmful_document",
              "ps3-test-remote-template.docx": "harmful_document", "ps3-test-dde.docx": "harmful_document",
              "ps3-test-kyc-link.pdf": "phishing_document", "ps3-test-kyc-letter.docx": "phishing_document",
              "ps3-test-login.html": "phishing_document"}
    got = {n: checker.check(samples.samples()[n][0], n).category for n in expect}
    assert got == expect
    f = checker.check(samples.samples()["Wedding_Invitation.pdf"][0], "Wedding_Invitation.pdf")
    assert f.reasons[0] == "the file says it is .pdf, but it is really an Android app (APK)"
    assert "read your SMS, control your screen and read your contacts" in f.reasons[1]
    kyc = checker.check(samples.samples()["ps3-test-kyc-link.pdf"][0], "kyc.pdf")
    assert kyc.entities["claims_to_be"] == "SBI" and kyc.entities["links"][0]["verdict"] == "dangerous"


def test_pdf_tricks_and_limits(checker):
    hexed = samples.pdf(extra_catalog=b" /OpenAction 6 0 R",
                        extra_objs=[b"<< /S /J#61vaScript /J#53 (app.alert\\(1\\)) >>"])
    assert checker.check(hexed, "a.pdf").verdict == "dangerous"          # /J#61vaScript is /JavaScript
    code_only = samples.pdf(extra_objs=[b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>"])
    f = checker.check(code_only, "a.pdf")
    assert f.verdict == "suspicious" and "hidden code" in f.reasons[0]   # code, but nothing runs it on opening
    locked = samples.pdf().replace(b"/Root 1 0 R", b"/Root 1 0 R /Encrypt << /Filter /Standard >>")
    f = checker.check(locked, "statement.pdf")
    assert f.verdict == "safe" and "password-protected" in " ".join(f.reasons)


def test_archives_and_disguises(checker):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.pdf", samples.pdf())
    data = bytearray(buf.getvalue())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):          # mark it password-locked
        i = data.find(sig)
        data[i + off] |= 0x1
    f = checker.check(bytes(data), "notes.zip")
    assert f.verdict == "suspicious" and "locked with a password" in f.reasons[0]
    big = io.BytesIO()
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("huge.pdf", b"%PDF-1.7\n" + b"0" * (30 * 1024 * 1024))     # too big to unpack: skipped
    assert checker.check(big.getvalue(), "huge.zip").verdict == "safe"
    page = samples.login_page()
    f = checker.check(page, "invoice.pdf")
    assert f.verdict == "dangerous" and "really a web page" in " ".join(f.reasons)
    assert real_type(b"BMW cars are great") == "text" and real_type(samples.png()) == "image"


def test_a_chat_that_brings_an_app_file_is_dangerous():
    d = SmsDetector(url_detector=None)
    f = d.check("📄 Wedding_Invitation.apk", sender=None)
    assert (f.verdict, f.category) == ("dangerous", "app_file")
    assert f.reasons[0] == "the chat brought an Android app (APK) file, not a document or a photo"
    assert not any("from a link" in r for r in f.reasons)
    assert d.check("Learn node.js and React this summer", sender=None).category != "app_file"


def test_advice_and_llama_prompt_for_files(checker):
    books = load_playbooks()
    for key in ("app_file", "harmful_document", "phishing_document"):
        book = get_playbook(books, key)
        assert book.key == key and book.severity == "critical" and book.fact and book.wants
        assert any("1930" in s for s in book.steps)
    advisor = Advisor()
    bad = checker.check(samples.samples()["Wedding_Invitation.apk"][0], "Wedding_Invitation.apk")
    assert advisor.quick(bad).headline == "DANGEROUS: App or program sent as a file"
    prompt = build_prompt(bad, get_playbook(books, bad.category))
    assert "App or program sent as a file" in prompt and "Wedding" not in prompt
    ok = checker.check(samples.pdf(), "ticket.pdf")
    advice = advisor.quick(ok)
    assert advice.headline.startswith("LIKELY SAFE") and advice.why.startswith("A real PDF")


@pytest.fixture
def app_client(tmp_path):
    detector = SmsDetector(url_detector=UrlDetector(model_path=None, intel_path=None, top_sites=None))
    return TestClient(create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                                 net_state=str(tmp_path / "devices.json"), net_explain_every_s=None))


def test_post_file_checks_in_memory_and_logs_no_name(app_client, monkeypatch):
    data = samples.samples()["ps3-test-kyc-link.pdf"][0]
    r = app_client.post("/file", params={"name": "My_KYC_letter.pdf"}, content=data,
                        headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding"]["verdict"] == "dangerous" and body["finding"]["category"] == "phishing_document"
    assert body["advice"]["headline"] == "DANGEROUS: Document that leads to a fake website"
    with open(os.environ["FILE_LOG"], encoding="utf-8") as f:
        line = f.read()
    assert "KYC" not in line and json.loads(line)["verdict"] == "dangerous"      # the name stays out of the log
    with open(os.environ["NET_WATCH"], encoding="utf-8") as f:                  # the link is watched on the Wi-Fi
        assert "sbi-kyc-update-ps3lab.xyz" in f.read()
    assert app_client.post("/file", content=b"").status_code == 422
    import app.server as server
    monkeypatch.setattr(server, "MAX_FILE_BYTES", 1000)
    big = app_client.post("/file", params={"name": "big.pdf"}, content=b"%PDF-1.7\n" + b"0" * 5000)
    assert big.status_code == 413 and "MB" in big.json()["detail"]


def test_page_has_the_file_picker(app_client):
    page = app_client.get("/").text
    assert 'id="file"' in page and "fetch('/file?name='" in page
