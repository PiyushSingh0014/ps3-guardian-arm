"""Files that come in chats: the checks, the page's and the phone's way in (POST /file), and the
chat warning for app files. Every test file is made here and harmless (scripts/make_file_samples.py)."""
import hashlib
import io
import json
import os
import re
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
    assert f.verdict == "safe" and "encrypted" in " ".join(f.reasons)


def _stream(data, extra=b""):
    packed = zlib.compress(data)
    return b"<< /Filter /FlateDecode /Length %d" % len(packed) + extra + b" >>\nstream\n" + packed + b"\nendstream"


def test_picture_and_font_bytes_are_not_pdf_keys(checker):
    """Random bytes in pictures and fonts contain "/JS" or "/AA" about 0.06 times per MB each.
    Found on everyday PDFs (an e-book, a datasheet, a paper): only dictionaries count now."""
    assert checker.check(samples.pdf_scan(), "scan.pdf").verdict == "safe"
    font = _stream(b"/JavaScript /JS (x) /AA << /O 9 0 R >> /OpenAction /Launch /EmbeddedFiles" * 50, b" /Length1 4000")
    f = checker.check(samples.pdf(extra_objs=[font]), "book.pdf")
    assert f.verdict == "safe", f.reasons


def test_form_helpers_are_not_hidden_code_but_other_scripts_are(checker):
    f = checker.check(samples.pdf_form(), "form.pdf")
    assert f.verdict == "safe" and f.reasons[1] == "the PDF's only scripts are Acrobat's own helpers for numbers, dates and totals"
    typed = samples.pdf_form().replace(b'AFNumber_Keystroke\\(2, 0, 0, 0, "", true\\);', b"app.alert\\(1\\);")
    f = checker.check(typed, "form.pdf")                     # runs when you type in the field, not on opening
    assert f.verdict == "suspicious" and f.reasons[0] == "the PDF contains hidden code (JavaScript)"
    on_open = "the PDF runs hidden code (JavaScript) as soon as it is opened"
    page = samples.pdf(annots=b" /AA << /O 6 0 R >>", extra_objs=[b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>"])
    assert checker.check(page, "a.pdf").reasons[0] == on_open             # the page's "opened" action
    doc = samples.pdf(extra_catalog=b" /Names << /JavaScript << /Names [(init) 6 0 R] >> >>",
                      extra_objs=[b"<< /S /JavaScript /JS 7 0 R >>", _stream(b"this.exportDataObject({cName: 'a'});")])
    assert checker.check(doc, "a.pdf").reasons[0] == on_open              # the document's own scripts, in a stream
    chained = samples.pdf(extra_catalog=b" /OpenAction 6 0 R",
                          extra_objs=[b"<< /S /GoTo /D [3 0 R /Fit] /Next 7 0 R >>",
                                      b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>"])
    assert checker.check(chained, "a.pdf").reasons[0] == on_open          # a page jump, then code
    helpers = samples.pdf(extra_catalog=b" /OpenAction 6 0 R",
                          extra_objs=[b"<< /S /JavaScript /JS 7 0 R >>",
                                      _stream(b'AFSimple_Calculate("SUM", new Array ("a", "b"));')])
    assert checker.check(helpers, "a.pdf").verdict == "safe"
    sneaky = samples.pdf(extra_catalog=b" /OpenAction 6 0 R",
                         extra_objs=[b'<< /S /JavaScript /JS (AFNumber_Format\\(eval\\("x"\\)\\);) >>'])
    assert checker.check(sneaky, "a.pdf").verdict == "dangerous"         # a helper's name is not enough


def test_files_inside_a_pdf_are_checked_too(checker):
    def embed(data, name=b"card.jpg"):
        return samples.pdf(extra_catalog=b" /Names << /EmbeddedFiles << /Names [(a) 6 0 R] >> >>",
                           extra_objs=[b"<< /Type /Filespec /F (" + name + b") /UF (" + name + b") /EF << /F 7 0 R >> >>",
                                       _stream(data, b" /Type /EmbeddedFile")])
    f = checker.check(embed(samples.fake_apk()), "invitation.pdf")
    assert f.verdict == "dangerous" and f.reasons[0] == "inside the PDF: the file is an Android app (APK), not a document or a photo"
    f = checker.check(embed(samples.docx(macro=True), b"letter.docx"), "letter.pdf")
    assert f.verdict == "dangerous" and f.reasons[0].startswith("inside the PDF: the document contains macros")
    f = checker.check(embed(b"<office:document>a hybrid PDF keeps its document</office:document>", b"a.odt"), "a.pdf")
    assert f.verdict == "safe" and f.reasons[1] == "the PDF carries a text file inside it, which was checked too"
    f = checker.check(embed(bytes(range(256)) * 40, b"data.dat"), "report.pdf")
    assert f.verdict == "suspicious" and "of a type the Pi does not know" in f.reasons[0]


def test_hidden_objects_behind_other_filters(checker):
    inner = b"7 0 << /S /JavaScript /JS (app.alert\\(1\\)) >>"
    hexed = zlib.compress(inner).hex().encode() + b">"
    chained = (b"<< /Type /ObjStm /N 1 /First 4 /Filter [/ASCIIHexDecode /FlateDecode] /Length %d >>\nstream\n"
               % len(hexed) + hexed + b"\nendstream")
    plain = b"<< /Type /ObjStm /N 1 /First 4 /Length %d >>\nstream\n" % len(inner) + inner + b"\nendstream"
    for objstm in (chained, plain):
        f = checker.check(samples.pdf(extra_catalog=b" /OpenAction 7 0 R", extra_objs=[objstm]), "a.pdf")
        assert f.verdict == "dangerous", f.reasons


def test_broken_pdfs_do_not_stop_the_check(checker):
    good = samples.samples()["ps3-test-hidden-code.pdf"][0]
    for cut in range(10, len(good), 23):
        checker.check(good[:cut], "a.pdf")
    for data in (b"%PDF-1.7\n1 0 obj << /Length 999999 >>\nstream\nabc",
                 b"%PDF-1.7\n" + b">> stream\n" * 2000,
                 b"%PDF-1.7\n1 0 obj << /Type /ObjStm /N 99999999 /First 99999999 /Filter /FlateDecode >>\nstream\nxx\nendstream",
                 b"%PDF-1.7\n1 0 obj << /OpenAction 1 0 R /JS 1 0 R /AA 1 0 R /Next 1 0 R >> endobj"):
        assert checker.check(data, "a.pdf").source == "file"


def test_check_files_counts_copies_once(tmp_path, capsys):
    import check_files
    (tmp_path / "a.pdf").write_bytes(samples.pdf())
    (tmp_path / "a - Copy.pdf").write_bytes(samples.pdf())
    (tmp_path / "form.pdf").write_bytes(samples.pdf_form())
    (tmp_path / "x.pdf").write_bytes(samples.pdf_autorun_js())
    (tmp_path / "card.apk").write_bytes(samples.fake_apk())          # the same bytes, another ending: not a copy
    (tmp_path / "card.pdf").write_bytes(samples.fake_apk())
    assert check_files.main([str(tmp_path), "--quiet", "--details"]) == 0
    out = capsys.readouterr().out
    assert "5 different files" in out and "1 copy of another file left out" in out
    assert "card.apk:" in out and "card.pdf: the file says it is .pdf" in out
    assert "scripts: code, run on opening, first: app.alert(" in out and "form.pdf" not in out


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


def test_email_and_phone_links_are_no_websites(checker):
    """mailto:name@college.edu once looked like a link hiding its website after an @ sign."""
    mail = samples.pdf_with_link(b"mailto:hod.ece@college.example.edu")
    assert checker.check(mail, "paper.pdf").verdict == "safe"
    assert checker.check(samples.docx(hyperlink=b"tel:+911234567890"), "letter.docx").verdict == "safe"
    ftp = samples.pdf_with_link(b"ftp://sbi-kyc-update-ps3lab.xyz/form")
    assert checker.check(ftp, "kyc.pdf").verdict == "dangerous"


def _with_scripts(doc_script=None, click_scripts=()):
    """A PDF with a document script (its /JavaScript name tree) and links that run scripts."""
    def lit(js):
        return b"(" + js.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"\n", b"\\012") + b")"
    objs, refs, catalog = [], [], b""
    if doc_script is not None:
        objs.append(b"<< /JavaScript << /Names [ (JSInit) << /Type /Action /S /JavaScript /JS " + lit(doc_script)
                    + b" >> ] >> >>")
        catalog = b" /Names 6 0 R"
    for js in click_scripts:
        refs.append(b"%d 0 R" % (6 + len(objs)))
        objs.append(b"<< /Type /Annot /Subtype /Link /Rect [72 600 300 630] /A << /S /JavaScript /JS " + lit(js) + b" >> >>")
    return samples.pdf(extra_catalog=catalog, annots=b" /Annots [" + b" ".join(refs) + b"]" if refs else b"", extra_objs=objs)


def test_page_jumps_and_kicad_menus_are_no_hidden_code(checker, monkeypatch):
    import detectors.files.checker as files
    f = checker.check(_with_scripts(click_scripts=[b"this.zoom=100;this.pageNum=162", b"this.pageNum=3;"]), "book.pdf")
    assert f.verdict == "safe" and f.reasons[1] == "the PDF's only scripts are page jumps"         # an e-book's contents
    menu_function = b"function ShM(aEntries) {\n    app.popUpMenuEx.apply(app, aEntries);\n}\n"
    menus = [b'ShM([\n["Reference designator = R1"],\n["Value = 10k \\"0805\\""],\n'
             b'["https://www.ti.com/lit/ds/lm358.pdf", "https://www.ti.com/lit/ds/lm358.pdf"],\n]);']
    kicad = _with_scripts(menu_function, menus)
    f = checker.check(kicad, "schematic.pdf")              # not KiCad's own text: code, but nothing runs on opening
    assert f.verdict == "suspicious" and f.reasons[0] == "the PDF contains hidden code (JavaScript)"
    fingerprint = hashlib.sha256(re.sub(rb"\s+", b"", menu_function)).hexdigest()
    monkeypatch.setattr(files, "_KICAD_MENU_FUNCTION", files._KICAD_MENU_FUNCTION | {fingerprint})
    f = checker.check(kicad, "schematic.pdf")
    assert f.verdict == "safe" and f.reasons[1] == "the PDF's only scripts are KiCad's menus for part details and links"
    phishing = _with_scripts(menu_function, [menus[0].replace(b"https://www.ti.com/lit/ds/lm358.pdf",
                                                              b"http://sbi-kyc-update-ps3lab.xyz/login")])
    assert checker.check(phishing, "schematic.pdf").verdict == "dangerous"      # a menu's web address is a link
    assert checker.check(_with_scripts(None, menus), "a.pdf").verdict == "suspicious"   # menus without KiCad's function
    runs = _with_scripts(menu_function + b"app.alert(1);", menus)
    assert checker.check(runs, "a.pdf").reasons[0] == "the PDF runs hidden code (JavaScript) as soon as it is opened"
    assert len(files._KICAD_MENU_FUNCTION) == 3 and all(len(h) == 64 for h in files._KICAD_MENU_FUNCTION)
