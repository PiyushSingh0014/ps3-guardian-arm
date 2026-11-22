"""Update 44: a paired phone copies the Pi's Llama files (GET /llama, /llama/{name}) for Phone Guard.
The files here are small stand-ins; the real model never enters the repo."""
import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app import llama_files
from app.server import TokenGuard, create_app
from detectors.sms import detector as det
from tests.auth import client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def detector():
    return det.SmsDetector(url_detector=None)


@pytest.fixture
def files(tmp_path, monkeypatch):
    pte, tok = tmp_path / "model.pte", tmp_path / "tok.model"
    pte.write_bytes(os.urandom(300_000))
    tok.write_bytes(b"stand-in tokenizer\n" * 50)
    monkeypatch.setenv("LLAMA_PTE", str(pte))
    monkeypatch.setenv("LLAMA_TOKENIZER", str(tok))
    return pte, tok


@pytest.fixture
def app(detector, tmp_path):
    return create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                      net_state=str(tmp_path / "devices.json"), net_watch=str(tmp_path / "watch.json"),
                      net_explain_every_s=None, token_guard=TokenGuard())


def test_the_phone_gets_both_files_with_their_sizes_and_hashes(app, files):
    pte, tok = files
    c = client(app)
    listed = c.get("/llama").json()
    assert [f["name"] for f in listed["files"]] == ["llama3_2.pte", "tokenizer.model"]
    for f, path in zip(listed["files"], files):
        assert f["bytes"] == path.stat().st_size
        assert f["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert listed["bytes"] == pte.stat().st_size + tok.stat().st_size
    got = c.get("/llama/llama3_2.pte")
    assert got.status_code == 200 and got.content == pte.read_bytes()
    assert got.headers["content-type"] == "application/octet-stream"
    assert c.get("/llama/tokenizer.model").content == tok.read_bytes()


def test_only_the_two_files_and_only_with_the_token(app, files):
    c = client(app)
    for name in ("sms_baseline.joblib", "..%2Fserver.py", "llama3_2.pte.part", "LLAMA_PTE"):
        assert c.get(f"/llama/{name}").status_code == 404, name
    assert c.get("/llama/../app/server.py").status_code == 404
    nobody = TestClient(app)
    assert nobody.get("/llama").status_code == 401
    assert nobody.get("/llama/llama3_2.pte").status_code == 401


def test_no_model_on_the_pi_says_so(app, files, monkeypatch):
    c = client(app)
    monkeypatch.delenv("LLAMA_TOKENIZER")
    r = c.get("/llama")
    assert r.status_code == 404 and "LLAMA_TOKENIZER" in r.json()["detail"]
    assert c.get("/llama/tokenizer.model").status_code == 404
    assert c.get("/llama/llama3_2.pte").status_code == 200
    monkeypatch.setenv("LLAMA_PTE", str(files[0]) + ".gone")
    assert c.get("/llama/llama3_2.pte").status_code == 404


def test_a_hash_is_worked_out_again_only_when_the_file_changes(files):
    pte, _ = files
    hashes, reads = llama_files.Hashes(), []
    real_open = open

    def counting_open(path, *a, **kw):
        reads.append(path)
        return real_open(path, *a, **kw)

    first = hashes.of(str(pte))
    llama_files.open = counting_open                 # the module's own name for open
    try:
        assert hashes.of(str(pte)) == first and reads == []
        pte.write_bytes(b"a new model")
        os.utime(pte, ns=(1, 1))
        assert hashes.of(str(pte)) == hashlib.sha256(b"a new model").hexdigest() and len(reads) == 1
    finally:
        del llama_files.open


def test_the_start_script_gives_the_app_the_model_paths():
    with open(os.path.join(ROOT, "scripts", "run_pi.sh"), encoding="utf-8") as f:
        script = f.read()
    assert 'export LLAMA_PTE="${LLAMA_PTE:-$ET_DIR/llama3_2.pte}"' in script
    assert 'export LLAMA_TOKENIZER="${LLAMA_TOKENIZER:-$ET_DIR/tokenizer.model}"' in script
    assert '--pte "$LLAMA_PTE" --tokenizer "$LLAMA_TOKENIZER"' in script
    assert script.index("export LLAMA_PTE") < script.index("exec python -m app.serve")
