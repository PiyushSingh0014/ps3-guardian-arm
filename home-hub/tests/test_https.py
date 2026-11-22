"""Update 39: HTTPS for the phones and the page (a self-signed certificate the app pins), plain HTTP
only for lab devices' readings and the Pi itself, and the phone's own study switch."""
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app import serve
from app.server import TokenGuard, create_app
from app.sms_log import SmsLog, StudyPhones
from detectors.sms import detector as det
from tests.auth import AUTH

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READING = {"device": "esp32-lab", "mode": "normal", "readings": {"temp_c": 27.4}}
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")


@pytest.fixture(scope="module")
def detector():
    return det.SmsDetector(url_detector=None)


@pytest.fixture
def make(detector, tmp_path):
    def build(**kw):
        return create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                          net_state=str(tmp_path / "devices.json"), net_watch=str(tmp_path / "watch.json"),
                          sms_log=kw.pop("sms_log", None) or SmsLog(tmp_path / "sms.jsonl"),
                          net_explain_every_s=None, token_guard=TokenGuard(), **kw)
    return build


@pytest.fixture
def cert(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("needs the openssl command")
    c, k = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", "2", "-subj", "/CN=ps3-guardian", "-addext", "subjectAltName=IP:10.42.0.1",
                    "-keyout", str(k), "-out", str(c)], check=True, capture_output=True)
    return c, k


# --- plain HTTP with TLS on ----------------------------------------------------------------------

def test_plain_http_from_another_machine_only_posts_readings(make, monkeypatch):
    monkeypatch.setenv("GUARDIAN_DEVICE_TOKEN", "old1234a")
    app = make(tls=True)
    plain = TestClient(app, base_url="http://10.42.0.1:8000", client=("10.42.0.50", 1), headers=AUTH)
    r = plain.get("/health")                                   # even with the right token
    assert r.status_code == 403 and r.json()["detail"] == (
        "use https://10.42.0.1:8443/: plain HTTP only takes lab devices' readings")
    assert plain.post("/sms", json={"message": "ok see you at 6", "test": True}).status_code == 403
    page = plain.get("/", follow_redirects=False)
    assert page.status_code == 307 and page.headers["location"] == "https://10.42.0.1:8443/"
    assert plain.post("/iot", json=READING, headers={"X-Guardian-Token": "old1234a"}).status_code == 200
    assert plain.post("/iot", json=READING, headers={"X-Guardian-Token": "wrong"}).status_code == 401

    tls = TestClient(app, base_url="https://10.42.0.1:8443", client=("10.42.0.50", 1), headers=AUTH)
    assert tls.get("/").status_code == 200
    h = tls.get("/health").json()
    assert h["tls"]["on"] is True
    assert TestClient(app, base_url="https://10.42.0.1:8443", client=("10.42.0.50", 1)).get("/health").status_code == 401

    local = TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 5))
    assert local.get("/health").status_code == 200             # the Pi's own scripts: as before


def test_without_tls_plain_http_works_as_before(make):
    c = TestClient(make(tls=False), base_url="http://10.42.0.1:8000", client=("10.42.0.50", 1), headers=AUTH)
    h = c.get("/health").json()
    assert h["tls"] == {"on": False, "fingerprint": None}


# --- the phone's study switch --------------------------------------------------------------------

def test_the_phones_switch_can_only_keep_less(tmp_path, make):
    study = tmp_path / "study.json"
    study.write_text(json.dumps({"phones": ["A"]}))
    log = SmsLog(tmp_path / "sms.jsonl", study=StudyPhones(study))
    c = TestClient(make(sms_log=log), headers=AUTH)
    scam = "Your SBI account is blocked today, update KYC now at sbi-kyc-help.xyz"
    for device, switch in [("A", None), ("A", True), ("A", False), ("B", True)]:
        body = {"message": scam, "sender": "9812345678", "device": device}
        if switch is not None:
            body["study"] = switch
        assert c.post("/sms", json=body).status_code == 200
    rows = [json.loads(line) for line in (tmp_path / "sms.jsonl").read_text().splitlines()]
    assert [(r["device"], r["study"], r["text"] is not None) for r in rows] == [
        ("A", True, True), ("A", True, True), ("A", False, False), ("B", False, False)]
    assert c.post("/sms", json={"message": scam, "study": "yes please"}).status_code == 422


# --- app/serve.py --------------------------------------------------------------------------------

def test_the_fingerprint_is_the_certificates_sha256(cert):
    out = subprocess.run(["openssl", "x509", "-in", str(cert[0]), "-noout", "-fingerprint", "-sha256"],
                         check=True, capture_output=True, text=True).stdout
    want = out.strip().split("=", 1)[1].replace(":", "")
    got = serve.fingerprint(cert[0])
    assert got.replace(" ", "") == want and len(got.split()) == 16 and all(len(g) == 4 for g in got.split())


def test_two_servers_one_app(cert):
    tls, plain = serve.configs("app", str(cert[0]), str(cert[1]))
    assert (tls.port, tls.ssl_certfile, plain.port, plain.ssl_certfile, plain.lifespan) == (
        8443, str(cert[0]), 8000, None, "off")
    for s in serve.servers_for([tls, plain]):
        assert s.install_signal_handlers() is None
        with s.capture_signals():
            pass


def test_ctrl_c_stops_both_servers():
    class Fake:
        def __init__(self):
            self.should_exit, self.started = False, False

        async def serve(self):
            import asyncio
            self.started = True
            while not self.should_exit:
                await asyncio.sleep(0.01)

    async def run(servers):
        import asyncio
        asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGINT)
        await serve.serve_all(servers)

    import asyncio
    servers = [Fake(), Fake()]
    asyncio.run(run(servers))
    assert all(s.should_exit for s in servers)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_the_pi_serves_https_and_plain_http_in_one_process(cert, tmp_path):
    https_port, http_port = _free_port(), _free_port()
    env = dict(os.environ, NET_ALERTS=str(tmp_path / "alerts.jsonl"), NET_EXPLAIN="0", FILE_LOG=str(tmp_path / "f.jsonl"),
               GUARDIAN_SMS_LOG=str(tmp_path / "sms.jsonl"))
    p = subprocess.Popen([sys.executable, "-m", "app.serve", "--cert", str(cert[0]), "--key", str(cert[1]),
                          "--host", "127.0.0.1", "--https-port", str(https_port), "--http-port", str(http_port)],
                         cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(150):
            try:
                if httpx.get(f"http://127.0.0.1:{http_port}/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        h = httpx.get(f"https://127.0.0.1:{https_port}/health", headers=AUTH, verify=False, timeout=5).json()
        assert h["tls"] == {"on": True, "fingerprint": serve.fingerprint(cert[0])}
        served = ssl.get_server_certificate(("127.0.0.1", https_port))
        (tmp_path / "served.pem").write_text(served)
        assert serve.fingerprint(tmp_path / "served.pem") == h["tls"]["fingerprint"]   # what a phone pins
        assert httpx.get(f"http://127.0.0.1:{http_port}/health", timeout=5).json()["tls"]["on"] is True
    finally:
        p.send_signal(signal.SIGTERM)
        out = p.communicate(timeout=20)[0]
    assert p.returncode == 0, out[-2000:]


@needs_openssl
def test_the_start_script_makes_the_certificate_once(tmp_path):
    with open(os.path.join(ROOT, "scripts", "run_pi.sh"), encoding="utf-8") as f:
        text = f.read()
    block = tmp_path / "tls.sh"
    block.write_text('IP=10.42.0.1\n' + text[text.index("# HTTPS (update 39)"):text.index("ADVISOR_BACKEND=service exec")])
    home = tmp_path / "home"
    home.mkdir()
    env = {"HOME": str(home), "PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]}
    run = lambda: subprocess.run(["bash", "-c", f"set -euo pipefail; source {block}"], env=env, cwd=ROOT,  # noqa: E731
                                 capture_output=True, text=True, check=True).stdout
    first = run()
    cert_file, key_file = home / ".ps3_tls_cert.pem", home / ".ps3_tls_key.pem"
    fp = serve.fingerprint(cert_file)
    assert "Made a new HTTPS certificate" in first and fp in first
    assert (home / ".ps3_tls_fingerprint").read_text().strip() == fp
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    second = run()
    assert "Made a new" not in second and serve.fingerprint(cert_file) == fp      # kept: the phones stay paired
