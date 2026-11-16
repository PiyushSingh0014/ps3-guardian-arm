"""Update 40: DNS blocking on the Pi's hotspot: the block list, the app's endpoints and page, the
monitor's automatic blocks, the root helper, the DNS check and the set-up script."""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app import dns_block
from app.dns_block import BlockList, query, selftest, valid_name
from app.server import PAGE, TokenGuard, create_app
from app.sms_log import SmsLog
from detectors.net.dns import NameChecks
from detectors.net.flows import FlowRec
from detectors.net.scamlinks import ScamLinks
from detectors.sms import detector as det
from tests.auth import AUTH

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAM = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc-ps3lab.xyz/verify"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


# --- names and the list -------------------------------------------------------------------------

@pytest.mark.parametrize("raw,want", [
    ("sbi-kyc-update.xyz", "sbi-kyc-update.xyz"), ("HTTPS://Evil.Example.COM/path?x=1", "evil.example.com"),
    ("evil.xyz.", "evil.xyz"), ("bücher.de", "xn--bcher-kva.de"), ("localhost", None), ("10.0.0.1", None),
    ("*.evil.xyz", None), ("-bad.xyz", None), ("a" * 64 + ".xyz", None), ("evil xyz.com", None), ("", None),
])
def test_only_website_names_can_be_blocked(raw, want):
    assert valid_name(raw) == want


def test_blocks_end_unblocks_stick_and_hand_blocks_win(tmp_path):
    clock = Clock()
    b = BlockList(tmp_path / "list.json", clock=clock)
    assert b.block(["kyc-check.xyz"], "Fake bank KYC, in an SMS", "message") == (["kyc-check.xyz"], {})
    assert b.is_blocked("sbi.kyc-check.xyz") and b.is_blocked("kyc-check.xyz") and not b.is_blocked("check.xyz")
    assert b.block(["kyc-check.xyz"], "again", "network") == ([], {})              # already blocked as long
    clock.t += 8 * 86_400                                                         # 7 days later: over
    assert not b.is_blocked("kyc-check.xyz")
    b.block(["kyc-check.xyz"], "back", "message")
    assert b.unblock("kyc-check.xyz") and not b.is_blocked("kyc-check.xyz")
    added, refused = b.block(["kyc-check.xyz"], "a third message", "message")
    assert added == [] and "unblocked by hand" in refused["kyc-check.xyz"]          # undo sticks
    assert b.block(["kyc-check.xyz"], "by hand", "page", days=None)[0] == ["kyc-check.xyz"]
    clock.t += 365 * 86_400
    assert b.is_blocked("kyc-check.xyz")["source"] == "page"                      # until unblocked
    assert not b.unblock("never-blocked.xyz")
    with pytest.raises(ValueError):
        b.block(["x.xyz"], "?", "somewhere")


def test_protected_names_and_the_size_limit(tmp_path, monkeypatch):
    b = BlockList(tmp_path / "list.json", protected=lambda n: "an official website" if n == "onlinesbi.sbi" else None)
    added, refused = b.block(["onlinesbi.sbi", "fake-sbi.xyz", "not a name"], "test", "page", days=None)
    assert added == ["fake-sbi.xyz"]
    assert refused == {"onlinesbi.sbi": "onlinesbi.sbi is an official website: blocking it would cut off everyone",
                       "not a name": "not a website name"}
    monkeypatch.setattr(dns_block, "MAX_NAMES", 3)
    clock = Clock()
    b = BlockList(tmp_path / "small.json", clock=clock)
    for i in range(5):
        clock.t += 1
        b.block([f"scam{i}.xyz"], "m", "message")
    assert sorted(n for n, _ in b.entries()) == ["scam2.xyz", "scam3.xyz", "scam4.xyz"]   # the oldest went


def test_the_url_detector_protects_official_and_shared_sites():
    from detectors.url.detector import UrlDetector
    url = UrlDetector(model_path=None, intel_path=None, top_sites=None)
    assert "official" in dns_block.protected_reason(url, "onlinesbi.sbi")
    assert dns_block.protected_reason(url, "bit.ly")
    assert dns_block.protected_reason(url, "sbi-kyc-ps3lab.xyz") is None


# --- the app --------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def detector():
    from detectors.url.detector import UrlDetector
    return det.SmsDetector(url_detector=UrlDetector(model_path=None, intel_path=None, top_sites=None))


def make(tmp_path, detector, **kw):
    return create_app(detector=detector, advisor=Advisor(), net_alerts=str(tmp_path / "alerts.jsonl"),
                      net_state=str(tmp_path / "devices.json"), net_watch=str(tmp_path / "watch.json"),
                      sms_log=SmsLog(tmp_path / "sms.jsonl"), net_explain_every_s=None, token_guard=TokenGuard(),
                      **kw)


def test_a_dangerous_message_blocks_its_website(tmp_path, detector):
    blocks = BlockList(tmp_path / "list.json")
    c = TestClient(make(tmp_path, detector, dns_block=blocks), headers=AUTH)
    r = c.post("/check", json={"message": SCAM, "sender": "9812345678"}).json()
    assert r["finding"]["verdict"] == "dangerous"
    e = blocks.is_blocked("sbi-kyc-ps3lab.xyz")
    assert e["source"] == "message" and e["why"].endswith("in a message checked on the page") and e["until_ms"]
    TestClient(make(tmp_path, detector, dns_block=blocks), headers=AUTH).post(
        "/sms", json={"message": SCAM.replace("ps3lab", "sms"), "sender": "9812345678"})
    assert "an SMS from a mobile number" in blocks.is_blocked("sbi-kyc-sms.xyz")["why"]
    assert c.post("/check", json={"message": "ok see you at 6"}).status_code == 200
    assert sorted(n for n, _ in blocks.entries()) == ["sbi-kyc-ps3lab.xyz", "sbi-kyc-sms.xyz"]   # a safe one: none


def test_the_page_lists_blocks_and_undoes_them(tmp_path, detector):
    blocks = BlockList(tmp_path / "list.json")
    c = TestClient(make(tmp_path, detector, dns_block=blocks), headers=AUTH)
    d = c.get("/blocked").json()
    assert d["blocked"] == [] and d["set_up"] is False and "setup_dns_block.sh" in d["note"]
    assert c.post("/blocked", json={"name": "lottery-win-now.xyz"}).json()["blocked"][0]["name"] == "lottery-win-now.xyz"
    r = c.post("/blocked", json={"name": "onlinesbi.sbi"})
    assert r.status_code == 422 and "official website" in r.json()["detail"]
    assert c.post("/blocked/undo", json={"name": "lottery-win-now.xyz"}).json()["blocked"] == []
    assert c.post("/blocked/undo", json={"name": "lottery-win-now.xyz"}).status_code == 404
    assert TestClient(make(tmp_path, detector, dns_block=blocks)).get("/blocked").status_code == 401   # token
    assert c.get("/health").json()["dns_block"]["names"] == 0


def test_alerts_offer_to_block_their_website(tmp_path, detector):
    blocks = BlockList(tmp_path / "list.json")
    alert = {"time": "2026-11-15 10:00:00", "finding": {
        "source": "net", "verdict": "dangerous", "score": 0.95, "category": "phishing_lookup",
        "reasons": ["10.42.0.50 looked up a website that is on the public list of phishing sites"],
        "entities": {"device": "10.42.0.50", "peer": "sbi-kyc-update[.]xyz", "time_ms": 1_800_000_000_000}}}
    scan = {"time": "2026-11-15 10:01:00", "finding": {
        "source": "net", "verdict": "dangerous", "score": 0.95, "category": "network_scan", "reasons": ["x"],
        "entities": {"device": "10.42.0.50", "peer": "port 23", "time_ms": 1_800_000_060_000}}}
    (tmp_path / "alerts.jsonl").write_text(json.dumps(alert) + "\n" + json.dumps(scan) + "\n")
    c = TestClient(make(tmp_path, detector, dns_block=blocks), headers=AUTH)
    newest, oldest = c.get("/alerts").json()["alerts"]
    assert "block" not in newest and oldest["block"] == {"name": "sbi-kyc-update.xyz", "blocked": False}
    blocks.block(["sbi-kyc-update.xyz"], "test", "page", days=None)
    assert c.get("/alerts").json()["alerts"][1]["block"]["blocked"] is True


def test_the_page_has_the_blocked_websites_card():
    assert 'id="blocked"' in PAGE and "changeBlock('/blocked/undo',e.name)" in PAGE and "a.block.name" in PAGE


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node to parse the page's script")
def test_the_pages_script_parses(tmp_path):
    script = tmp_path / "page.js"
    script.write_text(PAGE[PAGE.index("<script>") + 8:PAGE.rindex("</script>")])
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


# --- the network monitor -----------------------------------------------------------------------

def dns_flow(name, src="10.42.0.50", t=1_800_000_000_000):
    return FlowRec(start_ms=t, end_ms=t + 20, src=src, dst="10.42.0.1", sport=40000, dport=53, proto=17,
                   pkts_out=1, pkts_in=1, bytes_out=40, bytes_in=80, app="DNS", server_name=name)


def test_the_monitor_blocks_a_phishing_lookup_and_says_so(tmp_path):
    from detectors.url.detector import UrlDetector
    url = UrlDetector(model_path=None, intel_path=None, top_sites=None)
    blocks = BlockList(tmp_path / "list.json")
    names = NameChecks(url_detector=url, blocks=blocks)
    first = names.update(dns_flow("sbi.co.in.login-verify-kyc.xyz"))
    assert [h.category for h in first] == ["phishing_lookup"]
    assert first[0].reasons[-1] == "the Pi has now blocked this website on its Wi-Fi" and first[0].facts["blocked"]
    assert blocks.is_blocked("login-verify-kyc.xyz")["source"] == "network"
    names.cache.clear()
    again = names.update(dns_flow("sbi.co.in.login-verify-kyc.xyz", src="10.42.0.51"))
    assert again[0].reasons[-1] == "the Pi's DNS refused it, so it did not open"
    plain = NameChecks(url_detector=url).update(dns_flow("sbi.co.in.login-verify-kyc.xyz"))
    assert len(plain[0].reasons) == 1 and plain[0].facts == {"name": "sbi.co.in.login-verify-kyc.xyz", "brand": "SBI",
                                                             "blocked": False}


def test_a_scam_link_opened_is_blocked_unless_unblocked_by_hand(tmp_path):
    clock = Clock()
    watch = ScamLinks(str(tmp_path / "watch.json"), clock=clock)
    watch.add(["win-prize-now.in"], "suspicious", "lottery_reward_scam", "an SMS from a mobile number")
    blocks = BlockList(tmp_path / "list.json")
    names = NameChecks(watch=watch, blocks=blocks)
    hit = names.update(dns_flow("win-prize-now.in", t=int(clock.t * 1000) + 5_000))[0]
    assert hit.category == "scam_link_opened" and hit.reasons[1] == "the Pi has now blocked this website on its Wi-Fi"
    blocks.unblock("win-prize-now.in")
    names.cache.clear()
    hit = names.update(dns_flow("win-prize-now.in", src="10.42.0.52", t=int(clock.t * 1000) + 9_000))[0]
    assert len(hit.reasons) == 1 and not hit.facts["blocked"]                     # the owner's undo stands


# --- the root helper -------------------------------------------------------------------------------

def run_helper(tmp_path, list_path):
    conf = tmp_path / "helper.json"
    servers = tmp_path / "out" / "blocked.servers"
    import pwd
    conf.write_text(json.dumps({"list": str(list_path), "owner": pwd.getpwuid(os.getuid()).pw_name,
                                "servers": str(servers)}))
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "dns_block_helper.py")],
                       env={"PS3_DNSBLOCK_CONF": str(conf), "PATH": os.environ["PATH"]}, capture_output=True, text=True)
    return r, servers


def test_the_helper_writes_only_valid_unexpired_names(tmp_path):
    clock = Clock()
    clock.t = __import__("time").time()
    b = BlockList(tmp_path / "list.json", clock=clock)
    b.block(["good-block.xyz"], "m", "message")
    b.block(["forever.xyz"], "p", "page", days=None)
    data = json.loads((tmp_path / "list.json").read_text())
    data["blocked"]["expired.xyz"] = {"since_ms": 1, "until_ms": 2, "source": "message"}
    data["blocked"]["bad name; rm -rf /"] = {"since_ms": 1, "until_ms": None, "source": "page"}
    data["blocked"]["evil.xyz/\nserver=/google.com"] = {"since_ms": 1, "until_ms": None, "source": "page"}
    (tmp_path / "list.json").write_text(json.dumps(data))
    r, servers = run_helper(tmp_path, tmp_path / "list.json")
    assert r.returncode == 0, r.stderr
    lines = [x for x in servers.read_text().splitlines() if not x.startswith("#")]
    assert lines == ["server=/forever.xyz/", "server=/good-block.xyz/"]
    assert oct(servers.stat().st_mode & 0o777) == "0o644"
    assert "2 websites blocked" in r.stdout and "the hotspot is off" in r.stdout


def test_the_helper_refuses_a_linked_list_and_keeps_the_old_one(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"blocked": {"leak.xyz": {"until_ms": None}}}))
    link = tmp_path / "list.json"
    link.symlink_to(secret)
    r, servers = run_helper(tmp_path, link)
    assert r.returncode == 1 and "cannot use the list" in r.stderr and not servers.exists()
    r, servers = run_helper(tmp_path, tmp_path / "missing.json")                  # no list yet: nothing blocked
    assert r.returncode == 0 and [x for x in servers.read_text().splitlines() if not x.startswith("#")] == []


# --- what the Pi's DNS answers ------------------------------------------------------------------------

class FakeDns(threading.Thread):
    """A tiny DNS server: NXDOMAIN for names on the block list, else one A record (or SERVFAIL)."""

    def __init__(self, blocks=None, online=True):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.blocks, self.online, self.stop = blocks, online, False

    def run(self):
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            i, labels = 12, []
            while data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode())
                i += 1 + data[i]
            question = data[12:i + 5]
            name = ".".join(labels)
            if self.blocks is not None and self.blocks.is_blocked(name):
                rcode, answers = 3, b""
            elif not self.online:
                rcode, answers = 2, b""
            else:
                rcode, answers = 0, b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.215.14")
            header = data[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, 1 if answers else 0, 0, 0)
            self.sock.sendto(header + question + answers, addr)

    def close(self):
        self.stop = True
        self.sock.close()


def test_query_reads_answers_and_nxdomain(tmp_path):
    blocks = BlockList(tmp_path / "list.json")
    blocks.block(["blocked.xyz"], "t", "page", days=None)
    fake = FakeDns(blocks)
    fake.start()
    try:
        assert query("example.org", "127.0.0.1", fake.port) == ("NOERROR", ["93.184.215.14"])
        assert query("www.blocked.xyz", "127.0.0.1", fake.port) == ("NXDOMAIN", [])
    finally:
        fake.close()


def test_the_selftest_blocks_for_a_moment_and_undoes_it(tmp_path, monkeypatch):
    blocks = BlockList(tmp_path / "list.json")
    fake = FakeDns(blocks, online=False)                         # no internet: SERVFAIL, still testable
    fake.start()
    monkeypatch.setattr(dns_block, "query", lambda name, server, port=53, timeout=2.0:
                        query(name, "127.0.0.1", fake.port, timeout))
    said = []
    try:
        assert selftest(blocks, server="127.0.0.1", say=said.append) == 0
    finally:
        fake.close()
    assert "no internet now" in said[0] and said[-1].endswith("DNS blocking works.")
    assert blocks.entries() == [] and json.loads((tmp_path / "list.json").read_text())["allowed"] == {}


def test_the_selftest_fails_when_nothing_applies_the_list(tmp_path, monkeypatch):
    fake = FakeDns(blocks=None)                                  # a DNS server that never blocks
    fake.start()
    monkeypatch.setattr(dns_block, "query", lambda name, server, port=53, timeout=2.0:
                        query(name, "127.0.0.1", fake.port, timeout))
    monkeypatch.setattr(dns_block, "wait_for", lambda name, want, server, seconds=20.0:
                        query(name, "127.0.0.1", fake.port)[0])
    said = []
    try:
        assert selftest(BlockList(tmp_path / "list.json"), server="127.0.0.1", say=said.append) == 1
    finally:
        fake.close()
    assert said[-1].startswith("FAIL: example.org was blocked but the Pi's DNS still answers NOERROR")


def test_the_selftest_leaves_a_block_made_by_hand_alone(tmp_path, monkeypatch):
    blocks = BlockList(tmp_path / "list.json")
    blocks.block(["example.org"], "blocked by hand on the page", "page", days=None)    # the guide's "Try it"
    fake = FakeDns(blocks)
    fake.start()
    monkeypatch.setattr(dns_block, "query", lambda name, server, port=53, timeout=2.0:
                        query(name, "127.0.0.1", fake.port, timeout))
    said = []
    try:
        assert selftest(blocks, server="127.0.0.1", say=said.append) == 0
    finally:
        fake.close()
    assert "already on the block list" in said[-1] and "left in place" in said[-1]
    entry = blocks.is_blocked("example.org")
    assert entry["source"] == "page" and entry["until_ms"] is None


def test_blocking_from_the_command_line_has_the_pages_protection(tmp_path, monkeypatch, capsys):
    from detectors.url import detector as url_detector
    real = url_detector.UrlDetector
    monkeypatch.setattr(url_detector, "UrlDetector", lambda: real(model_path=None, intel_path=None, top_sites=None))
    path = str(tmp_path / "list.json")
    assert dns_block.main(["block", "onlinesbi.sbi", "--list", path]) == 1
    assert "official website" in capsys.readouterr().out
    assert dns_block.main(["block", "sbi-kyc-ps3lab.xyz", "--list", path]) == 0
    assert BlockList(path).is_blocked("sbi-kyc-ps3lab.xyz")["source"] == "page"

    def no_sklearn():
        raise ImportError("No module named 'sklearn'")
    monkeypatch.setattr(url_detector, "UrlDetector", no_sklearn)
    assert dns_block.main(["block", "other-scam.xyz", "--list", path]) == 1
    assert "Block it on the Pi's page" in capsys.readouterr().out
    assert not BlockList(path).is_blocked("other-scam.xyz")


# --- the set-up script -------------------------------------------------------------------------------

def test_the_setup_script_checks_before_it_changes_anything(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "nmcli").write_text("#!/bin/sh\nexit 0\n")                       # no active connection
    (fake / "sudo").write_text("#!/bin/sh\necho SUDO-CALLED >&2\nexit 1\n")
    for f in fake.iterdir():
        f.chmod(0o755)
    env = {"PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path), "PS3_SHARED_D": str(tmp_path / "shared")}
    script = os.path.join(ROOT, "scripts", "setup_dns_block.sh")
    r = subprocess.run(["bash", script], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert r.returncode == 1 and "the hotspot \"ps3-lab\" is not on" in r.stdout and "SUDO-CALLED" not in r.stderr
    r = subprocess.run(["bash", script, "--status"], env=env, capture_output=True, text=True)
    assert "DNS blocking: not set up" in r.stdout and "Hotspot: off" in r.stdout
    assert subprocess.run(["bash", "-n", script]).returncode == 0
