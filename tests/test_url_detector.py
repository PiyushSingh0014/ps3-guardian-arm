"""Link checker (detectors/url): finding links, the rules, the lists, the model file, and
how links change an SMS verdict. Rules-only detectors keep these tests independent of the
downloaded lists and of the trained model."""
import numpy as np
import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.server import create_app
from detectors.sms.detector import SmsDetector
from detectors.url import intel
from detectors.url.detector import UrlDetector
from detectors.url.links import find_links, parse_link


@pytest.fixture(scope="module")
def rules():
    return UrlDetector(model_path=None, intel_path=None, top_sites=None)


def hosts(text):
    return [link.host for link in find_links(text)]


# --- finding links ----------------------------------------------------------
def test_finds_explicit_and_bare_links():
    assert hosts("Pay now at https://www.sbi-kyc.top/x or po9.in/vphb and www.hdfcbank.com") == \
        ["sbi-kyc.top", "po9.in", "hdfcbank.com"]
    assert hosts("visit Westside.com today") == ["westside.com"]


def test_abbreviations_emails_and_reserved_names_are_not_links():
    text = ("B.Tech admission open, Ref.ID 7731, Civil.No 12, apply for placement.To know more "
            "mail care@hdfcbank.com or see http://qzhnrfr.example/x")
    assert hosts(text) == []


def test_link_parts():
    link = parse_link("https://www.sbi.co.in@evil-site.xyz/login")
    assert link.host == "evil-site.xyz" and link.has_at
    assert parse_link("https://pnb.bank.in/x").registered == "pnb.bank.in"
    assert parse_link("https://sbi-kyc.weebly.com").registered == "sbi-kyc.weebly.com"   # someone's own site
    assert parse_link("http://192.168.1.10/login").is_ip
    assert parse_link("https://xn--sbi-xyz.com").host.startswith("xn--")
    assert parse_link("https://ड.भारत").host.startswith("xn--")                       # non-Latin -> punycode


# --- rules ----------------------------------------------------------------
@pytest.mark.parametrize("url,brand", [
    ("http://sbi-kyc-update.xyz/login", "SBI"),
    ("sbi.co.in.verify-kyc.com/a", "SBI"),
    ("https://hdfcbank.weebly.com", "HDFC Bank"),
    ("https://sites.google.com/view/sbi-kyc-update", "SBI"),
    ("https://indiapost-track.top/fee", "India Post"),
])
def test_brand_imitation_is_dangerous(rules, url, brand):
    f = rules.check(url)
    assert f.verdict == "dangerous" and f.category == "phishing_link"
    assert f.entities["claims_to_be"] == brand


@pytest.mark.parametrize("url", ["https://www.onlinesbi.sbi/", "https://sbi.co.in", "https://pnb.bank.in/x",
                                 "https://uidai.gov.in", "https://i.airtel.in/offer", "https://amzn.in/d/abc",
                                 "https://www-google-com.translate.goog/"])
def test_official_sites_are_safe(rules, url):
    f = rules.check(url)
    assert f.verdict == "safe" and f.entities["link_kind"] == "official"


def test_apk_and_at_tricks_are_dangerous(rules):
    f = rules.check("https://pm-kisan.in/PMKisan.apk")
    assert f.verdict == "dangerous" and f.category == "apk_malware_link"
    assert rules.check("http://www.sbi.co.in@evil-site.xyz/login").verdict == "dangerous"


def test_short_chat_and_ip_links(rules):
    assert rules.check("https://bit.ly/3abc").category == "generic_suspicious"
    assert rules.check("wa.me/919800000012").entities["link_kind"] == "chat"
    assert rules.check("http://192.168.1.10/login").verdict == "dangerous"


def test_hidden_links_are_checked(rules):
    f = rules.check("https://www.google.com/url?q=https%3A%2F%2Fsbi-kyc-update.xyz%2Flogin")
    assert f.verdict == "dangerous" and "hidden inside the link" in f.reasons[0]
    f = rules.check("https://sbi-kyc-update-xyz.translate.goog/login")
    assert f.verdict == "dangerous" and "Google Translate" in f.reasons[0]


def test_reasons_never_contain_the_link(rules):
    for url in ("http://sbi-kyc-update.xyz/login", "https://hdfcbank.weebly.com", "http://192.168.1.10/login",
                "https://bit.ly/3abc", "https://sites.google.com/view/sbi-kyc-update"):
        f = rules.check(url)
        text = " ".join(f.reasons)
        assert parse_link(url).host not in text and "http" not in text


# --- lists ----------------------------------------------------------------
def test_blocklist(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    counts = intel.build({"test": ["# comment", "evil-login.com", "http://bad.example.org/x", "docs.google.com",
                                   "sbi.co.in", "axis.bank.in", "x.weebly.com", "popular.com"]},
                         out=db, allow={"popular.com"})
    assert counts == {"test": 3}                      # shared, official and allowed entries are left out
    d = UrlDetector(model_path=None, intel_path=db, top_sites=None)
    for url in ("https://evil-login.com/a", "https://www.evil-login.com", "https://pay.evil-login.com",
                "https://bad.example.org", "https://x.weebly.com"):
        v = d.check_link(parse_link(url))
        assert v.listed == "test" and v.decisive and v.verdict == "dangerous", url
    for url in ("https://docs.google.com/forms/x", "https://sbi.co.in", "https://y.weebly.com", "https://example.org"):
        assert d.check_link(parse_link(url)).listed is None, url
    assert d.info()["blocklist"]["hosts"] == 3


def test_top_sites_lower_the_score():
    plain = UrlDetector(model_path=None, intel_path=None, top_sites=None)
    known = UrlDetector(model_path=None, intel_path=None, top_sites={"shopfast.com"})
    link = parse_link("https://shopfast.com/sale")
    assert known.check_link(link).score < plain.check_link(link).score
    assert known.check_link(link).kind == "popular"


# --- the model file --------------------------------------------------------
def test_model_file_scores_like_scikit_learn(tmp_path):
    from sklearn.feature_extraction.text import TfidfTransformer
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    from detectors.url.features import HASHER, matrix, numeric
    from detectors.url.model import LinkModel
    pairs = [("hdfcbank", "com"), ("sbi-kyc-update", "xyz"), ("flipkart", "com"), ("paytm-reward", "top"),
             ("westside", "com"), ("x9z7q-login", "icu"), ("airtel", "in"), ("secure-verify", "cfd")]
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1])
    tfidf = TfidfTransformer(sublinear_tf=True).fit(HASHER.transform([f"{a}.{b}" for a, b in pairs]))
    scaler = StandardScaler().fit(np.array([numeric(a, b) for a, b in pairs], dtype=float))
    clf = LogisticRegression(max_iter=1000).fit(matrix(pairs, tfidf, scaler), y)
    path = str(tmp_path / "m.npz")
    LinkModel.from_sklearn(clf, tfidf, scaler, {"test": True}).save(path)
    m = LinkModel.load(path)
    test = [("kotak", "com"), ("hdfc-kyc", "xyz")]
    want = clf.predict_proba(matrix(test, tfidf, scaler))[:, 1]
    assert np.allclose(m.scores(test), want, atol=1e-5) and m.meta == {"test": True}
    d = UrlDetector(model_path=path, intel_path=None, top_sites=None)
    assert d.check_link(parse_link("https://hdfc-kyc.xyz")).model_score is None    # a decisive rule comes first
    v = d.check_link(parse_link("https://kotak-x.com"))                            # a brand name raises the odds
    assert v.model_score is not None and v.score > v.model_score and v.brand == "Kotak Mahindra Bank"


# --- links inside messages ------------------------------------------------
@pytest.fixture(scope="module")
def sms(rules):
    return SmsDetector(url_detector=rules)


def test_imitating_link_makes_any_message_dangerous(sms):
    f = sms.check("Your account will be blocked today. Update PAN at https://sbi-yono-pan.top/kyc",
                  sender="JD-SBIINB-S")
    assert f.verdict == "dangerous" and f.entities["claims_to_be"] == "SBI"
    assert f.reasons[0].startswith("the website address uses SBI's name")
    assert f.entities["links"] == [{"link": "sbi-yono-pan[.]top", "verdict": "dangerous", "kind": "site"}]


def test_official_link_lowers_the_score(sms):
    msg = "SBI: your account statement is ready, see https://sbi.co.in/stmt"
    plain = SmsDetector(url_detector=None).check(msg, sender="9812345678")
    f = sms.check(msg, sender="9812345678")
    assert f.score < plain.score
    assert not any(".bank.in" in r for r in f.reasons)       # the link is SBI's own website


def test_links_in_the_api(sms):
    c = TestClient(create_app(detector=sms, advisor=Advisor()))
    r = c.post("/url", json={"url": "https://hdfcbank.weebly.com/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding"]["source"] == "url" and body["finding"]["verdict"] == "dangerous"
    assert body["advice"]["steps"] and "raw_text" not in body["finding"]
    assert c.post("/url", json={"url": "two words"}).status_code == 422
    r = c.post("/check", json={"message": "sbi.co.in"})               # a pasted link on its own
    assert r.json()["finding"]["source"] == "url" and r.json()["advice"]["headline"].startswith("LIKELY SAFE")
    assert c.post("/check", json={"message": "hello there"}).json()["finding"]["source"] == "sms"
    assert "links" in c.get("/health").json()
