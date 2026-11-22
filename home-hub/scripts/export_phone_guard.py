"""Copy the data of the Pi's message and link checkers into the phone app (update 43).

The phone runs the same checks offline (phone-app/.../guard/): the SMS text model, the India rules,
the sender rules, the link model and lists, the scam types and the playbooks' steps. This script
writes what they need into phone-app/app/src/main/assets/guard/, from the same Python modules the Pi
uses, so the two cannot drift apart: rerun it after changing a rule, a list or a model.

    python scripts/export_phone_guard.py --sms-model detectors/sms/sms_baseline.joblib

--sms-model: a model from detectors/sms/train_baseline.py (v1). The phone has no phishing list
(392,000 sites): that stays on the Pi, which adds it when the phone is at home.
"""
import argparse
import html
import html.entities
import json
import os
import re
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "detectors", "sms"))

import joblib                                                    # noqa: E402
import tldextract                                                # noqa: E402

import brands as sms_brands                                      # noqa: E402
import rules_india                                               # noqa: E402
import says as sms_says                                          # noqa: E402
import senders                                                   # noqa: E402
from advisor import categorize                                   # noqa: E402
from advisor.advise import MAX_STEPS, SAFE_ADVICE                # noqa: E402
from advisor.findings import DANGEROUS_AT, SUSPICIOUS_AT         # noqa: E402
from advisor.playbooks import load_playbooks                     # noqa: E402
from detectors.files import names as file_names                  # noqa: E402
from detectors.sms import detector as sms_detector               # noqa: E402
from detectors.url import detector as url_detector               # noqa: E402
from detectors.url import links as url_links                     # noqa: E402
from detectors.url import lists as url_lists                     # noqa: E402

OUT = os.path.join(os.path.dirname(ROOT), "phone-app", "app", "src", "main", "assets", "guard")
SENDER_RULES_ON = ["cap", "brand"]          # measured on the Pi on 15 November 2026 (docs/sender-rules.md)


def pattern(rx):
    """[source, ignore case] of a compiled Python pattern. Other flags (re.M, re.S, re.X) would be lost on
    the phone, so they stop the export."""
    other = rx.flags & ~(re.I | re.U)
    if other:
        raise ValueError(f"pattern {rx.pattern[:40]!r} has flags the phone does not copy: {re.RegexFlag(other)!r}")
    return [rx.pattern, bool(rx.flags & re.I)]


def write_json(name, data):
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return path


def sms_model(path):
    bundle = joblib.load(path)
    if int(bundle.get("version", 1)) != 1:
        sys.exit("the phone runs SMS model v1 (two classes): pass a model from train_baseline.py")
    vec, clf = bundle["vec"], bundle["clf"]
    params = vec.get_params()
    if (params["analyzer"], params["ngram_range"], params["lowercase"], params["norm"], params["use_idf"],
            params["smooth_idf"], params["sublinear_tf"]) != ("char_wb", (2, 5), True, "l2", True, True, False):
        sys.exit("the phone's code expects TfidfVectorizer(char_wb, 2-5, l2, idf, no sublinear tf)")
    classes = [int(c) for c in clf.classes_]
    coef = clf.coef_[0].astype(float)
    if classes != [0, 1]:
        sys.exit(f"unexpected classes {classes}")
    return {"vocab": {k: int(v) for k, v in vec.vocabulary_.items()}, "idf": [float(x) for x in vec.idf_],
            "coef": [float(x) for x in coef], "intercept": float(clf.intercept_[0]),
            "features": rules_india.FEATURE_NAMES, "messages": bundle.get("messages"),
            "data": bundle.get("data"), "date": bundle.get("date")}


def link_model_bin(path):
    """The link model as little-endian numbers: idf and coefficients as float32 (as stored), the rest float64."""
    with np.load(path, allow_pickle=False) as z:
        idf, coef = z["idf"].astype("<f4"), z["coef"].astype("<f4")
        head = np.array([len(idf), len(coef)], dtype="<i4")
        tail = np.concatenate([z["intercept"][:1], z["mean"], z["scale"]]).astype("<f8")
        meta = json.loads(str(z["meta"]))
    out = os.path.join(OUT, "link_model.bin")
    with open(out, "wb") as f:
        f.write(b"PS3L" + head.tobytes() + idf.tobytes() + coef.tobytes() + tail.tobytes())
    return out, meta


def sms_data():
    """sms.json: the India rules' patterns, the brands, the sender odds and rules, the thresholds."""
    patterns = {name: pattern(getattr(rules_india, name)) for name in (
        "URL_RE", "BARE_DOMAIN_RE", "APK_RE", "UPI_RE", "SECRET_RE", "URGENCY_RE", "MONEY_RE", "SHORTENER_RE",
        "BANK_WORDS_RE", "REWARD_RE", "TEN_DIGIT_RE", "CALL_NUMBER_RE", "BANK_IN_RE", "GOV_SITE_RE",
        "NETBANKING_RE", "BANK_DETAILS_RE", "ASK_SECRET_RE", "NEGATION_RE")}
    patterns.update({
        "HEADER_RE": pattern(senders.HEADER_RE),
        "RISKY_CLAIM_RE": pattern(sms_detector.RISKY_CLAIM_RE),
        "DIGITAL_ARREST_RE": pattern(categorize.DIGITAL_ARREST_RE), "DELIVERY_RE": pattern(categorize.DELIVERY_RE),
        "JOB_RE": pattern(categorize.JOB_RE), "UTILITY_RE": pattern(categorize.UTILITY_RE),
        "CHAT_FILE_RE": pattern(file_names._CHAT_FILE_RE),
        "LINK_RE": pattern(url_links._LINK_RE), "WWW_RE": pattern(url_links._WWW_RE),
        "AMP_PATH_RE": pattern(url_detector._AMP_PATH_RE), "EMBEDDED_RE": pattern(url_detector._EMBEDDED_RE),
        "CREDENTIAL_WORDS": pattern(url_lists.CREDENTIAL_WORDS),
    })
    return {
        "patterns": patterns,
        "brands": [[name, kind, *pattern(rx)] for name, kind, rx in sms_brands.BRANDS],
        "header_roots": {k: list(v) for k, v in sms_brands.HEADER_ROOTS.items()},
        "preferred": {k: list(v) for k, v in sms_brands._PREFERRED.items()},
        "header_odds": senders.HEADER_ODDS, "mobile_risky_odds": senders.MOBILE_RISKY_ODDS,
        "no_suffix_odds": senders.NO_SUFFIX_ODDS, "sender_rules": SENDER_RULES_ON,
        "link_odds": sms_detector.LINK_ODDS, "official_link_odds": sms_detector.OFFICIAL_LINK_ODDS,
        "risky_kinds": list(sms_detector.RISKY_KINDS), "app_ext": sorted(file_names.APP_EXT),
        "suspicious_at": SUSPICIOUS_AT, "dangerous_at": DANGEROUS_AT,
        # What a flagged message says, in fixed words, for Llama (detectors/sms/says.py, prompt v5).
        "says": [[*pattern(rx), phrase] for rx, phrase in sms_says._RULES], "max_says": sms_says.MAX_SAYS,
    }


def links_data(top, link_meta):
    """links.json: the link checker's lists, reasons and odds, the popular websites and the suffix list."""
    extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                      include_psl_private_domains=True)._get_tld_extractor()
    return {
        "bank_zones": list(url_lists.BANK_ZONES), "gov_zones": list(url_lists.GOV_ZONES),
        "fin_zones": list(url_lists.FIN_ZONES), "brand_tlds": {k: list(v) for k, v in url_lists.BRAND_TLDS.items()},
        "brands": [[name, kind, rx.pattern, sorted(domains)] for name, kind, rx, domains in url_lists.BRANDS],
        "brand_infra": sorted(url_lists.BRAND_INFRA), "free_hosting": sorted(url_lists.FREE_HOSTING),
        "shared_content": sorted(url_lists.SHARED_CONTENT), "shorteners": sorted(url_lists.SHORTENERS),
        "chat_hosts": sorted(url_lists.CHAT_HOSTS), "cheap_tlds": sorted(url_lists.CHEAP_TLDS),
        "tld_like": sorted(url_lists.TLD_LIKE), "extra_suffixes": sorted(url_links._EXTRA_SUFFIXES),
        "reserved": sorted(url_links._RESERVED), "bare_ok": sorted(url_links._BARE_OK),
        "reasons": url_detector.R, "odds": url_detector.ODDS, "weak_brand_kinds": sorted(url_detector.WEAK_BRAND_KINDS),
        "scores": {"no_model": url_detector.NO_MODEL_SCORE, "opaque": url_detector.OPAQUE_SCORE,
                   "shared": url_detector.SHARED_SCORE, "official": url_detector.OFFICIAL_SCORE,
                   "decisive": url_detector.DECISIVE_SCORE, "listed": url_detector.LISTED_SCORE},
        "top_sites": top, "link_model": link_meta,
        "psl_public": sorted(extractor.public_tlds), "psl_private": sorted(extractor.private_tlds),
    }


def playbooks_data():
    books = load_playbooks()
    return {"max_steps": MAX_STEPS, "safe": SAFE_ADVICE, "books": {
        k: {"title": b.title, "severity": b.severity, "summary": b.summary, "steps": b.steps,
            "pretends": b.pretends, "wants": b.wants, "fact": b.fact} for k, b in books.items()}}


def llama_data():
    """llama.json (update 44): the Pi's Llama prompt for messages (advisor/prompt.py) and its answer
    checker (advisor/validator.py), so Llama on the phone is asked and held to the evidence as on the Pi."""
    from advisor import advise, findings, prompt, validator
    v = validator
    return {
        "system": prompt.SYSTEM, "lang_names": prompt.LANG_NAMES, "result_text": prompt.RESULT_TEXT,
        "examples": prompt.EXAMPLES, "max_signs": prompt.MAX_SIGNS, "max_new_tokens": prompt.MAX_NEW_TOKENS,
        "include_bos": prompt.INCLUDE_BOS_TOKEN, "special_token": prompt._SPECIAL_TOKEN_RE.pattern,
        "kind_label": findings._KIND_LABEL, "skip_severities": sorted(advise.SKIP_LLM_SEVERITIES),
        "preferred": {k: list(x) for k, x in sms_brands._PREFERRED.items()},
        "allowed_domains": sorted(v.ALLOWED_DOMAINS), "allowed_numbers": sorted(v.ALLOWED_NUMBERS),
        "max_sentences": v.MAX_SENTENCES, "max_words": v.MAX_WORDS,
        "patterns": {name: pattern(getattr(v, name)) for name in (
            "_CONTRADICTION_RE", "_URL_RE", "_PHONE_RE", "_SPECIAL_RE", "_SPLIT_RE", "_ABBREV_RE", "_PREAMBLE_RE",
            "_DEVANAGARI_RE", "_NUMBER_RE", "_ABSOLUTE_RE", "_NO_EVER_RE", "_DOMAIN_CLAIM_RE", "_RULE_RE",
            "_FACT_RULE_RE")},
        "hedges": [[*pattern(rx), repl] for rx, repl in v._HEDGES],
        "glossary": [[*pattern(rx), repl] for rx, repl in v._GLOSSARY],
        "organisations": [[name, *pattern(rx)] for name, rx in v.ORGANISATIONS],
    }


def text_data():
    """text.json: Python's HTML entities and ftfy's simple fixes, as the Pi's clean_text applies them
    (its mojibake repair is not copied)."""
    import ftfy.chardata as fc
    return {
        "entities": html.entities.html5,
        "invalid_charrefs": {str(k): v for k, v in html._invalid_charrefs.items()},
        "invalid_codepoints": sorted(html._invalid_codepoints),
        "c1": {str(b): bytes([b]).decode("sloppy-windows-1252") for b in range(0x80, 0xA0)},
        "ligatures": {str(k): v for k, v in fc.LIGATURES.items()},
        "width": {str(k): v for k, v in fc.WIDTH_MAP.items()},
        "control_chars": sorted(k for k, v in fc.CONTROL_CHARS.items() if v is None),
        "single_quote": fc.SINGLE_QUOTE_RE.pattern, "double_quote": fc.DOUBLE_QUOTE_RE.pattern}


def main(argv=None):
    global OUT
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sms-model", default=os.path.join(ROOT, "detectors", "sms", "sms_baseline.joblib"))
    ap.add_argument("--link-model", default=url_detector.MODEL)
    ap.add_argument("--top-sites", default=url_detector.TOP_SITES)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    OUT = a.out
    os.makedirs(OUT, exist_ok=True)

    model = sms_model(a.sms_model)
    write_json("sms_model.json", model)
    _, link_meta = link_model_bin(a.link_model)
    top = sorted(url_detector.load_top_sites(a.top_sites))
    if not top:
        sys.exit(f"no popular websites at {a.top_sites}: run scripts/get_url_data.py first")
    write_json("sms.json", sms_data())
    write_json("links.json", links_data(top, link_meta))
    write_json("playbooks.json", playbooks_data())
    write_json("text.json", text_data())
    write_json("llama.json", llama_data())
    write_json("meta.json", {"sms_model": {k: model[k] for k in ("messages", "data", "date")},
                             "vocabulary": len(model["vocab"]), "link_model": link_meta, "top_sites": len(top),
                             "sender_rules": SENDER_RULES_ON, "playbooks": len(playbooks_data()["books"])})
    for name in sorted(os.listdir(OUT)):
        print(f"  {name:20s} {os.path.getsize(os.path.join(OUT, name)) / 1024:8.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
