"""Update 43: the phone's copy of the checks (android/app/src/main/assets/guard/) must match the
Pi's Python rules. Change a rule, a list or a playbook, and this fails until
scripts/export_phone_guard.py has been run again."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "android", "app", "src", "main", "assets", "guard")
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def asset(name):
    with open(os.path.join(ASSETS, name), encoding="utf-8") as f:
        return json.load(f)


def same(a, b):
    return json.loads(json.dumps(a, sort_keys=True)) == b


@pytest.fixture(scope="module")
def export():
    import export_phone_guard
    return export_phone_guard


def test_the_phone_has_the_pis_rules_brands_and_sender_rules(export):
    assert same(export.sms_data(), asset("sms.json"))
    assert asset("sms.json")["sender_rules"] == ["cap", "brand"]


def test_the_phone_has_the_pis_playbooks(export):
    assert same(export.playbooks_data(), asset("playbooks.json"))
    assert len(asset("playbooks.json")["books"]) == 25


def test_the_phone_asks_llama_and_checks_its_answers_as_the_pi_does(export):
    assert same(export.llama_data(), asset("llama.json"))
    assert asset("llama.json")["max_new_tokens"] == {"en": 80, "hi": 192}


def test_the_phone_has_the_pis_link_lists(export):
    phone = asset("links.json")
    pi = export.links_data(phone["top_sites"], phone["link_model"])
    for key in ("psl_public", "psl_private"):        # the suffix list comes with tldextract's version
        pi.pop(key)
        assert len(phone[key]) > 1000
    assert same(pi, {k: v for k, v in phone.items() if k not in ("psl_public", "psl_private")})


def test_the_phone_has_the_pis_link_model(export, tmp_path):
    import numpy as np
    with open(os.path.join(ASSETS, "link_model.bin"), "rb") as f:
        data = f.read()
    assert data[:4] == b"PS3L"
    n_text, n_coef = np.frombuffer(data[4:12], dtype="<i4")
    with np.load(export.url_detector.MODEL) as z:
        assert (n_text, n_coef) == (len(z["idf"]), len(z["coef"]))
        assert np.array_equal(np.frombuffer(data[12:12 + 4 * n_text], dtype="<f4"), z["idf"].astype("<f4"))


def test_the_phone_has_a_real_sms_model():
    m = asset("sms_model.json")
    assert m["messages"] > 4000 and m["data"] == "merged_sms.csv"
    assert len(m["vocab"]) == len(m["idf"]) == len(m["coef"]) - 11
