"""Update 38: the validator's grounding checks (a sentence may not say more than the case Llama was
shown) and the tool to grade Llama's sentences by hand. Llama is a stand-in here."""
import json

import pytest

from advisor import grade
from advisor.advise import Advisor
from advisor.backends import GenResult
from advisor.findings import Finding
from advisor.playbooks import get_playbook
from advisor.prompt import case_text
from advisor.validator import check_explanation, ungrounded

EVIDENCE = ("Scam type: Fake bank KYC\nFact: Banks never ask you to update KYC through a link in an SMS.\n"
            "Scanner result: scam (high confidence)\nPretends to be: SBI (a bank)\nWarning signs:\n- uses a short link")


class Llama:
    """Answers every prompt with the same text, like a fixed greedy answer."""
    name = "fake_service"

    def __init__(self, text):
        self.text, self.calls = text, 0

    def generate(self, prompt, max_new_tokens=None):
        self.calls += 1
        return GenResult(text=self.text, metrics={"total_s": 0.01, "cached": False})


# --- grounding ----------------------------------------------------------------------------------

@pytest.mark.parametrize("sentence,why", [
    ("This message pretends to be from SBI to get your bank login.", None),
    ("Banks never ask you to update KYC through a link.", None),                  # "never" is in the fact
    ("Call 1930 to report it.", None),                                            # the helpline: always fine
    ("It pretends to be from HDFC Bank.", "names HDFC Bank, which the evidence does not"),
    ("Act within 24 hours or lose your account.", "a number the evidence does not have (24)"),
    ("Banks always use .bank.in links.", 'says "always", which the evidence does not'),
    ("Report it to the police at once.", "names the police, which the evidence does not"),
])
def test_a_sentence_may_not_say_more_than_the_evidence(sentence, why):
    assert ungrounded(sentence, EVIDENCE) == why


# --- update 38b: what reading the first 100 graded answers showed -------------------------------

OTP = ("Scam type: OTP or password theft\nFact: No bank, company or government office ever asks you to share an "
       "OTP; anyone who has your OTP can take money from your account or take over your apps.\n"
       "Scanner result: scam (high confidence)\nPretends to be: a bank or company\nWarning signs:\n- contains a link")
GENERIC = ("Scam type: Suspicious message\nScammer wants: to rush you into opening a link or sharing personal details\n"
           "Fact: Scammers use urgency, links and requests for personal details to rush people into mistakes before "
           "they can check.\nScanner result: scam (high confidence)\nPretends to be: someone you might trust\n"
           "Warning signs:\n- contains a link")
KYC = ("Scam type: Fake bank KYC (Know Your Customer) message\nFact: Banks update KYC only at a branch or through "
       "their official app or website, and genuine bank links end in .bank.in.\nScanner result: scam (high "
       "confidence)\nPretends to be: SBI (a bank)\nWarning signs:\n- claims to be from a bank, but the link is not "
       "on an official .bank.in website")
RULE = "a rule about what real companies or people do, which the fact does not state"
DOMAIN = "says where the link goes, or that .bank.in or .gov.in sites are not real"


@pytest.mark.parametrize("evidence,sentence,why", [
    (OTP, "Real companies never ask for your OTP, and this link is a common bait.", None),   # "No ... ever asks"
    (GENERIC, "Real companies never ask for your OTP.", 'says "never", which the evidence does not'),
    (GENERIC, "Real trusted sources do not ask you to call a number.", RULE),
    (GENERIC, "Real people you trust are unlikely to ask you to click on a link.", RULE),
    (GENERIC, "Scammers use urgency and links to rush people into mistakes.", None),
    (GENERIC, "This message pretends to be from a trusted source, but the link is suspicious.", None),
    (KYC, "Genuine banks do not send links to fake KYC pages.", None),         # the fact states a rule
    (KYC, "Genuine banks do not send such messages, and the link ends in .bank.in.", DOMAIN),
    (KYC, "Genuine banks do not update KYC on their website, and links ending in .bank.in are not real.", DOMAIN),
    (KYC, "This link ends in .bank.in, which is not a bank's official domain.", DOMAIN),
    (KYC, "Genuine bank links end in .bank.in, and this link is not on an official .bank.in website.", None),
])
def test_rules_and_domains_must_come_from_the_case(evidence, sentence, why):
    assert ungrounded(sentence, evidence) == why


def test_every_worked_example_passes_the_checks_against_its_own_case():
    """Llama copies the prompt's examples, so they must survive the checks. Update 38 dropped the OTP
    example's "Real companies never ask for your OTP": its fact says "No bank ... ever asks"."""
    from advisor.prompt import EXAMPLES, EXAMPLES_NET, format_case, format_net_case
    for ex in EXAMPLES:
        case = format_case(ex["result"], ex["scam_type"], ex["pretends"], ex["signs"], ex["fact"], ex["wants"],
                           ex["says"])
        verdict = "dangerous" if "high" in ex["result"] else "suspicious"
        for lang, answer in ex["answer"].items():
            c = check_explanation(answer, verdict, lang, evidence=case)
            assert [k for _, k, _ in c.sentences] == [True, True], (answer, c.flags)
    for ex in EXAMPLES_NET:
        case = format_net_case(ex["result"], ex["alert_type"], ex["wants"], ex["fact"], ex["saw"])
        verdict = "dangerous" if "high" in ex["result"] else "suspicious"
        c = check_explanation(ex["answer"], verdict, evidence=case)
        assert [k for _, k, _ in c.sentences] == [True, True], (ex["answer"], c.flags)


def test_devanagari_digits_count_as_numbers():
    assert ungrounded("२४ घंटे में खाता बंद होगा।", EVIDENCE, "hi") == "a number the evidence does not have (24)"


def test_the_checker_records_each_sentence_and_drops_the_ungrounded_one():
    raw = "This message pretends to be from SBI to steal your login. HDFC Bank sends such messages too."
    c = check_explanation(raw, "dangerous", evidence=EVIDENCE)
    assert c.what.startswith("This message pretends") and c.why == ""
    assert [k for _, k, _ in c.sentences] == [True, False]
    assert c.sentences[1][2] == "names HDFC Bank, which the evidence does not"
    assert [k for _, k, _ in check_explanation(raw, "dangerous").sentences] == [True, True]   # no evidence: as before


def test_the_advisor_holds_llama_to_its_case(monkeypatch):
    f = Finding(source="sms", verdict="dangerous", score=0.95, category="bank_kyc_scam",
                reasons=["uses a short link that hides the real website"],
                entities={"claims_to_be": "SBI", "claims_kind": "bank"})
    text = "This message pretends to be from SBI to steal your login. HDFC Bank sends such messages too."
    adv = Advisor(backend=Llama(text))
    a = adv.explain(f)
    assert a.source == "llm" and a.what.startswith("This message pretends") and "HDFC" not in a.why
    assert any("names HDFC Bank" in fl for fl in a.flags)
    monkeypatch.setenv("GUARDIAN_GROUNDING", "0")
    assert "HDFC" in adv.explain(f).why                                          # the switch turns it off
    assert "SBI" in case_text(f, get_playbook(adv.books, f.category))


# --- the grading tool ---------------------------------------------------------------------------

def findings():
    kyc = Finding(source="sms", verdict="dangerous", score=0.95, category="bank_kyc_scam",
                  reasons=["uses a short link that hides the real website"],
                  entities={"claims_to_be": "SBI", "claims_kind": "bank"})
    same = Finding(**{**kyc.__dict__})                                            # the same case: asked once
    other = Finding(source="sms", verdict="suspicious", score=0.6, category="bank_kyc_scam",
                    reasons=["talks about your OTP, PIN, CVV or password"],
                    entities={"claims_to_be": "SBI", "claims_kind": "bank"})
    safe = Finding(source="sms", verdict="safe", score=0.1, category="none", reasons=[], entities={})
    return [kyc, same, other, safe]


def test_generate_asks_once_per_case_and_carries_on(tmp_path):
    llama = Llama("This message pretends to be from SBI to steal your login. Banks always reply within 24 hours.")
    adv, said = Advisor(backend=llama), []
    assert grade.generate(findings(), adv, str(tmp_path), say=said.append) == 0
    answers = grade.read_answers(str(tmp_path))
    assert llama.calls == 2 and len(answers) == 2 and said[0].startswith("2 different cases")
    a = answers[0]
    assert a["shown_before"] == [True, True] and a["shown_now"] == [True, False]
    assert a["dropped_now"][1] == "a number the evidence does not have (24)" and "Pretends to be: SBI" in a["case"]
    assert grade.generate(findings(), adv, str(tmp_path), say=said.append) == 0  # run again: nothing new
    assert llama.calls == 2 and "(2 answered before): asking Llama for 0" in said[-1]


def test_generate_stops_when_llama_does_not_answer(tmp_path):
    class Down(Llama):
        def generate(self, prompt, max_new_tokens=None):
            return GenResult(error="connection refused")
    many = [Finding(source="sms", verdict="dangerous", score=0.9, category="bank_kyc_scam", reasons=[f"sign {i}"],
                    entities={}) for i in range(5)]
    said = []
    assert grade.generate(many, Advisor(backend=Down("")), str(tmp_path), say=said.append) == 1
    assert "is the Llama service running?" in said[-1]


def test_label_and_report_with_two_graders(tmp_path):
    grade.generate(findings(), Advisor(backend=Llama(
        "This message pretends to be from SBI to steal your login. Banks always reply within 24 hours.")),
        str(tmp_path), say=lambda _: None)
    said = []
    answers = iter(["s", "x", "w", "b", "n", "s", "q"])        # typo, back, and stop before the last
    grade.label(str(tmp_path), "asha", ask=lambda _: next(answers), say=said.append)
    assert json.loads((tmp_path / "grades_asha.json").read_text()) == {
        grade.read_answers(str(tmp_path))[0]["id"]: {"0": "s", "1": "n"},
        grade.read_answers(str(tmp_path))[1]["id"]: {"0": "s"}}
    assert any("What Llama was shown" in s for s in said) and not any("shown_now" in s for s in said)  # blind
    for name, marks in (("asha", ["w"]), ("ravi", ["s", "w", "s", "n"])):
        it = iter(marks)
        grade.label(str(tmp_path), name, ask=lambda _: next(it), say=lambda _: None)
    out = []
    assert grade.report(str(tmp_path), say=out.append) == 0
    text = "\n".join(out)
    assert "2 answers (sms 2), 4 sentences" in text
    assert "Sentences today's checks drop: a number the evidence does not have 2" in text
    assert "differently from when the answers were saved" not in text
    assert "dropped by the checks" in text and "Grader ravi: 4 of 4 sentences graded" in text
    assert "asha and ravi graded 4 sentences both: they agree on 50%, Cohen's kappa 0.20" in text


def test_report_reruns_todays_checks_on_saved_answers(tmp_path):
    """Answers saved under older checks: the report measures today's, on the same grades."""
    first = "This message pretends to be from a trusted source to rush you into opening a link."
    second = "Real trusted sources do not ask you to call a number."
    rec = {"id": "a1", "source": "sms", "category": "generic_suspicious", "verdict": "dangerous", "language": "en",
           "case": GENERIC, "answer": f"{first} {second}", "sentences": [first, second],
           "shown_before": [True, True], "shown_now": [True, True], "dropped_now": ["", ""],
           "rejected_before": False, "rejected_now": False, "seconds": 1.0, "cached": False}
    (tmp_path / "answers.jsonl").write_text(json.dumps(rec) + "\n")
    (tmp_path / "grades_asha.json").write_text(json.dumps({"a1": {"0": "s", "1": "w"}}))
    out = []
    assert grade.report(str(tmp_path), say=out.append, wrong=True) == 0
    text = "\n".join(out)
    assert f"Sentences today's checks drop: {RULE} 1" in text
    assert "(1 sentences are shown or dropped differently from when the answers were saved" in text
    row = {line[:28].strip(): line[28:] for line in out if line[:28].strip()}
    assert row["shown now"].split()[:3] == ["1", "1", "(100%)"]                  # only sentence 1 is shown
    assert row["dropped by the checks"].split()[0] == "1" and row["first sentences"].split()[:2] == ["1", "1"]
    assert f"- generic_suspicious (asha w; dropped: {RULE}): {second}" in text


def test_generate_waits_for_the_llama_service():
    class Loading:
        calls = 0

        def health(self):
            self.calls += 1
            return {"ok": self.calls >= 3}
    said, slept = [], []
    assert grade.wait_for_llama(Loading(), say=said.append, wait_s=60, step_s=5, sleep=slept.append)
    assert slept == [5, 5] and said[0].startswith("Waiting for the Llama service")

    class Down:
        def health(self):
            return {"ok": False, "error": "ConnectError"}
    said = []
    assert not grade.wait_for_llama(Down(), say=said.append, wait_s=10, step_s=5, sleep=lambda s: None)
    assert "did not answer" in said[-1]
    assert grade.wait_for_llama(object())                                         # no health check: ready


def test_kappa():
    assert grade.kappa([("s", "s"), ("n", "n")])[1] == pytest.approx(1.0)
    assert grade.kappa([("s", "n"), ("n", "s")])[1] < 0
    assert grade.kappa([]) is None


TWO = "This message pretends to be from SBI to steal your login. Banks always reply within 24 hours."


def test_a_second_look_where_two_graders_differ(tmp_path):
    grade.generate(findings(), Advisor(backend=Llama(TWO)), str(tmp_path), say=lambda _: None)
    ids = [a["id"] for a in grade.read_answers(str(tmp_path))]
    (tmp_path / "grades_asha.json").write_text(json.dumps({ids[0]: {"0": "w", "1": "n"}, ids[1]: {"0": "s", "1": "n"}}))
    (tmp_path / "grades_ravi.json").write_text(json.dumps({ids[0]: {"0": "s", "1": "n"}, ids[1]: {"0": "s", "1": "w"}}))
    said, keys = [], iter(["s", ""])                 # asha changes the first; Enter keeps her grade on the second
    assert grade.label(str(tmp_path), "asha", ask=lambda _: next(keys), say=said.append, recheck="ravi") == 0
    assert said[0].startswith("2 sentences where asha and ravi differ") and "firstpass_asha.json" in said[0]
    assert any("What Llama was shown" in s for s in said) and "    -> supported" in said     # each grade echoed
    assert json.loads((tmp_path / "grades_asha.json").read_text()) == {ids[0]: {"0": "s", "1": "n"},
                                                                       ids[1]: {"0": "s", "1": "n"}}
    first = tmp_path / "firstpass_asha.json"
    assert json.loads(first.read_text())[ids[0]]["0"] == "w"
    keys = iter(["q"])
    assert grade.label(str(tmp_path), "asha", ask=lambda _: next(keys), say=lambda _: None, recheck="ravi") == 0
    assert json.loads(first.read_text())[ids[0]]["0"] == "w"                  # the first pass is kept, once
    said = []
    assert grade.label(str(tmp_path), "asha", say=said.append, recheck="zed") == 1 and "No grades from zed" in said[0]
    assert not list(tmp_path.glob("grades_firstpass*"))                       # never read as a grader


def test_report_compares_every_pair_and_finds_one_sentence_graded_two_ways(tmp_path):
    grade.generate(findings(), Advisor(backend=Llama(TWO)), str(tmp_path), say=lambda _: None)
    ids = [a["id"] for a in grade.read_answers(str(tmp_path))]
    for name, marks in {"asha": {ids[0]: {"0": "s", "1": "w"}, ids[1]: {"0": "w", "1": "w"}},
                        "ravi": {ids[0]: {"0": "s", "1": "w"}, ids[1]: {"0": "s", "1": "w"}},
                        "zoya": {ids[0]: {"0": "s", "1": "n"}, ids[1]: {"0": "s", "1": "n"}}}.items():
        (tmp_path / f"grades_{name}.json").write_text(json.dumps(marks))
    out = []
    assert grade.report(str(tmp_path), say=out.append, same=True) == 0
    text = "\n".join(out)
    for pair in ("asha and ravi", "asha and zoya", "ravi and zoya"):
        assert f"{pair} graded 4 sentences both" in text
    assert text.count("Same sentence and scam type graded differently: 1 (--same lists them)") == 1     # asha
    assert text.count("Same sentence and scam type graded differently: 0") == 2
    assert "asha: the same sentence, for the same scam type, graded differently (1):" in text
    assert "- bank_kyc_scam (s 1, w 1): This message pretends to be from SBI to steal your login." in text


def test_a_consistency_pass_and_the_first_pass_in_the_report(tmp_path):
    grade.generate(findings(), Advisor(backend=Llama(TWO)), str(tmp_path), say=lambda _: None)
    ids = [a["id"] for a in grade.read_answers(str(tmp_path))]
    (tmp_path / "grades_asha.json").write_text(json.dumps({ids[0]: {"0": "s", "1": "w"}, ids[1]: {"0": "w", "1": "w"}}))
    (tmp_path / "grades_ravi.json").write_text(json.dumps({ids[0]: {"0": "s", "1": "w"}, ids[1]: {"0": "s", "1": "n"}}))
    said, keys = [], iter(["s", "s"])                # the same first sentence, graded s and w: both shown
    assert grade.label(str(tmp_path), "asha", ask=lambda _: next(keys), say=said.append, same=True) == 0
    assert said[0].startswith("1 sentences you graded in more than one way, 2 times in all")
    assert json.loads((tmp_path / "grades_asha.json").read_text())[ids[1]] == {"0": "s", "1": "w"}
    said = []
    assert grade.label(str(tmp_path), "asha", say=said.append, same=True) == 0
    assert said == ["asha grades every repeated sentence one way."]
    out = []
    assert grade.report(str(tmp_path), say=out.append) == 0
    text = "\n".join(out)
    assert "asha's first pass is kept: the second look changed 1 of its 4 grades." in text
    assert "asha's first pass and ravi: they agree on 50%, Cohen's kappa 0.27" in text
    assert "asha and ravi graded 4 sentences both: they agree on 75%" in text


def test_prompt_v5_against_v4_on_the_same_cases(tmp_path):
    # v4: cases without what the message says; v5 asks again for the same cases, now with the phrases.
    old, new = tmp_path / "v4", tmp_path / "v5"
    v4 = findings()
    llama = Llama("This message pretends to be from SBI to steal your login.")
    grade.generate(v4, Advisor(backend=llama), str(old), say=lambda _: None)
    v5 = [Finding(**{**f.__dict__, "entities": {**f.entities, "says": ["says your bank account will be blocked"]}})
          for f in v4[:3]]
    v5.append(Finding(source="sms", verdict="dangerous", score=0.9, category="lottery_reward_scam",
                      reasons=["promises a prize"], entities={}))         # not graded before: not asked
    said = []
    assert grade.generate(v5, Advisor(backend=llama), str(new), say=said.append, match=str(old)) == 0
    assert said[0] == f"2 of the 2 message cases in {old} found again."
    answers, before = grade.read_answers(str(new)), grade.read_answers(str(old))
    assert [a["was"] for a in answers] == [a["id"] for a in before]
    assert all("- says your bank account will be blocked" in a["case"] for a in answers)
    for folder, mark in ((old, "w"), (new, "s")):
        it = iter([mark, mark])
        grade.label(str(folder), "asha", ask=lambda _: next(it), say=lambda _: None)
    out = []
    assert grade.report(str(new), say=out.append, compare_with=str(old)) == 0
    text = "\n".join(out)
    assert "The same 2 message cases, before and after" in text
    assert "everything Llama wrote, old" in text and "everything Llama wrote, new" in text
    assert "2 (100%)" in text.split("everything Llama wrote, new")[1].split("\n")[0]
