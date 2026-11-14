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
    assert "Sentences the grounding checks now drop: a number the evidence does not have 2" in text
    assert "dropped by the new checks" in text and "Grader ravi: 4 of 4 sentences graded" in text
    assert "asha and ravi graded 4 sentences both: they agree on 50%, Cohen's kappa 0.20" in text


def test_kappa():
    assert grade.kappa([("s", "s"), ("n", "n")])[1] == pytest.approx(1.0)
    assert grade.kappa([("s", "n"), ("n", "s")])[1] < 0
    assert grade.kappa([]) is None
