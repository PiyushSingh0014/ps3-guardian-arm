"""Check one message from a terminal (laptop or Pi). Run from the repo root.

    python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v"

    # with the persistent Llama service running on the Pi (see README.md):
    ADVISOR_BACKEND=service python -m advisor.cli "..." --sender 9812345678 --show-prompt
"""
import argparse
import json
import time

from advisor.advise import Advisor
from advisor.backends import backend_from_env
from advisor.playbooks import get_playbook
from advisor.prompt import build_prompt
from detectors.sms.detector import SmsDetector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("message")
    ap.add_argument("--sender")
    ap.add_argument("--lang", default="en", choices=["en", "hi"])
    ap.add_argument("--show-prompt", action="store_true")
    a = ap.parse_args()

    finding = SmsDetector().check(a.message, sender=a.sender, language=a.lang)
    advisor = Advisor(backend=backend_from_env())
    t0 = time.time()
    advice = advisor.advise(finding)
    took = time.time() - t0

    cached = " (saved answer)" if advice.metrics.get("cached") else ""
    print(f"\n{advice.headline}")
    print(f"(score {finding.score:.2f} | category {finding.category} | "
          f"backend {advisor.backend.name} | source {advice.source}{cached} | {took:.1f} s)")
    print(f"\nWhat happened: {advice.what}\nWhy: {advice.why}\nWhat to do now:")
    for i, step in enumerate(advice.steps, 1):
        print(f"  {i}. {step}")
    if advice.flags:
        print("\nValidator notes: " + "; ".join(advice.flags))
    if advice.metrics:
        print("Metrics: " + json.dumps(advice.metrics))
    if a.show_prompt and finding.verdict != "safe":
        book = get_playbook(advisor.books, finding.category)
        n = getattr(advisor.backend, "n_examples", None)
        prompt = build_prompt(finding, book, n) if n is not None else build_prompt(finding, book)
        print("\n--- prompt sent to Llama ---\n" + prompt)


if __name__ == "__main__":
    main()
