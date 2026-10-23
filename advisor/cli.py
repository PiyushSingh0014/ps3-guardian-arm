"""Check one message from a terminal (laptop or Pi). Run from the repo root.

    python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v"

    # with Llama on the Pi:
    ADVISOR_BACKEND=llama_main LLAMA_MAIN=./llama_main LLAMA_PTE=llama3_2.pte \
    LLAMA_TOKENIZER=tokenizer.model python -m advisor.cli "..." --lang hi --show-prompt
"""
import argparse
import json

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
    advice = advisor.advise(finding)

    print(f"\n{advice.headline}")
    print(f"(score {finding.score:.2f} | category {finding.category} | "
          f"backend {advisor.backend.name} | source {advice.source})")
    print(f"\nWhat happened: {advice.what}\nWhy: {advice.why}\nWhat to do now:")
    for i, step in enumerate(advice.steps, 1):
        print(f"  {i}. {step}")
    if advice.flags:
        print("\nValidator notes: " + "; ".join(advice.flags))
    if advice.metrics:
        print("Metrics: " + json.dumps(advice.metrics))
    if a.show_prompt:
        book = get_playbook(advisor.books, finding.category)
        print("\n--- prompt sent to Llama ---\n" + build_prompt(finding, book))


if __name__ == "__main__":
    main()
