"""Warning signs from detectors/sms/rules_india.py: they become Llama's evidence, so they must be true.

Cases from the first Pi benchmark: a lottery message ("share your bank details"),
an income-tax refund ("confirm your account") and a Paytm wallet message were all
told to Llama as "claims to be from a bank", and Llama then wrote things like
"Paytm is not a bank". The bank sign now needs a named bank.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detectors", "sms"))
from rules_india import extract_signals  # noqa: E402

BANK = "claims to be from a bank, but the link is not on an official .bank.in website"
GOV = "claims to be from a government office, but the link is not on an official .gov.in website"


def reasons(message, sender=None):
    return extract_signals(message, sender=sender).reasons


def test_bank_sign_needs_a_named_bank():
    assert BANK in reasons("Your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify")
    assert BANK in reasons("Your HDFC netbanking is suspended. Re-activate: short.example/hdfc")
    paytm = reasons("KYC pending for your Paytm wallet. Install this app to verify: http://paytm-kyc.example/app.apk")
    assert BANK not in paytm and paytm[0].startswith("asks you to install an app file")


def test_lottery_and_refund_get_accurate_signs():
    lottery = reasons("Congratulations! You won Rs 25,00,000 in the KBC lottery. Claim here and share "
                      "your bank details: http://kbc-win.example")
    assert BANK not in lottery and "asks for your bank account details" in lottery and "contains a link" in lottery
    refund = reasons("Income Tax refund of Rs 15,340 approved. Confirm your account: http://itr-refund.example/claim")
    assert BANK not in refund and refund[0] == GOV


def test_official_government_site_is_not_flagged_as_fake():
    assert GOV not in reasons("Income tax refund credited. Details at https://www.incometax.gov.in")


def test_feature_vector_is_unchanged_by_the_new_signs():
    sig = extract_signals("Claim here and share your bank details: http://kbc-win.example")
    assert sig.bank_context == 1 and sig.bank_link_not_bankin == 1     # same features the model was trained on
