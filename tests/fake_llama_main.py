"""Stand-in for ExecuTorch's llama_main, so the slice can be tested on a laptop.

Mimics the real runner's stdout: echoes the prompt, prints the answer, then a
"PyTorchObserver {json}" stats line; log lines go to stderr.
Set FAKE_LLAMA_MODE=good|contradict|leak|garbage to exercise the validator.
"""
import argparse
import json
import os
import sys

ap = argparse.ArgumentParser()
for flag in ("--model_path", "--tokenizer_path", "--prompt_file", "--max_new_tokens",
             "--temperature", "--cpu_threads"):
    ap.add_argument(flag)
args, _ = ap.parse_known_args()

with open(args.prompt_file, encoding="utf-8") as f:
    prompt = f.read()

ANSWERS = {
    "good": ("WHAT HAPPENED: Someone pretending to be your bank sent you a fake KYC message.\n"
             "WHY: The link is not a real bank website and it threatens to block your account.\n"
             "STEPS: 1, 2, 5"),
    "contradict": "WHAT HAPPENED: This message is safe.\nWHY: It looks legitimate.\nSTEPS: 1",
    "leak": ("WHAT HAPPENED: A fake bank message. Call 98123 45678 or visit sbi-help.example now.\n"
             "WHY: It asks for your OTP. Report at cybercrime.gov.in or call 1930.\nSTEPS: 2, 9, 2"),
    "garbage": "I am not sure what you mean.",
}

sys.stderr.write("I 00:00:00.000100 executorch:text_llm_runner.cpp:100] RSS after loading model: 1900 MiB\n")
sys.stdout.write(prompt)                                   # echo, like the real runner
sys.stdout.write(ANSWERS[os.environ.get("FAKE_LLAMA_MODE", "good")] + "<|eot_id|>\n")
stats = {"prompt_tokens": 380, "generated_tokens": 42,
         "model_load_start_ms": 1000, "model_load_end_ms": 2500,
         "inference_start_ms": 2500, "prompt_eval_end_ms": 8000,
         "first_token_ms": 8100, "inference_end_ms": 12000,
         "SCALING_FACTOR_UNITS_PER_SECOND": 1000}
sys.stdout.write("PyTorchObserver " + json.dumps(stats) + "\n")
