"""Stand-in for ExecuTorch's llama_main, so the advisor can be tested on a laptop.

Mimics the real runner's stdout: echoes the prompt, prints the answer, then a
"PyTorchObserver {json}" stats line; log lines go to stderr.
Set FAKE_LLAMA_MODE=good|contradict|leak|garbage|hedge to exercise the validator.
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
    "good": ("This message pretends to be from SBI to trick you into opening a fake KYC link. "
             "Real banks send SMS from registered sender IDs, and genuine bank links end in .bank.in."),
    "contradict": "This message is safe and comes from your bank. You can trust it.",
    "leak": ("This message pretends to be from SBI to steal your bank details. "
             "Call 98123 45678 or visit sbi-help.example to fix your account."),
    "garbage": "I am not sure what you mean by",
    "hedge": ("This message is likely a scam pretending to be SBI. "
              "It asks you to update your Know Your Account details through a fake link."),
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
