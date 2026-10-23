"""Pre-explain messages through the Llama service, and write a review/benchmark table.

Run on the Pi from the repo root while `python -m advisor.llm_service` is running:

    python -m advisor.warm_cache detectors/sms/sample_messages.csv
    python -m advisor.warm_cache my_india_test.csv --lang hi
    python -m advisor.warm_cache my_india_test.csv --fresh --report eval/advisor_pi4.md

What it does:
  1. runs the SMS detector on every message (CSV columns: message, optional
     sender and label);
  2. builds the advisor prompt for each flagged message. v3 prompts contain
     only evidence, so many messages share a prompt;
  3. asks the service once per distinct prompt. Each answer lands in the
     service's answer cache, so those alerts are instant in the demo;
  4. validates every answer and writes a Markdown table you can review by
     hand and paste into the report (timings included).
--fresh bypasses the answer cache, to measure real generation time.
"""
import argparse
import csv
import os
import re
import time

from advisor.advise import Advisor
from advisor.backends import LlamaServiceBackend
from advisor.playbooks import get_playbook
from advisor.prompt import build_prompt, max_new_tokens
from advisor.validator import check_explanation


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if rows and "message" not in rows[0]:
        if "v2" in rows[0]:                       # UCI spam.csv layout
            rows = [{"message": r["v2"], "label": r.get("v1", "")} for r in rows]
        else:
            raise SystemExit("CSV needs a 'message' column (optional: sender, label)")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--lang", default="en", choices=["en", "hi"])
    ap.add_argument("--limit", type=int, default=0, help="stop after N distinct prompts")
    ap.add_argument("--fresh", action="store_true", help="ignore saved answers (benchmark mode)")
    ap.add_argument("--report", default=os.path.join("eval", "advisor_review.md"))
    ap.add_argument("--url", default=os.environ.get("LLAMA_SERVICE_URL", "http://127.0.0.1:8765"))
    a = ap.parse_args()

    from detectors.sms.detector import SmsDetector
    detector, backend = SmsDetector(), LlamaServiceBackend(url=a.url)
    advisor = Advisor(backend=backend)
    if not backend.health().get("ok"):
        raise SystemExit(f"Llama service not reachable at {a.url}. Start: python -m advisor.llm_service ...")

    rows = read_rows(a.csv)
    prompts = {}                                   # prompt -> (finding, count)
    flagged = 0
    for r in rows:
        f = detector.check(r["message"], sender=(r.get("sender") or None), language=a.lang)
        if not advisor.needs_llm(f):
            continue
        flagged += 1
        p = build_prompt(f, get_playbook(advisor.books, f.category))
        first, n = prompts.get(p, (f, 0))
        prompts[p] = (first, n + 1)
    print(f"{len(rows)} messages, {flagged} need an explanation, {len(prompts)} distinct prompts")

    results, t_start = [], time.time()
    for i, (p, (f, n)) in enumerate(prompts.items(), 1):
        if a.limit and i > a.limit:
            break
        if a.fresh:
            r = backend._http().post("/generate", json={"prompt": p, "use_cache": False,
                                                         "max_new_tokens": max_new_tokens(a.lang)})
            d = r.json() if r.status_code == 200 else {"text": "", "metrics": {}}
            text, m = d.get("text", ""), d.get("metrics", {})
        else:
            res = backend.generate(p, max_new_tokens=max_new_tokens(a.lang))
            text, m = res.text, res.metrics
        c = check_explanation(text, f.verdict, a.lang)
        results.append((f, n, text, c, m))
        print(f"[{i}/{len(prompts)}] {f.category:<26} {'cached' if m.get('cached') else str(m.get('total_s', '?')) + ' s':>8} "
              f"{'OK ' if c.ok else 'REJ'} {text[:90]!r}")
    print(f"done in {time.time() - t_start:.1f} s")

    os.makedirs(os.path.dirname(a.report) or ".", exist_ok=True)
    with open(a.report, "w", encoding="utf-8") as out:
        out.write(f"# Advisor review ({a.lang}, {'fresh' if a.fresh else 'cached where possible'})\n\n")
        out.write(f"Source: `{a.csv}`. {len(rows)} messages, {flagged} flagged, {len(prompts)} distinct prompts.\n\n")
        out.write("| # | Category | Msgs | Prompt tok (reused) | TTFT s | Decode tok/s | Total s | Valid | Explanation |\n")
        out.write("|---|---|---|---|---|---|---|---|---|\n")
        for i, (f, n, text, c, m) in enumerate(results, 1):
            shown = " ".join([c.what, c.why]).strip() if c.ok else text
            shown = re.sub(r"[\x00-\x1f\x7f|]", " ", shown)          # keep the Markdown table intact
            out.write(f"| {i} | {f.category} | {n} | {m.get('prompt_tokens', '')} ({m.get('reused_tokens', '')}) | "
                      f"{m.get('ttft_s', '')} | {m.get('decode_tok_s', '')} | "
                      f"{'cached' if m.get('cached') else m.get('total_s', '')} | "
                      f"{'yes' if c.ok else 'no: ' + '; '.join(c.flags)[:60]} | {shown[:300]} |\n")
    print(f"review table -> {a.report}")


if __name__ == "__main__":
    main()
