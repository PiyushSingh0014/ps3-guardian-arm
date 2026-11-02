"""Pre-explain messages through the Llama service, and write a review/benchmark table.

Run on the Pi from the repo root while `python -m advisor.llm_service` is running:

    python -m advisor.warm_cache detectors/sms/sample_messages.csv
    python -m advisor.warm_cache my_india_test.csv --lang hi
    python -m advisor.warm_cache my_india_test.csv --fresh --report eval/advisor_pi4.md
    python -m advisor.warm_cache --net                      # network alerts

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

--net does the same for network alerts: one sample of each of the 10 alert kinds, plus
every alert in the monitor's file (logs/net_alerts.jsonl), into eval/advisor_net_review.md.
The samples' reasons are written the way the monitor writes them.
"""
import argparse
import csv
import os
import re
import time

from advisor.advise import Advisor
from advisor.backends import LlamaServiceBackend
from advisor.findings import Finding
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


DEV = "10.42.0.170"
NET_SAMPLES = [   # (kind, verdict, score, reasons), worded as detectors/net writes them
    ("port_scan", "dangerous", 0.95, [f"{DEV} tried 100 different ports on 10.42.0.1 within 5 seconds, most of "
                                      "them closed: that is how attackers look for a way in"]),
    ("network_scan", "dangerous", 0.95, [f"{DEV} tried to connect to 23 different machines on Telnet within a "
                                         "minute, mostly without answer",
                                         "scanning for Telnet is what Mirai-type botnets do from infected cameras "
                                         "and routers"]),
    ("dos_flood", "dangerous", 0.95, [f"{DEV} sent 200 half-open connection requests (SYN flood) to 10.42.0.1 port "
                                      "80 within 10 seconds: a flood meant to overload it"]),
    ("brute_force", "dangerous", 0.95, [f"{DEV} made 40 short login attempts on SSH at 10.42.0.1 within a minute: "
                                        "someone is guessing passwords"]),
    ("risky_port", "suspicious", 0.6, [f"{DEV} connected to an internet address on IRC chat, used to control bots "
                                       "(port 6667), which home devices normally never use"]),
    ("malware_beacon", "suspicious", 0.6, [f"{DEV} contacts example.com every 60 seconds, like clockwork (10 times "
                                           "so far): malware checks in with its controller this way"]),
    ("phishing_lookup", "dangerous", 0.9, [f"{DEV} looked up a fake website: the website address uses SBI's name, "
                                           "but it is not SBI's official website"]),
    ("dga_domains", "dangerous", 0.85, [f"{DEV} looked up 5 different random-looking website names within 10 "
                                        "minutes: malware makes up names like these to find its controller"]),
    ("dns_tunnel", "dangerous", 0.9, [f"{DEV} made 25 long, never-repeating DNS lookups under one website (about "
                                      "30 characters each) within 10 minutes: a way to smuggle data out, or to "
                                      "control malware, through DNS"]),
    ("device_anomaly", "suspicious", 0.7, [f"{DEV} is behaving unlike its normal self: 5.2 MB data sent in 5 "
                                           "minutes (its usual most is 300 KB)",
                                           f"{DEV} talked to 12 servers it never used before"]),
]


def net_findings(alerts_path):
    """One sample per network alert kind, then the monitor's alerts, oldest first."""
    out = [Finding(source="net", verdict=v, score=s, category=k, reasons=r, entities={"device": DEV})
           for k, v, s, r in NET_SAMPLES]
    if alerts_path and os.path.exists(alerts_path):
        from app.server import read_alerts
        out += [Finding(**item["finding"]) for item in reversed(read_alerts(alerts_path, limit=100_000))]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", help="messages to explain (not needed with --net)")
    ap.add_argument("--net", action="store_true", help="network alerts: samples of all kinds plus the monitor's")
    ap.add_argument("--alerts", default=os.path.join("logs", "net_alerts.jsonl"), help="the monitor's alerts (--net)")
    ap.add_argument("--lang", default="en", choices=["en", "hi"])
    ap.add_argument("--limit", type=int, default=0, help="stop after N distinct prompts")
    ap.add_argument("--fresh", action="store_true", help="ignore saved answers (benchmark mode)")
    ap.add_argument("--report", default=None, help="default: eval/advisor_review.md, or eval/advisor_net_review.md")
    ap.add_argument("--url", default=os.environ.get("LLAMA_SERVICE_URL", "http://127.0.0.1:8765"))
    a = ap.parse_args()
    if not a.net and not a.csv:
        ap.error("give a CSV of messages, or --net")
    a.report = a.report or os.path.join("eval", "advisor_net_review.md" if a.net else "advisor_review.md")

    backend = LlamaServiceBackend(url=a.url)
    advisor = Advisor(backend=backend)
    if not backend.health().get("ok"):
        raise SystemExit(f"Llama service not reachable at {a.url}. Start: python -m advisor.llm_service ...")

    if a.net:
        source = f"{len(NET_SAMPLES)} samples + `{a.alerts}`"
        findings = net_findings(a.alerts)
        what = "alerts"
    else:
        from detectors.sms.detector import SmsDetector
        detector = SmsDetector()
        source = f"`{a.csv}`"
        findings = (detector.check(r["message"], sender=(r.get("sender") or None), language=a.lang)
                    for r in read_rows(a.csv))
        what = "messages"
    prompts = {}                                   # prompt -> (finding, count)
    flagged = total = 0
    for f in findings:
        total += 1
        if not advisor.needs_llm(f):
            continue
        flagged += 1
        p = build_prompt(f, get_playbook(advisor.books, f.category))
        first, n = prompts.get(p, (f, 0))
        prompts[p] = (first, n + 1)
    print(f"{total} {what}, {flagged} need an explanation, {len(prompts)} distinct prompts")

    results, t_start = [], time.time()
    for i, (p, (f, n)) in enumerate(prompts.items(), 1):
        if a.limit and i > a.limit:
            break
        n_new = max_new_tokens(f.language, f.source)
        if a.fresh:
            r = backend._http().post("/generate", json={"prompt": p, "use_cache": False, "max_new_tokens": n_new})
            d = r.json() if r.status_code == 200 else {"text": "", "metrics": {}}
            text, m = d.get("text", ""), d.get("metrics", {})
        else:
            res = backend.generate(p, max_new_tokens=n_new)
            text, m = res.text, res.metrics
        c = check_explanation(text, f.verdict, f.language)
        results.append((f, n, text, c, m))
        print(f"[{i}/{len(prompts)}] {f.category:<26} {'cached' if m.get('cached') else str(m.get('total_s', '?')) + ' s':>8} "
              f"{'OK ' if c.ok else 'REJ'} {text[:90]!r}")
    print(f"done in {time.time() - t_start:.1f} s")

    os.makedirs(os.path.dirname(a.report) or ".", exist_ok=True)
    with open(a.report, "w", encoding="utf-8") as out:
        kind = "network alerts" if a.net else a.lang
        out.write(f"# Advisor review ({kind}, {'fresh' if a.fresh else 'cached where possible'})\n\n")
        out.write(f"Source: {source}. {total} {what}, {flagged} flagged, {len(prompts)} distinct prompts.\n\n")
        out.write(f"| # | Category | {'Alerts' if a.net else 'Msgs'} | Prompt tok (reused) | TTFT s | Decode tok/s | "
                  "Total s | Valid | Explanation |\n")
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
