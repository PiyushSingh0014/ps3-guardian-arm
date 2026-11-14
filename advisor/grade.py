"""Grade Llama's explanations: is each sentence supported by the case Llama was shown?

Run on the Pi from the repo root while the Llama service is running (scripts/run_pi.sh starts it):

    python -m advisor.grade generate --india ~/india_sms_collection_v9.xlsx --net    # about an hour
    python -m advisor.grade label --grader piyush        # each grader on their own
    python -m advisor.grade report                       # the rates, before and after the grounding checks

generate: runs the app's SMS detector on the India set, builds the case Llama is shown for each
flagged message (prompt.case_text: verdict, scam type, fact, who it pretends to be, warning signs),
and asks Llama once per different case, up to --max (100). --net adds one sample of each network
alert kind. Each answer is saved with its case and with which sentences users saw before update 38
(no grounding checks) and see now, in data/advisor/grading/answers.jsonl. Stop it with Ctrl+C and
run it again to carry on. Run it when nobody is using the app: the alerts would wait for Llama.
label: shows each sentence Llama wrote beside its case, without saying whether the validator kept
it:  s = supported by the case,  n = not supported (the case does not say it, true or not),
w = wrong (it contradicts the case, or it is false). Enter skips, b goes back, q stops. Saved at once.
report: per grader, the share of sentences supported, not supported and wrong, for everything Llama
wrote, for what users saw before update 38 and for what they see now; with two graders, how often
they agree (Cohen's kappa). "Now" re-runs today's checks on the saved answers, so a change to the
checks is measured on sentences already graded. --wrong lists the sentences graded w (they come
from the India set and the fixed network samples, not from the team's messages).
"""
import argparse
import hashlib
import json
import os
import re
import sys
import textwrap
import time
from collections import Counter

from advisor.advise import Advisor
from advisor.backends import LlamaServiceBackend, backend_from_env
from advisor.playbooks import get_playbook
from advisor.prompt import build_prompt, case_text, max_new_tokens
from advisor.validator import check_explanation

FOLDER = os.path.join("data", "advisor", "grading")
GRADES = {"s": "supported", "n": "not supported", "w": "wrong"}
HELP = ("s = supported by the case, n = not supported (the case does not say it), w = wrong (contradicts the case "
        "or is false). Enter = skip, b = back, q = stop. Saved at once.")


def read_answers(folder):
    path = os.path.join(folder, "answers.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def india_findings(path, detector):
    from detectors.sms.eval_india import read_test        # .xlsx needs openpyxl; a CSV needs nothing
    df = read_test(path)
    for msg, snd in zip(df.message, df.sender):
        yield detector.check(msg, sender=snd or None)


def different_cases(findings, advisor, limit):
    """(id, finding, playbook, case) for each different case Llama would be shown, up to limit."""
    out, seen = [], set()
    for f in findings:
        if not advisor.needs_llm(f):
            continue
        book = get_playbook(advisor.books, f.category)
        case = case_text(f, book)
        cid = hashlib.sha256(f"{f.source}|{f.language}|{case}".encode()).hexdigest()[:12]
        if cid not in seen:
            seen.add(cid)
            out.append((cid, f, book, case))
        if len(out) >= limit:
            break
    return out


def wait_for_llama(backend, say=print, wait_s=180, step_s=5, sleep=time.sleep):
    """True once the Llama service answers /health. After `systemctl restart ps3-guardian` it loads
    for about a minute; backends without a health check (tests, llama_main) count as ready."""
    health = getattr(backend, "health", None)
    if health is None:
        return True
    for k in range(int(wait_s // step_s) + 1):
        if health().get("ok"):
            return True
        if k == 0:
            say(f"Waiting for the Llama service (it loads for about a minute after a restart), up to {wait_s} s ...")
        sleep(step_s)
    say("The Llama service did not answer: is it running? curl -s http://127.0.0.1:8765/health")
    return False


def generate(findings, advisor, folder=FOLDER, limit=100, say=print, wait_s=180):
    os.makedirs(folder, exist_ok=True)
    done = {a["id"] for a in read_answers(folder)}
    cases = different_cases(findings, advisor, limit)
    todo = [c for c in cases if c[0] not in done]
    say(f"{len(cases)} different cases ({len(cases) - len(todo)} answered before): asking Llama for {len(todo)}.")
    if todo and not wait_for_llama(advisor.backend, say, wait_s):
        return 1
    failures = 0
    with open(os.path.join(folder, "answers.jsonl"), "a", encoding="utf-8") as out:
        for i, (cid, f, book, case) in enumerate(todo, 1):
            t0 = time.time()
            res = advisor.backend.generate(build_prompt(f, book), max_new_tokens=max_new_tokens(f.language, f.source))
            if res.error or not res.text:
                failures += 1
                say(f"[{i}/{len(todo)}] {f.category}: no answer ({res.error or 'empty'})")
                if failures >= 3 and i == failures:
                    say("Three failures in a row: is the Llama service running? curl -s http://127.0.0.1:8765/health")
                    return 1
                continue
            before = check_explanation(res.text, f.verdict, f.language)
            now = check_explanation(res.text, f.verdict, f.language, evidence=case)
            rec = {"id": cid, "source": f.source, "category": f.category, "verdict": f.verdict,
                   "language": f.language, "case": case, "answer": res.text,
                   "sentences": [s for s, _, _ in now.sentences],
                   "shown_before": [k for _, k, _ in before.sentences], "shown_now": [k for _, k, _ in now.sentences],
                   "dropped_now": [why for _, _, why in now.sentences],
                   "rejected_before": not before.ok, "rejected_now": not now.ok,
                   "seconds": round(time.time() - t0, 1), "cached": bool(res.metrics.get("cached"))}
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            say(f"[{i}/{len(todo)}] {f.source} {f.category} ({f.verdict}): {rec['seconds']} s"
                + (" (saved answer)" if rec["cached"] else ""))
    return 0


def grades_path(folder, grader):
    return os.path.join(folder, f"grades_{re.sub(r'[^A-Za-z0-9_-]', '', grader)[:32] or 'grader'}.json")


def load(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=0, sort_keys=True)
    os.replace(tmp, path)


def label(folder, grader, again=False, ask=input, say=print):
    answers, path = read_answers(folder), grades_path(folder, grader)
    grades = load(path)
    items = [(a, i) for a in answers for i in range(len(a["sentences"]))
             if again or str(i) not in grades.get(a["id"], {})]
    if not items:
        say(f"Nothing left to grade for {grader} ({sum(len(a['sentences']) for a in answers)} sentences)."
            + ("" if answers else " Run generate first."))
        return 0
    say(f"{len(items)} sentences to grade, from {len({a['id'] for a, _ in items})} answers.\n{HELP}\n")
    done, k, shown = [], 0, None
    while k < len(items):
        a, i = items[k]
        if a["id"] != shown:
            say(f"--- {a['source'].upper()} alert, {a['verdict']}. What Llama was shown:")
            for line in a["case"].splitlines():
                say("      " + line)
            shown = a["id"]
        say(f"[{k + 1}/{len(items)}] Sentence {i + 1} of {len(a['sentences'])}:")
        for line in textwrap.wrap(a["sentences"][i], 100):
            say("    " + line)
        try:
            answer = ask("grade: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            say("")
            break
        if answer == "q":
            break
        if answer == "b":
            if done:
                k = done.pop()
                prev, j = items[k]
                grades.get(prev["id"], {}).pop(str(j), None)
                save(path, grades)
                shown = None
            continue
        if answer in GRADES:
            grades.setdefault(a["id"], {})[str(i)] = answer
            save(path, grades)
            done.append(k)
        elif answer:
            say("    (s, n, w, Enter, b or q)")
            continue
        k += 1
    n = sum(len(v) for v in grades.values())
    say(f"\n{grader}: {n} sentences graded, saved in {path}.")
    return 0


def _shares(labels):
    c, n = Counter(labels), len(labels)
    return n, [f"{c[g]:4d} ({c[g] / n:4.0%})" if n else "   -" for g in GRADES]


def kappa(pairs):
    """Cohen's kappa of two graders' labels on the same sentences."""
    n = len(pairs)
    if not n:
        return None
    agree = sum(1 for x, y in pairs if x == y) / n
    c1, c2 = Counter(x for x, _ in pairs), Counter(y for _, y in pairs)
    chance = sum(c1[g] * c2[g] for g in GRADES) / (n * n)
    return agree, (agree - chance) / (1 - chance) if chance < 1 else 1.0


def recheck(a):
    """Today's checks re-run on a saved answer: (shown, why not, rejected whole). The saved result
    is kept if the answer no longer splits into the same sentences."""
    c = check_explanation(a["answer"], a["verdict"], a["language"], evidence=a["case"])
    if [s for s, _, _ in c.sentences] != a["sentences"]:
        return a["shown_now"], a["dropped_now"], a["rejected_now"]
    return [k for _, k, _ in c.sentences], [w for _, _, w in c.sentences], not c.ok


SUBSETS = [("everything Llama wrote", lambda a, i: True),
           ("  first sentences", lambda a, i: i == 0),
           ("  second sentences", lambda a, i: i == 1),
           ("shown before update 38", lambda a, i: a["shown_before"][i]),
           ("shown now", lambda a, i: a["now"][i]),
           ("  network alerts", lambda a, i: a["now"][i] and a["source"] == "net"),
           ("  messages", lambda a, i: a["now"][i] and a["source"] != "net"),
           ("dropped by the checks", lambda a, i: a["shown_before"][i] and not a["now"][i])]


def report(folder, say=print, wrong=False):
    answers = read_answers(folder)
    files = sorted(f for f in os.listdir(folder) if f.startswith("grades_") and f.endswith(".json")) \
        if os.path.isdir(folder) else []
    if not answers or not files:
        say("Nothing to report yet: generate, then label (python -m advisor.grade --help).")
        return 1
    for a in answers:
        a["now"], a["why_not"], a["rejected"] = recheck(a)
    n_sent = sum(len(a["sentences"]) for a in answers)
    by = Counter(a["source"] for a in answers)
    say(f"{len(answers)} answers ({', '.join(f'{k} {v}' for k, v in sorted(by.items()))}), {n_sent} sentences; "
        f"answers rejected whole (template shown): before {sum(a['rejected_before'] for a in answers)}, "
        f"now {sum(a['rejected'] for a in answers)}")
    dropped = Counter(re.sub(r" \(.*\)$", "", w) for a in answers for w, b, s in
                      zip(a["why_not"], a["shown_before"], a["now"]) if b and not s)
    if dropped:
        say("Sentences today's checks drop: " + ", ".join(f"{k} {v}" for k, v in dropped.most_common()))
    moved = sum(x != y for a in answers for x, y in zip(a["shown_now"], a["now"]))
    if moved:
        say(f"({moved} sentences are shown or dropped differently from when the answers were saved: "
            "the checks have changed since)")
    all_grades = {}
    for fname in files:
        grader = fname[len("grades_"):-len(".json")]
        g = all_grades[grader] = load(os.path.join(folder, fname))
        say(f"\nGrader {grader}: {sum(len(v) for v in g.values())} of {n_sent} sentences graded")
        say(f"{'':28s} {'sentences':>9s} {'supported':>11s} {'not supported':>13s} {'wrong':>11s}")
        for name, keep in SUBSETS:
            labels = [g[a["id"]][str(i)] for a in answers for i in range(len(a["sentences"]))
                      if str(i) in g.get(a["id"], {}) and keep(a, i)]
            n, cells = _shares(labels)
            say(f"{name:28s} {n:9d} {cells[0]:>11s} {cells[1]:>13s} {cells[2]:>11s}")
    names = sorted(all_grades)
    if len(names) >= 2:
        g1, g2 = all_grades[names[0]], all_grades[names[1]]
        pairs = [(g1[a][i], g2[a][i]) for a in g1 for i in g1[a] if i in g2.get(a, {})]
        k = kappa(pairs)
        if k:
            say(f"\n{names[0]} and {names[1]} graded {len(pairs)} sentences both: they agree on {k[0]:.0%}, "
                f"Cohen's kappa {k[1]:.2f}")
    if wrong:
        say("\nSentences graded wrong (w):")
        for a in answers:
            for i, s in enumerate(a["sentences"]):
                marks = {name: g.get(a["id"], {}).get(str(i)) for name, g in sorted(all_grades.items())}
                if "w" in marks.values():
                    status = "users see it" if a["now"][i] else f"dropped: {a['why_not'][i]}"
                    who = ", ".join(f"{name} {m}" for name, m in marks.items() if m)
                    say(f"- {a['category']} ({who}; {status}): {s}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--india", help="the India test set (.xlsx or .csv)")
    g.add_argument("--net", action="store_true", help="also one sample of each network alert kind")
    g.add_argument("--max", type=int, default=100, help="at most this many different cases")
    lb = sub.add_parser("label")
    lb.add_argument("--grader", required=True, help="your name: each grader gets a file of their own")
    lb.add_argument("--again", action="store_true", help="also show sentences graded before")
    rp = sub.add_parser("report")
    rp.add_argument("--wrong", action="store_true", help="also list the sentences graded w")
    for p in (g, lb, rp):
        p.add_argument("--folder", default=FOLDER)
    a = ap.parse_args(argv)
    if a.cmd == "generate":
        if not a.india and not a.net:
            ap.error("give --india, --net or both")
        from detectors.sms.detector import SmsDetector
        backend = backend_from_env() if os.environ.get("ADVISOR_BACKEND") else LlamaServiceBackend()
        advisor = Advisor(backend=backend)
        findings = []
        if a.net:                                  # first: the samples always fit within --max
            from advisor.warm_cache import net_findings
            findings += net_findings(None)
        if a.india:
            findings += list(india_findings(os.path.expanduser(a.india), SmsDetector()))
        return generate(findings, advisor, a.folder, a.max)
    if a.cmd == "label":
        return label(a.folder, a.grader, a.again)
    return report(a.folder, wrong=a.wrong)


if __name__ == "__main__":
    sys.exit(main())
