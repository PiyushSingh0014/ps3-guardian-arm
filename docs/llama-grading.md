# Are Llama's sentences true? Grounding checks and grading

## Why

Llama explains each alert in two sentences from a short case: the verdict, the scam type, a checked fact, who the message pretends to be and the warning signs ([advisor/prompt.py](../advisor/prompt.py), `case_text`). Until update 38 the answer checker ([advisor/validator.py](../advisor/validator.py)) caught forbidden forms: a link, a phone number, "this is safe". It could not see an invented fact. "13 of 13 accepted by the checker" meant 13 answers passed some patterns, not 13 true answers (the hard review, gap 2.5). A 1B model at 4 bits does invent details: "Genuine companies never ask for bank account details or cashback" appeared with nothing in the case to support it.

## Grounding checks (update 38)

A sentence is dropped when it says more than the case Llama was shown:

| Check | Example dropped |
| --- | --- |
| A number the case does not have (1930, the helpline, is always allowed) | "Act within 24 hours" |
| An organisation the case does not name (the brand list, plus RBI, NPCI, WhatsApp, the police, courts…) | "pretends to be from HDFC Bank" when the case says SBI |
| "never" or "always" (English) when the case does not use the word | "Banks always use .bank.in links" |

If both sentences go, the app shows the playbook's template text, as for any rejected answer. `GUARDIAN_GROUNDING=0` in the app's environment switches the checks off.

## Grading (two people, about an hour each)

On the Pi, from `~/ps3-guardian` with `source ~/ps3-venv/bin/activate`, while the app runs (it keeps the Llama service up):

1. **Generate** the answers, when nobody needs the app for an hour (alerts would wait for Llama):

   ```bash
   python -m advisor.grade generate --india ~/india_sms_collection_v9.xlsx --net
   ```

   It checks the India set's messages, builds the case for each flagged one, and asks Llama once per different case, up to 100, plus one of each network alert kind. Each answer takes 20–30 s; saved answers are instant. Ctrl+C stops it; run it again to carry on. Everything goes to `data/advisor/grading/answers.jsonl`, with which sentences users saw before update 38 and see now.

2. **Grade**, each person on their own:

   ```bash
   python -m advisor.grade label --grader piyush
   ```

   Each sentence Llama wrote appears under its case. You are not told whether the checker kept it.

   | Key | Grade |
   | --- | --- |
   | `s` | supported: the case says it |
   | `n` | not supported: the case does not say it (true or not) |
   | `w` | wrong: it contradicts the case, or it is false |

   Enter skips, `b` goes back, `q` stops; every grade is saved at once.

3. **Report**:

   ```bash
   python -m advisor.grade report
   ```

   For each grader: the share of sentences supported, not supported and wrong, for everything Llama wrote, for what users saw before update 38, for what they see now, and for the sentences the new checks drop. With two graders, how often they agree (Cohen's kappa). Paste it into the chat for the results.

## Limits

- The case is all Llama sees, so "supported" means supported by the scanner's evidence, not that the scan was right.
- Graders know the project; a user study with non-experts (do the sentences help people act?) is Phase 2.
- Hindi answers are not in this grading yet: they take about 50 s each.
