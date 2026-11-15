# Are Llama's sentences true? Grounding checks and grading

## Why

Llama explains each alert in two sentences from a short case: the verdict, the scam type, a checked fact, who the message pretends to be and the warning signs ([advisor/prompt.py](../advisor/prompt.py), `case_text`). Until update 38 the answer checker ([advisor/validator.py](../advisor/validator.py)) caught forbidden forms: a link, a phone number, "this is safe". It could not see an invented fact. "13 of 13 accepted by the checker" meant 13 answers passed some patterns, not 13 true answers (the hard review, gap 2.5). A 1B model at 4 bits does invent details: "Genuine companies never ask for bank account details or cashback" appeared with nothing in the case to support it.

## Grounding checks (updates 38 and 38b)

A sentence is dropped when it says more than the case Llama was shown:

| Check | Example dropped |
| --- | --- |
| A number the case does not have (1930, the helpline, is always allowed) | "Act within 24 hours" |
| An organisation the case does not name (the brand list, plus RBI, NPCI, WhatsApp, the police, courts…) | "pretends to be from HDFC Bank" when the case says SBI |
| "never" or "always" (English) when the case does not say it; "No bank … ever asks" says "never" (38b) | "Banks always use .bank.in links" |
| Where the message's link goes, or that .bank.in or .gov.in sites are not real: the case never says where a link goes (38b) | "the link ends in .bank.in, not .com" |
| A rule about what real companies, banks or people do, when the case's fact states no rule (38b) | "Real trusted sources do not ask you to call a number" for a suspicious message |

If both sentences go, the app shows the playbook's template text, as for any rejected answer. If only sentence 2 goes, the app shows the scanner's red flags in its place ([advisor/advise.py](../advisor/advise.py)). `GUARDIAN_GROUNDING=0` in the app's environment switches the checks off.

Every worked example in the prompt must pass the checks against its own case (a test): Llama copies them, and update 38's "never" check dropped the OTP example's own second sentence.

## The first run (15 November 2026)

On the Pi, `generate` asked Llama for 100 different cases: 89 flagged messages from the India set and the 11 network alert samples, 183 sentences. Reading them showed what update 38 got wrong, fixed in 38b:

| Problem | Example | Change in 38b |
| --- | --- | --- |
| The "never" check dropped sentences its case supports | "Real companies never ask for your OTP or PIN" (the fact: "No bank, company or government office ever asks you to share an OTP") | "no … ever" grounds "never": 3 sentences kept again |
| .bank.in turned around | "the link ends in .bank.in, which is a known domain"; "links ending in .bank.in are not real bank websites" | new check: drops 4 sentences, 3 of them shown before |
| Rules about real senders that the case does not state, in answers about suspicious messages (Llama copies the example "Real companies never ask for your OTP") | "Real messages from trusted sources do not ask you to open links or share personal details" | new check: drops 5 sentences, all shown before |
| The case for an IRC alert carried the Telnet fact | (the case, not Llama) | the risky-port fact now fits every risky port |

The job-scam fact also read badly, and Llama copies it word for word: "they do not pay for online tasks that later need a deposit to withdraw earnings". It now reads "no real job asks for a deposit before you can withdraw what you earned" (38c).

In all, 38b shows 163 of the 183 sentences (update 38: 168; before it: 183). Whether each sentence it drops or keeps is right is what the grading by hand measures (below).

Reading also found sentences no word check can catch, for example "Genuine companies never ask for payment or sensitive information via link" (a prize scam: its fact has "never", so the check passes it) and "Real Aadhaar numbers are registered business sender IDs".

## Results (15 November 2026)

One person (Piyush) graded all 183 sentences, not told which ones the checks keep. Then two more passes: a second look at each sentence where an AI pre-check (Claude's grades from reading the answers, made before the 38b checks were written) disagreed, without seeing either grade; and a pass over the sentences Llama wrote word for word, so that each gets one grade. The second look changed 50 of the 183 grades.

| | Grader | AI pre-check |
| --- | --- | --- |
| Everything Llama wrote (183 sentences): supported, not supported, wrong | 64%, 16%, 19% | 79%, 13%, 9% |
| First sentences (100) | 77%, 17%, 6% | 97%, 3%, 0% |
| Second sentences (83) | 49%, 16%, 35% | 57%, 24%, 19% |
| Wrong sentences users saw before update 38 (of 183) | 35 (19%) | 16 (9%) |
| **What users see now (163)**: supported, not supported, wrong | **72%, 17%, 12%** (19 wrong) | 88%, 10%, 2% (3 wrong) |
| Network alerts (16 sentences shown) | all supported | all supported |
| Sentences the checks drop (20) | 16 wrong, 3 not supported, 1 supported | 13 wrong, 6 not supported, 1 supported |

The grader and the AI pre-check agree on 78% of the sentences (Cohen's kappa 0.52, moderate). The grader's first pass, before the second look, agreed with the pre-check on 69% (kappa 0.12, slight).

- **Network alerts:** every sentence Llama wrote is supported by its case, for both.
- **The checks:** of the 20 sentences they drop, 19 are wrong or not supported, for both. They cut the wrong sentences users see from 35 to 19 (grader) or from 16 to 3 (AI pre-check).
- **What users still see:** by the grader, about one sentence in eight is wrong, all in message answers. About half are rules about real companies or banks that the case does not state ("Real companies like Flipkart do not ask for your OTP, PIN, or CVV through links in SMS messages"). A third are first sentences, mostly about who a suspicious message pretends to be ("This message looks like someone pretending to be a trusted person to rush you into opening a link…"): the case says "Pretends to be: someone you might trust", which is the playbook's default when the scanner finds no name. The rest are garbled ("Real Aadhaar numbers are registered business sender IDs") or copy the old job-scam fact, reworded since.
- **Where the two differ:** the grader counts a rule the case does not state as wrong, the pre-check as not supported; and the grader judged those first sentences wrong, the pre-check supported, since the case says them.
- **How far to trust the numbers:** one person graded. The second look raised the agreement from 0.12 to 0.52, but it showed only the sentences where the pre-check disagreed, so 0.52 is not an independent agreement. A second person grading on their own would give one.

## Grading (two people, about an hour each)

On the Pi, from `~/ps3-guardian` with `source ~/ps3-venv/bin/activate`, while the app runs (it keeps the Llama service up):

1. **Generate** the answers, when nobody needs the app for an hour (alerts would wait for Llama):

   ```bash
   python -m advisor.grade generate --india ~/india_sms_collection_v9.xlsx --net
   ```

   It checks the India set's messages, builds the case for each flagged one, and asks Llama once per different case, up to 100, plus one of each network alert kind. After a restart it waits up to 3 minutes for the Llama service to load. Each answer takes 20–30 s; saved answers are instant. Ctrl+C stops it; run it again to carry on. Everything goes to `data/advisor/grading/answers.jsonl`, with which sentences users saw before update 38.

2. **Grade**, each person on their own, before reading anyone else's grades or this page's examples of wrong sentences:

   ```bash
   python -m advisor.grade label --grader piyush
   ```

   Each sentence Llama wrote appears under its case. You are not told whether the checker kept it. `--again` goes through sentences you graded before.

   | Key | Grade |
   | --- | --- |
   | `s` | supported: the case says it |
   | `n` | not supported: the case does not say it (true or not) |
   | `w` | wrong: it contradicts the case, or it is false |

   Enter skips, `b` goes back, `q` stops. Every grade is saved at once and echoed (`-> supported`), so a key pressed for the wrong sentence shows at once: press `b` to fix it.

   **Grade what each sentence says, not where it stands.** A sentence with several claims gets the worst grade among them. For example:

   - "This message pretends to be from HDFC Bank to steal your net-banking login, card details or OTP through a fake KYC page." The case says "Pretends to be: HDFC Bank" and "Scammer wants: to steal your net-banking login, card details or OTP through a fake KYC page": **s**.
   - "Real electricity companies do not ask you to call a personal number or install an app, and they do not rush you with a deadline." The first half is the fact; the case does not say the second: **n**.
   - "Genuine banks do not update KYC on their website, and links ending in .bank.in are not real bank websites." The fact says banks update KYC on their official website and genuine bank links end in .bank.in: **w**.

   **A second look.** An hour of grading brings slips: a key pressed for the wrong sentence, the same sentence graded two ways. When a second grader has finished, each one looks again at the sentences the two graded differently, without seeing either grade:

   ```bash
   python -m advisor.grade label --grader piyush --recheck ravi
   ```

   Keep your grade where you think it is right. With no second person, an AI pre-check of the first run (Claude's grades, `grades_ai-precheck.json`, not in the repo) can be the other grader; say so when you report the numbers.

   Llama often writes the same sentence word for word for one scam type ("This message pretends to be from a trusted source to rush you…"). It should get the same grade each time unless its case makes a difference. To grade again each one you graded in more than one way, each under its own case:

   ```bash
   python -m advisor.grade label --grader piyush --same
   ```

   Both keep your first pass, once, in `firstpass_piyush.json`.

3. **Report**:

   ```bash
   python -m advisor.grade report
   ```

   For each grader: the share of sentences supported, not supported and wrong, for everything Llama wrote (and first and second sentences apart), for what users saw before update 38, for what they see now (network alerts and messages apart), and for the sentences the checks drop. "Now" re-runs today's checks on the saved answers, so a change to the checks is measured on sentences already graded. Then how many sentences Llama wrote word for word for the same scam type the grader graded in more than one way (`--same` lists them), and, for every two graders, how often they agree (Cohen's kappa). A grader's first pass is shown too: how many grades the second look changed, and how the first pass agreed with the other graders. `--wrong` also lists the sentences graded w, and whether users see them. Paste it into the chat for the results.

## Limits

- The case is all Llama sees, so "supported" means supported by the scanner's evidence, not that the scan was right.
- The 38b checks were written after reading these same answers, so how much they help here is the best case. The India set gives only about 104 different cases, so there is no second set of the same kind; the app's own alerts will show it over time.
- The checks look at words, not meaning: a rule is allowed in any case whose fact states a rule, and one supported sentence is still dropped ("real banks never send messages from 10-digit mobile numbers", where the case says "real banks send SMS from registered sender IDs").
- For a message with no name the scanner knows, the case says "Pretends to be: someone you might trust" (the playbook's default), and Llama repeats it as a fact. A case that says no name was found, with a worked example for it, is Phase 2: it changes the prompt, so the answers would have to be made and graded again.
- Graders know the project; a user study with non-experts (do the sentences help people act?) is Phase 2.
- Hindi answers are not in this grading yet: they take about 50 s each.
