# SMS scam detector: baseline results (Track A)

Measured 2026-10-22 with `detectors/sms/train_baseline.py` v2.1.

## Model

- Text features: TF-IDF over character n-grams inside words (`char_wb`, 2–5 characters, 20,000 features).
- Rule features: 11 India-specific signals from `rules_india.py`:
  - link, link shortener, `.apk` file
  - OTP/PIN/CVV/password words, UPI ID
  - urgency, money amount, bank words, prize/refund words
  - bank message whose link is not on `.bank.in`
  - sender is a 10-digit mobile number
- Classifier: logistic regression with balanced class weights.
- Verdicts: score ≥ 0.5 is *suspicious*, ≥ 0.8 is *dangerous*.

## Data

Two public datasets, merged: the UCI SMS Spam Collection, and the Mishra & Soni SMS phishing dataset (ham / spam / smishing). Anything that is not *ham* counts as a threat.

| Step | Messages |
| --- | --- |
| Merged rows | 11,543 |
| After cleaning and de-duplication (v2.1) | 6,053 unique |
| Held-out test set (30%, stratified) | 1,816 (1,498 normal, 318 threats) |

What the cleaning does:

- Reads files as UTF-8 first, repairs garbled characters (`ftfy`) and decodes HTML entities.
- Removes dataset artefacts such as UCI's `<#>` number placeholder.
- Removes duplicates, plus the texts the two datasets label differently.

## Results (held-out 30%)

| Metric | Value |
| --- | --- |
| Threat precision | 0.941 |
| Threat recall | 0.959 |
| Threat F1 | 0.950 |
| False alarms | 19 of 1,498 normal messages = 1.27% (about 13 per 1,000) |
| Missed threats | 13 of 318 = 4.1% |

Confusion matrix (rows = true, columns = predicted):

| | predicted normal | predicted threat |
| --- | --- | --- |
| **normal** | 1,479 | 19 |
| **threat** | 13 | 305 |

### Why the first score (F1 0.98) was too high

The first run, without de-duplication, scored F1 0.98 on the merged 11,543 rows. The two datasets share thousands of identical messages, so the same text landed in both training and test, and the score mostly measured memory. After removing duplicates (v2), F1 was 0.954. After the encoding fixes (v2.1), it was 0.950. **0.950 is the number to report.**

## Error analysis (from `--show-errors`)

- **Label noise:** a few messages labelled spam look normal, and the reverse.
- **Domain mismatch:** UK premium-rate SMS content dominates the old spam class. Indian scams look different.
- **False alarms:**
  - formal Indian English and ordinary talk about money or banks
  - genuine bank alerts

  The sender header (for example `AD-SBIBNK-S`) is what separates genuine bank alerts, and these datasets have no sender field.
- **Missed threats:** lures with no link that ask the reader to reply or call.

## Next

1. Build an India test set: about 100 real messages with sender IDs, never used for training. Report results on it separately. (Done: see "India test set" below.)
2. Train a 3-class model (ham / spam / smishing) with a scam-type output that replaces the keyword `categorize.py`.
3. Run a cross-source test: `--holdout-source` trains on one dataset and tests on the other.
4. Fine-tune a small multilingual encoder, export it to ExecuTorch as INT8, and compare it with this baseline.

## Reproduce

```bash
python detectors/sms/train_baseline.py --data merged_sms.csv --show-errors 15
```

## India test set (2026-10-25)

227 real messages, never used for training: 100 fraud, 52 genuine marketing, 75 normal. 22 are in Hindi or Hinglish. None of them appears in the training data.

- Fraud:
  - 12 from the team's inboxes
  - 8 quoted word for word in Indian fact-checks (PIB Fact Check and others)
  - 80 picked by hand from the Fishing for Smishing dataset (Agarwal, Papasavva, Suarez-Tangil and Vasek, IMC 2025, CC BY 4.0): reports of scam SMS sent from Indian mobile numbers, 2017–2023
- Marketing and normal messages: the team's own phones, anonymised.

Measured with `detectors/sms/eval_india.py`: the app's model (same training data, cleaning and split as above) and the app's verdict rules.

| | Messages | Flagged (suspicious or dangerous) | Dangerous |
| --- | --- | --- | --- |
| Fraud | 100 | 94 (94%) | 69 |
| Marketing | 52 | 50 (96%) | 36 |
| Normal | 75 | 48 (64%) | 25 |

Normal messages flagged, by kind:

| Kind | Flagged |
| --- | --- |
| Delivery updates | 6 of 6 |
| Government notices | 7 of 8 |
| Bank alerts | 7 of 9 |
| Service alerts (recharges, bookings, payments) | 12 of 15 |
| OTPs | 15 of 24 |
| Personal chats | 1 of 13 |

A model trained on 100% of the training data gives almost the same result: 95 fraud, 49 marketing and 51 normal messages flagged.

### What this shows

- **Catching fraud carries over to India.** 94 of 100 real Indian scams are flagged. None of the 6 misses has a link:
  - a Hindi prize message
  - a "PM yojana" benefit
  - two loan messages
  - a dating lure
  - a work-from-home job
- **Avoiding false alarms does not.** 64% of normal Indian messages are flagged, against 1.3% on the public test. Personal chats are fine, but almost every transactional message is flagged: OTPs, bank alerts, deliveries, recharges and government notices.
- **Why:** in the public training data, normal messages are mostly personal chat.
  - It has no OTP messages at all.
  - Most messages with bank words are labelled threats (76%), and so are most with delivery words (82%), a link (94%) or an amount of money (95%).
  - So the model learned that a transactional message is a threat, and Indian inboxes are mostly transactional.
- **Marketing is flagged as a threat (96%)** because the model has only two classes.

### With the sender (2026-10-25)

Sender-aware scoring (`detectors/sms/senders.py`, used by the app and by `eval_india.py`) multiplies the odds of fraud:

- by 0.02 for a registered sender ID ending in `-S`, `-T` or `-G` (service, transactional, government)
- by 0.1 for one ending in `-P` (promotional) or with no suffix
- by 4 for a mobile number, when the message has a link, money, urgency, bank words or OTP talk

An `.apk` link stays dangerous whoever sends it. The multipliers come from TRAI's sender-ID rules and were set before this test, not fitted to it.

| Flagged | Messages | Text only | With the senders in the sheet | Projection: genuine messages carry their registered sender ID |
| --- | --- | --- | --- | --- |
| Fraud | 100 | 94 | 96 | 96 |
| Marketing | 52 | 50 | 35 | 21 |
| Normal | 75 | 48 (64%) | 44 (59%) | 3 (4%) |

- **Senders in the sheet:**
  - The 77 dataset scams come from Indian mobile numbers, and the chats from a saved contact.
  - 6 inbox messages came from phone numbers copied from the phone.
  - Most business messages have a name typed by hand (for example "HDFC bank"). The scoring does not trust names, because anyone can type one.
  - Senders copied from the message text were removed (the number to call, the user's own number).
- **The projection** gives each genuine business message the sender ID that TRAI rules require: `-T` for bank alerts and OTPs, `-S` for other services, `-G` for government, `-P` for marketing. Everything else stays as measured. It is an assumption, not a measurement.
  - With IDs that have no suffix (older IDs such as `AX-HDFCBK`), 17 normal messages stay flagged.
  - If the 4 genuine messages that came from mobile numbers keep them, 6 normal messages stay flagged.
- **Still missed:** 4 frauds that have no link and nothing the rules recognise as money or urgency: a Hindi prize message, an MSME loan reference, a "PM yojana" benefit and a dating lure.
- **Still flagged in the projection:**
  - the Canara merchant notice (score 0.99, 0.64 with the sender)
  - the cash-on-delivery Flipkart delivery (0.98 → 0.55)
  - a one-word chat ("congratulations…")

### What this means

- **The sender ID fixes the false alarms.** With it, the share of normal Indian messages flagged drops from 64% to about 4–8% (up to 23% with suffix-less IDs), and slightly more fraud is caught.
- **It has to be the real ID** (`JD-HDFCBK-S`), not a name. Typed names do not help, and a made-up number makes a genuine message look like a scam.
- **So the app should read the sender ID itself.** An Android app gets it with every incoming SMS. In the web demo, type the ID exactly as the phone shows it.

### First real SMS through the Android companion (2026-10-25)

The companion app (`android/`, [docs/android-companion.md](../docs/android-companion.md)) now runs on a Galaxy S25 and sends each incoming SMS with its raw sender ID to the Pi. From the Pi's traffic log, digits masked:

| Sender | Message | Text only | With the sender ID |
| --- | --- | --- | --- |
| `AE-AIRTEL-S` | "Pack Valid till ## Oct ####. SMS cost:Rs#.## Bal:Rs.#.##. Unlimited data and calls …" | 0.856, dangerous | **0.106, safe** |

This is the false alarm the projection above predicts away, now on a real message: a genuine operator notice with an amount of money looks like a scam on its text alone, and its `-S` sender ID clears it. One message is an example, not a measurement; the week of real traffic (Part E of the guide) gives the numbers.

### With the links checked (update 9, 2026-10-25)

The phishing link checker ([docs/url-detector.md](../docs/url-detector.md)) now checks every link in a message and adjusts the score after the sender:

- a link that is dangerous on its own (an `.apk`, a reported phishing site, a brand's name on someone else's site) makes the message dangerous;
- otherwise the worst link multiplies the odds by 3 (dangerous) or 1.5 (suspicious), and links that are all official divide them by about 3.

| Flagged | Messages | Text only | With sender | Sender + links |
| --- | --- | --- | --- | --- |
| Fraud | 100 | 94 | 96 | 96 |
| Marketing | 52 | 50 | 35 | 30 |
| Normal | 75 | 48 | 44 | 44 |

Five Airtel offers with links on Airtel's own sites turned safe, and four messages with official links went from dangerous to suspicious. Two went the other way (`gs.im`, `weurl.co`). No fraud changed: the real scam links in this set are short random domains such as `po9.in`, which look like the link domains genuine marketing uses, and the 36 anonymised ones (`*.example`) are skipped. Details: [eval/results_url.md](results_url.md).

### Next

1. **Measure on real traffic:** about a week of SMS through the companion, labelled by hand, with `scripts/sms_traffic.py measure`.
2. **Real Indian normal messages in training.** OTPs, bank alerts and delivery updates from business sender IDs, taken from phones other than the test set's and anonymised. This helps when the sender is unknown.
3. **Three classes** (fraud, marketing, normal), so the app can show marketing as low-risk.

```bash
python detectors/sms/eval_india.py --train merged_sms.csv --test india_sms_collection_v9.xlsx --show 20
```
