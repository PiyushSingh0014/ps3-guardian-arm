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

1. Build an India test set: about 100 real messages with sender IDs, never used for training. Report results on it separately.
2. Train a 3-class model (ham / spam / smishing) with a scam-type output that replaces the keyword `categorize.py`.
3. Run a cross-source test: `--holdout-source` trains on one dataset and tests on the other.
4. Fine-tune a small multilingual encoder, export it to ExecuTorch as INT8, and compare it with this baseline.

## Reproduce

```bash
python detectors/sms/train_baseline.py --data merged_sms.csv --show-errors 15
```
