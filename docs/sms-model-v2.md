# SMS model v2: learning from the team's own messages

## Why

SMS model v1 learned from two public datasets and knows two classes, threat or normal. On the 227 real Indian messages of the India test set ([eval/results_sms.md](../eval/results_sms.md)) it catches 94% of the scams on the text alone, but:

- it flags 96% of genuine marketing, because marketing counts as a threat;
- it flags 64% of normal messages: OTPs, bank alerts, deliveries. The public data has almost no Indian transactional messages, so the model learned that money, links and bank words mean a scam.

The sender ID fixes much of this in the app, but not everything: marketing from registered senders is still flagged, and chats and pasted messages have no sender ID.

v2 changes two things:

1. **Three classes:** fraud, marketing and normal.
2. **The team's own messages:** the SMS the phones sent to the Pi (logs/sms_traffic.jsonl), labelled by hand. They teach the model Indian bank alerts, OTPs, deliveries and offers.

The features stay those of v1: character n-grams and the India red-flag rules, with a logistic regression. Training takes seconds, and checking a message still takes milliseconds.

## How the app decides with v2

In India, only a registered sender ID (`JD-HDFCBK-P`) may send marketing (TRAI's DLT rules, [senders.py](../detectors/sms/senders.py)). So v2 trusts the "marketing" reading only for those:

| Who sent it | The score the decision starts from |
| --- | --- |
| A registered sender ID | the chance of **fraud**: an offer is just an offer |
| A phone number, a chat, or an unknown sender | the chance of **fraud or marketing**, as in v1: a genuine business does not send offers from a personal number |

Then the sender's odds and the links change the score exactly as before. The code is `model_score` in [detector.py](../detectors/sms/detector.py).

Digits: the Pi's log writes `#` for every digit. For training, each `#` in a team message becomes a random digit, the same on every run. An OTP or an amount says nothing by its value, and the app always sees real digits.

## How the design was chosen (before any team message)

Two first ideas were measured on the public data and the India set. No team message was used.

| Design | India set, flagged as the app decides: fraud | marketing | normal |
| --- | --- | --- | --- |
| v1, trained again on the same public messages | 96% | 60% | 61% |
| Three classes, the chance of fraud for every sender | 71% | 23% | 15% |
| Three classes, every digit read as 7, the rule above | 94% | 52% | 65% |
| **Three classes, digits as written, the rule above (v2)** | **96%** | **58%** | **61%** |

- **The chance of fraud for every sender** missed a quarter of the scams: many Indian scams read like offers (loans, jobs, prizes). Hence the rule above.
- **Reading every digit as 7** was meant to match the log's `#`. It made a 6-digit OTP look like the long premium-rate phone numbers of the public data's spam, so more normal messages were flagged.
- **With the public data alone, three classes change almost nothing.** Most of the India set's genuine messages have a sender typed by hand, which is not a registered ID, so they get v1's treatment. The team's messages, with real sender IDs, are what v2 adds.

These choices were made after looking at the India set, so it is no longer an untouched test of them. The clean tests are the team's messages: the 30% held out, and each phone held out in turn.

## On the Pi

**1. Apply the update** (as usual). Laptop, PowerShell:

```powershell
scp $HOME\Downloads\ps3-guardian-update33.bundle arrehinus@10.42.0.1:~/
scp $HOME\Downloads\india_sms_collection_v9.xlsx arrehinus@10.42.0.1:~/
```

Pi:

```bash
cd ~/ps3-guardian
git pull --no-rebase --no-edit ~/ps3-guardian-update33.bundle step3
git push origin step3 step3:main
source ~/ps3-venv/bin/activate
pip install openpyxl          # reads the India set (.xlsx); nothing happens if it is already there
```

**2. Label.** Each person labels their own phone's messages, because they know best whether a message really came from their bank:

```bash
python scripts/sms_traffic.py label --device B
```

- For each message: `f` fraud, `m` genuine marketing, `n` normal, Enter if you are not sure (skipped), `u` to undo the last one, `q` to stop.
- The same message from the same sender (digits aside, for example every OTP from one bank) is asked once and labelled for all its copies.
- Labels are saved at once in `data/sms/labels.json`. Run the command again to carry on where you stopped.
- The phone name is the one typed in the app, and capitals count. A wrong name prints the names in the log.
- Then `--device C`, and the first phone (its name, for example `A`).

**3. Measure v1 on the real traffic** (what the app decided when the messages came in):

```bash
python scripts/sms_traffic.py measure
```

**4. Compare v1 and v2:**

```bash
python detectors/sms/train_v2.py --public ~/merged_sms.csv --india ~/india_sms_collection_v9.xlsx
```

It prints the data it used, then the share of each class flagged by three models, on the text alone and as the app decides (sender and links):

- `v1`: two classes, public data only (what the app uses now)
- `3-class`: three classes, public data only
- `v2`: three classes, public and team data

| Table | What it tests |
| --- | --- |
| Team messages held out | 30% of the team's messages, never trained on |
| India test set | the 227 messages; copies and near-copies of them never train |
| Public messages held out | the public data; v2 must not get worse here |
| Phone B, Phone C, … | each phone held out in turn: v2 learns from the other phones only, as for a new user's phone |

It takes a minute or two on the Pi. Paste the whole output into the chat.

**5. Decide.** The rule, set before seeing the results. Use v2 only if, as the app decides:

- on the India set, it catches at least as many of the 100 scams as v1, give or take 2;
- on each phone held out in turn, it flags fewer normal and marketing messages than v1, and misses no more of that phone's scams.

Otherwise the app keeps v1, and v2's numbers go in the report anyway.

**6. If v2 passes, save it and restart:**

```bash
python detectors/sms/train_v2.py --public ~/merged_sms.csv --india ~/india_sms_collection_v9.xlsx --save
sudo systemctl restart ps3-guardian
curl -s http://localhost:8000/health
```

`--save` trains v2 again on all the messages (still never on the India set) and writes `detectors/sms/sms_v2.joblib`. The app loads it at start: `/health` shows `"sms_model": "v2 (sms_v2.joblib)"`.

**To go back to v1:** `rm detectors/sms/sms_v2.joblib`, then `sudo systemctl restart ps3-guardian`.

## Privacy

- The messages and labels stay on the Pi: `logs/` and `data/` are not in git.
- `sms_v2.joblib` is not in git either (`*.joblib`). It holds no messages, but its vocabulary has pieces of words, up to 5 characters, taken from them.
- Only the printed tables (counts and percentages) leave the Pi.
- When the project ends, delete `logs/sms_traffic.jsonl`, `data/sms/labels.json` and `detectors/sms/sms_v2.joblib`.

## Limits

- **Same phones, same templates:** the 30% held out comes from the phones v2 learned from, often the same banks' templates. The per-phone tables are the fairer test.
- **Few team scams:** most of the team's messages are genuine. The India set's 100 scams remain the main test of catching fraud.
- **No ordinary personal SMS from the team:** the Pi does not keep the text of safe messages from phone numbers. The public data covers personal chat.
- **Masked digits:** a `#` cannot tell a toll-free `1800` from any other number.
- **Labels by one person per phone,** without a second opinion.
