# Sender rules: when a registered sender ID should not make a message safe

## Why

A registered sender ID such as `JD-HDFCBK-S` divides the odds of fraud by 50 (`-S`, `-T`, `-G`) or by 10 (`-P`, or no suffix) ([senders.py](../detectors/sms/senders.py)). That is what clears most false alarms on Indian messages. But the code checks only the header's shape, so a scam sent through a registered header gets the same discount (the hard review, gap 2.3). Our own SMS v2 run met one: the scam on phone B came from a registered ID.

## The three rules

Each rule only ever takes away some of the trust a registered ID gives. So it can catch more scams, and it can add false alarms, only on messages from registered IDs.

| Rule | What it does |
| --- | --- |
| `suffix` | Since May 2025 every business header carries `-P`, `-S`, `-T` or `-G`. A header without one gets odds 0.3 instead of 0.1: about the geometric middle of a promotional ID and an unknown sender. |
| `cap` | No sender ID clears a message that **asks you to share or enter** an OTP, PIN, password or card number. Nor one that names a bank, regulator, payment app or government office and carries a link the link checker does not call safe. Such a message stays at least suspicious if its text was. |
| `brand` | A risky message that names a bank, payment app or government office gets no discount from a sender ID that does not look like that organisation's. Risky means: an account threat (blocked, KYC, suspended), a request for a secret or bank details, or a link that is not safe. "Looks like" means the ID's six characters contain one of the roots the team knows for the brand (`SBI` in `SBIINB`, `HDFC` in `HDFCBK`; [brands.py](../detectors/sms/brands.py)). A co-branded message is fine when the ID belongs to any brand it names (Airtel's ID for an "Airtel Axis Bank" card). |

**Asking for a secret is not naming one.** "Your OTP is 4821. Do not share it" and "Enter OTP 4821 to log in" are genuine; "share the OTP with our officer", "send your OTP to 98…", "enter your UPI PIN to receive Rs 5000" are not. The new signal (`asks_for_secret` in [rules_india.py](../detectors/sms/rules_india.py)) tells them apart; the old OTP signal, a model feature, stays as it was.

**Not done yet:** the review's check against TRAI's full list of registered headers (an unregistered header gets no discount and a red flag). It needs the list from TRAI's Header Information Portal, which has to be downloaded in a browser. With it, the brand rule would use each header's real owner instead of the roots.

## Measure first, then switch on

Nothing changes in the app until a rule is switched on in `data/sms/sender_rules.json`. The measurement scores every message from a registered ID as the app does, without the rules and with each rule alone:

- the India set's messages from registered IDs (labelled, never trained on);
- the team's messages from registered IDs in the Pi's log, labelled or not (the log keeps all of them).

**The rule, set before measuring:** a sender rule goes live only if, alone, it flags no more labelled genuine messages (marketing or normal) than the app does without it.

On the Pi:

```bash
cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
python detectors/sms/eval_senders.py --india ~/india_sms_collection_v9.xlsx
```

It prints, for each rule, the genuine messages flagged, the scams caught and the not-labelled messages flagged, then which rules pass. Then:

- `--show` lists the messages a rule changes, to read on the Pi (they are the team's messages: share only the counts).
- `--apply` switches on the rules that pass. Restart the app: `sudo systemctl restart ps3-guardian`. `curl -s http://127.0.0.1:8000/health` then shows them under `sender_rules`.
- To switch them off: `rm data/sms/sender_rules.json`, then restart.

Labelling more of the team's messages from registered IDs (`python scripts/sms_traffic.py label --device A`) makes the measurement stronger: a rule is judged on labelled messages only.

## A dry run on the India set

In the cloud, with v1 trained on the public data as on the Pi, on the India set's 35 genuine messages from registered IDs (no team messages):

| Rule | Genuine flagged (of 35) | Passes |
| --- | --- | --- |
| none (today) | 6 | |
| `suffix` | 13 (+7) | no |
| `cap` | 6 | yes |
| `brand` | 6 | yes |

The 7 extra are names typed into the sheet that have the shape of a six-letter header without a suffix ("Airtel", "Travel", "swiggy"). Real messages carry real headers; the Pi's run decides.
