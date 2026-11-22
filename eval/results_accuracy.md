# Accuracy test (update 49, 22 November 2026)

How often Sajag is right about scam and normal messages, measured on labelled messages it was not
built from, with the code the phone runs. Four parts:

| Part | What | Where | Status |
| --- | --- | --- | --- |
| A | Labelled message sets: real Indian scam reports, public held-out messages, the India test set | `scripts/accuracy_test.py`, in the cloud (the phone's model and rules) | **done**, below |
| B | Your phones' real messages, as the app decided at the time | `scripts/sms_traffic.py label --flagged`, then `measure`, on the Pi | **done**, below |
| C | Llama's explanations: prompt v5 against v4, on the same cases | `advisor/grade.py --match / --compare`, on the Pi | moved to Phase 2: the answers to 87 cases are generated, not graded yet |
| D | The whole app on the Galaxy S25: alert, title, the message's sender and time | 20 messages from another phone, 4 again with the Wi-Fi off | **done**, below |

## A. Labelled message sets

Run with the phone's SMS model (v1, trained on 70% of `merged_sms.csv`), the sender rules the app
has on (`cap`, `brand`) and the link checker without a phishing list, as on the phone. The phone's
Kotlin code gives the same verdict as this Python code on all 16,272 comparison messages
([phone-guard.md](../docs/phone-guard.md)), so these are the phone's numbers. Flagged = suspicious
or dangerous: the app shows an alert. In brackets: the share and its 95% interval (Wilson). Two
runs gave the same numbers.

| Set | What it is | Scams flagged | Normal flagged (false alarms) |
| --- | --- | --- | --- |
| **Fishing for Smishing, India** | 859 scam campaigns reported by the public from Indian mobile numbers (one message per campaign). Never used to build Sajag: the 80 messages of this dataset in the India test set, and anything like them, are left out | **755 of 859 (87.9%, 86–90%)** | – (no normal messages) |
| Public, held out | the 1,816 messages of `merged_sms.csv` the model never trained on (UCI SMS Spam Collection, Mishra & Soni); no sender | 304 of 318 (95.6%, 93–97%) | 18 of 1,498 (1.2%, 1–2%) |
| India test set | 227 real Indian messages with sender names typed into the sheet. Used while building the rules, so not an untouched test | 96 of 100 (96.0%, 90–98%) | 44 of 75 (58.7%, 47–69%) |

**Scams.** On real Indian scams Sajag had never seen, it flags 88%: 97% of banking scams (456),
93% of telecom (SIM) scams (145), all 11 delivery scams, 70% of government scams (20) and 68% of
"others" (223: job and task offers, investment, prize and "hi, I am…" openers). It misses the
"wrong number" openers (0 of 4). With the link left out (the reports hide links), it still flags
86.3%. Most misses carry no link, no money and no deadline: "Hey there! I am using WhatsApp.",
"Hi, I'm Rahul, Project Manager at …", a loan "request accepted, check your loan amount", or a
"free laptop" registration. Some reports are not scams at all (a Google verification code).

**Normal messages.** On the public held-out set, 1.2% of normal messages are flagged. On the India
test set it is 59%, because the sheet's senders are typed names: by sender, normal messages from
a real registered sender ID (`AX-HDFCBK-S` and the like) were flagged 1 of 10, but those with a
typed name ("Airtel", "HDFC Bank") 38 of 47. The phone reads the real sender ID of every SMS, so
the number that counts is the real traffic (part B).

| India test set, by sender | Scams flagged | Normal flagged | Marketing flagged |
| --- | --- | --- | --- |
| Mobile number | 73 of 77 | 4 of 17 | 1 of 1 |
| Registered sender ID | – | 1 of 10 | 5 of 25 |
| Other name (typed) | 8 of 8 | 38 of 47 | 24 of 26 |
| None | 15 of 15 | 1 of 1 | – |

**Does the alert name the right kind of scam?** Of the 96 caught India scams, the title names the
right kind for 52 (54%), a general one ("Suspicious message", "Phishing link") for 29 (30%), and
the wrong kind for 15 (16%). Most wrong titles say "Fake bank KYC message" because a bank is named:
credit-card reward points (4), bank messages that push an app (4), SIM-card scams (2). Sajag has
no title of its own for SIM-card, loan or investment scams. This is the next thing to fix
(Phase 2: a scam-type model trained on labelled types); nothing was changed before the test.

**What the message says (prompt v5).** 89.6% of the caught India scams and 88.2% of the caught
Indian scam reports get at least one fixed phrase of what the message says for Llama.

**Speed.** 1.1–1.2 ms per message in the cloud (median); 2–11 ms on the Galaxy S25 (update 43).

Reproduce (the Fishing for Smishing CSV is `dataset/final_dataset_output.csv` in
github.com/reportsmishing/Smishing-Dataset-IMC25, CC BY 4.0):

    python scripts/accuracy_test.py --india ~/india_sms_collection_v9.xlsx --public ~/merged_sms.csv \
        --smishing ~/final_dataset_output.csv --out eval/results_accuracy_run.md

## B. Your phones' real messages

On the Pi, 22 November: `label --flagged` (every flagged message labelled except 14), then `measure`. The log holds
what the app decided for each message the team's four phones forwarded; nothing is re-scored. 3,126 messages (phone A
2,089, B 514, C 502, unnamed 21), 524 labelled. Texts of SMS from phone numbers and of chats are kept only when flagged,
so their missed scams cannot be counted; every SMS from a registered sender ID is kept.

| Sender | Received | Flagged | Flagged: scam / marketing / normal | Normal messages flagged per 100 received |
| --- | --- | --- | --- | --- |
| SMS from a registered sender ID | 327 | 44 | 4 / 25 / 14 (1 not labelled) | **4.3** |
| SMS from a phone number | 17 | 12 | 3 / 1 / 8 | 47.1 |
| Chat from an unknown number | 58 | 8 | 1 / 2 / 5 | 8.6 |
| Chat from a saved contact (testing switch) | 2,723 | 243 | 50 / 61 / 119 (13 not labelled) | 4.4 |
| All (with 1 SMS from a short code) | 3,126 | 307 | 58 / 89 / 146 (14 not labelled) | **4.7** (at most 5.1) |

- **False alarms on real messages: 4.3 normal SMS per 100 from registered sender IDs** (14 of 327; at most 4.6 if the
  one unlabelled flagged SMS is normal), and 4.7 per 100 over all 3,126 messages (at most 5.1). Before the labelling it
  was a range of 0.9 to 7.9.
- **Scams from registered sender IDs:** 4 flagged, 1 missed (the fantasy-league offer found on 14 November).
- **The sender ID, on real SMS** (labelled SMS, as the app decided against the text alone): normal messages flagged 15%
  instead of 94%, marketing 19% instead of 87%, scams 88% (7 of 8) instead of 100%.
- **Most false alarms are group chats** seen through the testing switch: college and placement-cell notices with links,
  shared PDFs and links to sign-in pages; and personal SMS from phone numbers that carry a link or a number (a personal
  number with a link is weighed as risky on purpose).

## C. Llama's explanations, v5 against v4

Moved to Phase 2. On 22 November the Pi found 87 of the 89 cases graded with prompt v4 again and generated
prompt v5's answers to them (`data/advisor/grading-v5`, 154 sentences); they will be graded in Phase 2. Until then the
explanation numbers are prompt v4's ([docs/llama-grading.md](../docs/llama-grading.md)).

## D. Live test on the phone

22 November, Sajag 3.2 on the Galaxy S25. The 20 test messages of [docs/accuracy-test.md](../docs/accuracy-test.md)
were sent from a second phone as WhatsApp messages from a saved contact (the testing switch on), so they went through
the chat path, judged on their text and links. Round 1 with the S25 on the hub's Wi-Fi, round 2 with its Wi-Fi off.

| Round | Messages | Result |
| --- | --- | --- |
| 1 (hub's Wi-Fi) | 11 scams | **11 flagged**: 9 dangerous, 2 suspicious (the electricity cut-off and the "CBI officer"); the title names the right kind for 9; the SIM-card and the reward-point scams were titled "Fake bank KYC message" (the gap found in part A) |
| 1 | 9 normal messages | **8 safe**, no alert; 1 suspicious: "Mom, I paid the electricity bill today, Rs 1,240", the hard case on the list |
| 2 (Wi-Fi off) | 4 scams again (1, 2, 4, 10) | **4 of 4 alerted again**, with the same verdicts: the phone alone, and a message sent twice gets two alerts (app 3.2) |

- Every notification named the sender, the start of the message and the time it arrived, so the alerts that came
  together could be told apart.
- The Hindi KYC scam was flagged dangerous in both rounds with the right title; the job, parcel, prize, app-install and
  OTP-cashback scams got their own titles.
- During the test, two real bank debit SMS received by the S25 ("Rs.… Dr. from A/C XXXXXX… and Cr. to …") were flagged
  suspicious: real false alarms of the kind part B counts.
- Llama's explanation screens were not captured in this run; the speed of Llama on the S25 (3.6 s per explanation) was
  measured on 22 November (update 45).

## Full output of part A

Run 2026-11-22 03:33 on x86_64, Python 3.13.17. SMS model v1 (sms_baseline.joblib); sender rules cap, brand; link checker without a phishing list, as on the phone.

Flagged = the app says suspicious or dangerous and shows an alert. In brackets: the share and its 95% interval.

| Set | Messages | Scams flagged | Normal flagged (false alarms) | Marketing flagged |
| --- | --- | --- | --- | --- |
| India test set (typed sender IDs) | 227 | 96 of 100 (96.0%, 90–98%) | 44 of 75 (58.7%, 47–69%) | 30 of 52 (57.7%, 44–70%) |
| Public, held out (no sender) | 1816 | 304 of 318 (95.6%, 93–97%) | 18 of 1498 (1.2%, 1–2%) | – |
| Fishing for Smishing, India (one per campaign) | 905 | 755 of 859 (87.9%, 86–90%) | – | 36 of 46 (78.3%, 64–88%) (spam) |

Time per message on this machine: median 1.1 ms, 95th percentile 2.0 ms (3,853 checks).

### India test set

| Label | Messages | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| scam | 100 | 4 | 22 | 74 |
| marketing | 52 | 22 | 5 | 25 |
| normal | 75 | 31 | 21 | 23 |

Scams by type:

| Type | Flagged |
| --- | --- |
| bank_kyc | 21 of 21 (100.0%, 85–100%) |
| utility_disconnection | 15 of 15 (100.0%, 80–100%) |
| lottery_reward | 14 of 15 (93.3%, 70–99%) |
| fake_offer | 9 of 10 (90.0%, 60–98%) |
| other_scam | 8 of 9 (88.9%, 56–98%) |
| loan_app | 8 of 9 (88.9%, 56–98%) |
| job_task | 9 of 9 (100.0%, 70–100%) |
| apk_link | 7 of 7 (100.0%, 65–100%) |
| investment_trading | 3 of 3 (100.0%, 44–100%) |
| delivery_fee | 2 of 2 (100.0%, 34–100%) |

Normal messages flagged, by type:

| Type | Flagged |
| --- | --- |
| otp_code | 15 of 24 (62.5%, 43–79%) |
| service_alert | 8 of 15 (53.3%, 30–75%) |
| personal_chat | 1 of 13 (7.7%, 1–33%) |
| bank_alert | 7 of 9 (77.8%, 45–94%) |
| govt_alert | 7 of 8 (87.5%, 53–98%) |
| delivery_update | 6 of 6 (100.0%, 61–100%) |

By sender (typed in the sheet):

| Sender | Scams flagged | Normal flagged | Marketing flagged |
| --- | --- | --- | --- |
| mobile_number | 73 of 77 (94.8%, 87–98%) | 4 of 17 (23.5%, 10–47%) | 1 of 1 (100.0%, 21–100%) |
| other | 8 of 8 (100.0%, 68–100%) | 38 of 47 (80.9%, 67–90%) | 24 of 26 (92.3%, 76–98%) |
| registered_sender_id | – | 1 of 10 (10.0%, 2–40%) | 5 of 25 (20.0%, 9–39%) |
| unknown | 15 of 15 (100.0%, 80–100%) | 1 of 1 (100.0%, 21–100%) | – |

Does the alert name the right kind of scam? (caught scams with a known type)

| Title | Alerts |
| --- | --- |
| Right | 52 of 96 (54.2%, 44–64%) |
| General ("Suspicious message", "Phishing link") | 29 of 96 (30.2%, 22–40%) |
| Wrong kind | 15 of 96 (15.6%, 10–24%) |

Wrong kinds: lottery_reward named bank_kyc_scam (4); apk_link named bank_kyc_scam (4); utility_disconnection named bank_kyc_scam (2); apk_link named lottery_reward_scam (1); job_task named bank_kyc_scam (1); loan_app named lottery_reward_scam (1); fake_offer named bank_kyc_scam (1); other_scam named lottery_reward_scam (1).

Caught scams with at least one phrase of what the message says (prompt v5): 86 of 96 (89.6%, 82–94%).

### Public messages, held out

The 30% of merged_sms.csv (UCI SMS Spam Collection and Mishra & Soni) the SMS model never trained on; no sender, so text and links only.

| Label | Messages | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| scam or spam | 318 | 14 | 38 | 266 |
| normal | 1498 | 1480 | 16 | 2 |

### Fishing for Smishing: Indian scam reports

3,729 reports from Indian mobile numbers, 2,520 different texts; 220 left out as like the training data or the India set; 905 campaigns (one message each).

| Label | Messages | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| scam | 859 | 104 | 83 | 672 |
| spam | 46 | 10 | 6 | 30 |

Scams by the reporters' type:

| Type | Flagged |
| --- | --- |
| banking | 443 of 456 (97.1%, 95–98%) |
| others | 152 of 223 (68.2%, 62–74%) |
| telecom | 135 of 145 (93.1%, 88–96%) |
| government | 14 of 20 (70.0%, 48–85%) |
| delivery | 11 of 11 (100.0%, 74–100%) |
| wrong number | 0 of 4 (0.0%, 0–49%) |

With the link left out (the reports hide it): scams flagged 741 of 859 (86.3%, 84–88%).

Caught scams with at least one phrase of what the message says: 666 of 755 (88.2%, 86–90%).

