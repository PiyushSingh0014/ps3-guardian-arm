# Accuracy test (update 49)

How often Sajag is right about scam and normal messages, and whether its explanations are true.
Results: [results/results_accuracy.md](../results/results_accuracy.md).

| Part | Who | Time |
| --- | --- | --- |
| A. Labelled message sets (real Indian scam reports, public held-out messages, the India test set) | done in the cloud | – |
| B. Your phones' real messages: label the flagged ones | done (22 November) | – |
| C. Llama's explanations: prompt v5 against v4 on the same cases | moved to Phase 2 (the answers are generated) | – |
| D. Live test on the Galaxy S25 | done (22 November) | – |

Before B and C, the Pi must run update 47 or later, restarted (prompt v5):

```
cd ~/ps3-guardian/home-hub
git log --oneline -1
sudo systemctl restart ps3-guardian
```

## Part A: labelled message sets

Done: see the results file. To run it again on the Pi (it then also shows the Pi's speed), copy
`final_dataset_output.csv` from github.com/reportsmishing/Smishing-Dataset-IMC25 (`dataset/`) to
the Pi's home folder, then:

```
cd ~/ps3-guardian/home-hub
~/ps3-venv/bin/python scripts/accuracy_test.py --india ~/india_sms_collection_v9.xlsx --public ~/merged_sms.csv --smishing ~/final_dataset_output.csv
```

## Part B: your phones' real messages

The Pi's log holds what the app decided for each message your phones forwarded. Some flagged ones
were never labelled, so the false-alarm rate is only a range (0.9 to 7.9 per 100 messages). Label
only the flagged ones: each is a true alert or a false alarm.

```
cd ~/ps3-guardian/home-hub
~/ps3-venv/bin/python scripts/sms_traffic.py label --flagged
```

For each message: `f` = scam (fraud), `m` = genuine marketing, `n` = normal, Enter = not sure
(skip), `u` = undo, `q` = stop (run it again to carry on). Label what the message is, not what the
app said. Most of these texts come from phones B and C: ask their owners to label their own (add
`--device B` or `--device C`), or sit with them.

Then paste the output of:

```
~/ps3-venv/bin/python scripts/sms_traffic.py measure
```

## Part C: Llama's explanations, v5 against v4

**Moved to Phase 2 (22 November).** Llama's answers to the same 87 cases are generated on the Pi
(`data/advisor/grading-v5`); grading them takes about an hour per grader, so Phase 1 reports prompt v4's grading. The
steps below are kept for Phase 2.

The 100 answers graded on 15 November were written with prompt v4. This asks Llama again for the
same message cases, now with what each message says (prompt v5), so the two gradings compare like
for like. Run it when nobody is using the app (alerts would wait for Llama):

```
cd ~/ps3-guardian/home-hub
~/ps3-venv/bin/python -m advisor.grade generate --india ~/india_sms_collection_v9.xlsx --folder data/advisor/grading-v5 --match data/advisor/grading
```

It prints how many of the old cases it found again (about 86 of 89), then one line per answer.
Ctrl+C stops it; the same command carries on.

Grade, each grader on their own, without looking at the old grades or the AI pre-check:

```
~/ps3-venv/bin/python -m advisor.grade label --grader piyush --folder data/advisor/grading-v5
```

`s` = supported by the case, `n` = not supported (the case does not say it), `w` = wrong (it
contradicts the case, or it is false), Enter = skip, `b` = back, `q` = stop. Judge each sentence
only against the case shown beside it, including the new lines under "The message:". A second
grader uses their own name (`--grader anshu`).

Then paste the output of:

```
~/ps3-venv/bin/python -m advisor.grade report --folder data/advisor/grading-v5 --compare data/advisor/grading --wrong
```

The last table puts each grader's v4 and v5 grades side by side for the same cases.

## Part D: live test on the phone

This checks the whole app on the S25: the alert comes, quickly, with the right title and an
explanation that fits the message. The messages below were written by us, so this is a test that
the app works end to end, not a measure of accuracy (parts A and B are).

Set-up: Sajag 3.2 on the S25, paired with the Home Hub, SMS checks on. A second phone sends each
message as an SMS to the S25. Send one, wait for Sajag's alert (or about 30 s for a normal
message), note the result, then send the next. Screenshots of each alert help (and give footage
for the video).

**Round 1: the S25 on the Home Hub's Wi-Fi** (the Hub checks too and Llama explains on the Pi).

| # | Send this | Should be |
| --- | --- | --- |
| 1 | Dear customer, your SBI account will be blocked today. Update your KYC now: http://sbi-kyc-update.example/login | Dangerous, fake bank KYC |
| 2 | Your electricity will be disconnected tonight at 9:30 pm as your last bill is not updated. Call the electricity officer at 9812345678 immediately. | Dangerous, electricity |
| 3 | India Post: your parcel is held at our office. Pay Rs 25 redelivery fee at http://indiapost-redeliver.example/pay within 24 hours. | Dangerous, delivery fee |
| 4 | Congratulations! Your number has won Rs 25,00,000 in the KBC lucky draw. Pay Rs 5,000 processing fee to claim. Call 9812345678. | Dangerous, prize or lottery |
| 5 | Part time job: earn Rs 3,000 per day from home by liking videos. WhatsApp 9812345678 to start. | Suspicious or dangerous, job or task |
| 6 | This is CBI officer. A parcel in your name has narcotics. You will be arrested today. Call 9812345678 immediately. | Dangerous, digital arrest |
| 7 | Paytm: you have received Rs 5,000 cashback. Share the OTP sent to your phone to receive it. | Dangerous, OTP theft or prize |
| 8 | Your Jio SIM will be blocked within 24 hours because your KYC is pending. Call customer care 9812345678 now. | Dangerous (title general or KYC: no SIM title yet) |
| 9 | Dear user, your loan of Rs 90,000 is approved. Install the app to get the money: http://quick-loan.example/loan.apk | Dangerous, app download |
| 10 | प्रिय ग्राहक, आपका बैंक खाता आज बंद हो जाएगा। तुरंत KYC अपडेट करें: http://kyc-update.example | Dangerous, explanation in Hindi |
| 11 | Your ICICI credit card reward points worth Rs 9,450 expire today. Redeem now: http://icici-rewards.example | Dangerous (title may say bank KYC: known) |
| 12 | Hi, reached home safely. Will call you after dinner. | Safe, no alert |
| 13 | Meeting moved to 5 pm tomorrow, same room. | Safe |
| 14 | Can you send me the notes for the DSP lecture? | Safe |
| 15 | Happy birthday! Have a great year ahead. | Safe |
| 16 | I'll be 10 minutes late, start without me. | Safe |
| 17 | Mom, I paid the electricity bill today, Rs 1,240. | Safe (hard: bill, electricity, money) |
| 18 | Check this video: https://www.youtube.com/watch?v=jNQXAC9IVRw | Safe or suspicious (a link from a mobile number) |
| 19 | Bhai kal cricket khelne chaloge? 6 baje ground pe milte hain. | Safe |
| 20 | आज शाम को घर पर पूजा है, जल्दी आ जाना। | Safe |

**Round 2: the S25's Wi-Fi off** (checked and explained on the phone alone). Send 1, 2, 4 and 10
again. Each should get its own alert again (app 3.2), explained "on this phone".

Note for each message:

| # | Arrived | Alert at | Verdict | Title right? | Explanation fits the message? (yes / partly / no) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | |

Send the filled table, or the screenshots, back for the results file.
