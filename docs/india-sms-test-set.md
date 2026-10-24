# India SMS test set: how to build it and use it

## Why

- The baseline model learned from public datasets: UCI (UK and Singapore SMS from the 2000s) and one Indian smishing set.
- Scams in India today look different: KYC and `.bank.in` links, UPI, "digital arrest", task jobs, Hinglish.
- Before collecting more training data, measure where the model actually fails on real Indian messages. The judges will ask the same question.

Two separate sets, never mixed:

| Set | Contents | Used for |
| --- | --- | --- |
| `india_test` | real messages only | measuring; never trained on |
| `india_train` | real messages, plus synthetic ones only where the test set shows a gap | training |

## What to collect (target: about 200 test messages)

About 100 threats, spread over the playbook types:

- bank KYC
- fake parcel or delivery fee
- prize, lottery or refund
- OTP theft
- APK app link
- electricity disconnection
- job or task scam
- "digital arrest"

About 25 genuine marketing messages from registered senders (label `spam`). "Exciting offer…" from an `-P` header is marketing, not fraud.

About 75 normal messages (label `ham`), including the hard ones that look like scams but are real:

- OTPs, bank transaction alerts and real KYC reminders from your bank's sender ID
- delivery updates with links
- government alerts
- personal chats

The collection sheet (`india_sms_collection.xlsx`, sent in the chat) has dropdowns for the labels and 19 categories, a target per category, and a progress sheet that counts what is still missing.

Where to get them:

- Your own and your teammates' inboxes.
- Family and friends' inboxes, only with their permission.
- Public sources that quote a real SMS word for word: PIB Fact Check posts, news fact-checks, bank and cyber-police advisories. Put the web link in `notes`. If the source hid the link or phone number, add a made-up one and say so in `notes`.
- The Fishing for Smishing research dataset (Agarwal, Papasavva, Suarez-Tangil and Vasek, IMC 2025, CC BY 4.0, [github.com/reportsmishing/Smishing-Dataset-IMC25](https://github.com/reportsmishing/Smishing-Dataset-IMC25)): real scam SMS that people posted online, 3,729 of them sent from Indian mobile numbers. Pick by hand, because some reports are genuine messages people were unsure about. Cite the paper.
- Not for testing: blog lists of "example" scam texts (written by the author) and generated datasets.

Privacy and safety:

- Before saving, replace names, account numbers, OTPs and personal phone numbers with made-up values of the same shape (a 10-digit number stays a 10-digit number).
- Keep links as text and never open them.

## CSV format

```
label,message,sender,source,category,language
smishing,"Your SBI KYC is pending, update today: http://sbi-kyc.example",9812345678,india_test,bank_kyc,en
ham,"Rs 500 debited from A/c XX1234 on 12-10. Not you? Call 1800...",AX-SBIINB-S,india_test,,en
```

- `label`: `smishing` (fraud), `spam` (genuine but unwanted marketing) or `ham` (normal). The model treats `spam` and `smishing` both as threats, so today the app shows marketing as suspicious too; a three-class model is planned.
- `sender`: copied exactly as the phone shows it (`AX-HDFCBK-S`, `9812345678`, or empty). Never guess it from the message text and never make one up: the detector treats a mobile-number sender as a warning sign, so an invented number on a genuine message creates a false alarm in the test.
- `language`: `en`, `hi` or `hinglish`.

## Measure

```bash
python detectors/sms/eval_india.py --train merged_sms.csv --test india_sms_collection_v9.xlsx --show 20
```

This trains the app's model without the India set (test messages that also appear in the training data are dropped), tests only on the India set, and lists the missed fraud and the false alarms. It reads the workbook directly, or a CSV in the format above. The results so far are in `eval/results_sms.md`.

## Then improve, in this order

1. **Real examples of what was missed** go into `india_train`.
2. **Synthetic messages** fill a gap only when real ones are too rare:
   - varied wording, marked `source=synthetic`, never in `india_test`
   - keep them only if the `india_test` score improves; a model can learn a generator's writing style instead of the scam.
3. **Hard negatives** (real bank alerts, OTPs, KYC reminders and delivery links labelled `ham`) teach the model that "account", "KYC" or a link alone is not a scam.
4. **Use the sender.**
   - The public datasets have no sender, so today the model cannot learn from it, and the 10-digit-sender rule only adds a warning sign.
   - With senders in the India set, the score can combine the model with sender rules: a link or money request from a personal number should be at least "suspicious".
5. **Later, a multilingual model** (the playbook's INT8 encoder on ExecuTorch) for Hindi and Hinglish, compared on the same `india_test`.
