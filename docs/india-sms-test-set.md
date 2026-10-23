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

About 100 normal messages, including the hard ones:

- OTPs and bank transaction alerts
- delivery updates
- real promotions from registered senders. "Exciting offer…" from an `-P` header is normal marketing, not a scam.
- government alerts
- personal chats

Where to get them:

- Your own and your teammates' inboxes.
- Family and friends' inboxes, only with their permission.
- Public warnings that quote the SMS text: Sanchar Saathi (Chakshu), bank, RBI and TRAI advisories, cyber-police awareness posts, news reports.

Privacy and safety:

- Before saving, replace names, account numbers, OTPs and personal phone numbers with made-up values of the same shape (a 10-digit number stays a 10-digit number).
- Keep links as text and never open them.

## CSV format

```
label,message,sender,source,category,language
smishing,"Your SBI KYC is pending, update today: http://sbi-kyc.example",9812345678,india_test,bank_kyc,en
ham,"Rs 500 debited from A/c XX1234 on 12-10. Not you? Call 1800...",AX-SBIINB-S,india_test,,en
```

- `label`: `ham`, `spam` (unwanted marketing) or `smishing` (fraud).
- `sender`: exactly as shown on the phone (`AX-HDFCBK-S`, `9812345678`, or empty).
- `language`: `en`, `hi` or `hinglish`.

## Measure

Append the rows to your `merged_sms.csv`. Add a `source` column to the old rows if they lack one, for example `uci` and `mishra_soni`. Then:

```bash
python detectors/sms/train_baseline.py --data merged_sms.csv --holdout-source india_test --show-errors 20
```

This trains without the India set, tests only on it, and lists the messages it got wrong. Write the numbers into `eval/results_sms.md`. For the demo model, train once more without `--holdout-source`.

## Then improve, in this order

1. **Real examples of what was missed** go into `india_train`.
2. **Synthetic messages** fill a gap only when real ones are too rare:
   - varied wording, marked `source=synthetic`, never in `india_test`
   - keep them only if the `india_test` score improves; a model can learn a generator's writing style instead of the scam.
3. **Hard negatives** (real promotions, bank alerts) teach the model that "offer" or "click" alone is not a scam.
4. **Use the sender.**
   - The public datasets have no sender, so today the model cannot learn from it, and the 10-digit-sender rule only adds a warning sign.
   - With senders in the India set, the score can combine the model with sender rules: a link or money request from a personal number should be at least "suspicious".
5. **Later, a multilingual model** (the playbook's INT8 encoder on ExecuTorch) for Hindi and Hinglish, compared on the same `india_test`.
