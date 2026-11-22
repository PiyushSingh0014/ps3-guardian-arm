# Advisor review (en, fresh)

Source: `home-hub/detectors/sms/sample_messages.csv`. 30 messages, 13 flagged, 12 distinct prompts.

| # | Category | Msgs | Prompt tok (reused) | TTFT s | Decode tok/s | Total s | Valid | Explanation |
|---|---|---|---|---|---|---|---|---|
| 1 | bank_kyc_scam | 1 | 592 (512) | 6.196 | 3.391 | 20.94 | yes | This message pretends to be from SBI to trick you into updating your KYC, which is not possible through a link. Genuine banks do not send links to update KYC, and this link is not on an official .bank.in website. |
| 2 | bank_kyc_scam | 1 | 587 (512) | 5.832 | 3.388 | 20.296 | yes | This message pretends to be from HDFC Bank to trick you into updating your KYC, which is not possible online. Genuine banks like HDFC Bank have official websites ending in .bank.in, and links to their websites are always correct. |
| 3 | lottery_reward_scam | 1 | 586 (480) | 8.278 | 3.397 | 19.759 | yes | This message pretends to be from a bank to trick you into giving away your income-tax refund. Genuine banks never ask for a fee or OTP, and links to official websites are not provided. |
| 4 | lottery_reward_scam | 1 | 581 (512) | 5.447 | 3.403 | 17.79 | yes | This message pretends to be from the Income Tax Department to trick you into giving away your income-tax refund. Genuine tax refunds go directly to your bank account, and links to official websites are not from banks. |
| 5 | delivery_fee_scam | 1 | 555 (480) | 5.807 | 3.43 | 18.051 | yes | This message pretends to be from customs officials to trick you into paying a fake delivery fee. Real customs officials do not ask for fees through links in SMS messages, and this short link hides the real website. |
| 6 | apk_malware_link | 1 | 591 (480) | 8.67 | 3.39 | 19.585 | yes | This message pretends to be from Paytm to trick you into installing a fake app. Real apps are installed only from the official Play Store, and Paytm is not a bank. |
