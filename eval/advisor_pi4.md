# Advisor review (en, fresh)

Source: `detectors/sms/sample_messages.csv`. 30 messages, 14 flagged, 14 distinct prompts.

| # | Category | Msgs | Prompt tok (reused) | TTFT s | Decode tok/s | Total s | Valid | Explanation |
|---|---|---|---|---|---|---|---|---|
| 1 | utility_disconnection_scam | 1 | 619 (512) | 8.259 | 3.337 | 22.944 | yes | This message looks like someone pretending to be the electricity company to scare you into paying a scammer or calling a fake helpline. Real electricity companies do not ask for personal numbers or install apps, and the text patterns are common in scam messages. |
| 2 | bank_kyc_scam | 1 | 658 (512) | 11.162 | 3.274 | 27.657 | yes | This message pretends to be from SBI to steal your net-banking login, card details, or OTP through a fake KYC page. Genuine banks do not send links to fake KYC pages, and this link is not on an official .bank.in website. |
| 3 | bank_kyc_scam | 1 | 653 (576) | 6.212 | 3.278 | 23.294 | yes | This message pretends to be from HDFC Bank to steal your net-banking login, card details or OTP through a fake KYC page. Genuine banks update KYC only at a branch or through their official app or website, and links to .bank.in websites are genuine. |
| 4 | lottery_reward_scam | 1 | 643 (512) | 10.354 | 3.321 | 22.097 | yes | This message pretends to be a genuine company or office offering a prize or refund to steal your bank account details and claim a prize. Genuine companies never ask for bank account details or cashback. |
| 5 | lottery_reward_scam | 1 | 647 (576) | 5.825 | 3.304 | 19.141 | yes | This message pretends to be from the Income Tax Department to steal a fee, bank details, or an OTP with a fake prize or refund. Genuine government offices never ask for payment or sensitive information via unsecured links. |
| 6 | delivery_fee_scam | 1 | 634 (512) | 9.458 | 3.327 | 22.984 | yes | This message pretends to be from customs officials to steal your card details through a fake delivery fee. Real courier companies and India Post do not collect fees through links in SMS messages, and this short link hides the real website. |
