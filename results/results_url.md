# Phishing link checker: results

Measured 2026-10-25 with `home-hub/detectors/url/eval_url.py` and link model v2 (`home-hub/detectors/url/url_model.npz`). How the checker works is in [docs/url-detector.md](../docs/url-detector.md).

## Data

| Source | What it gives | Licence |
| --- | --- | --- |
| [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad and Chandra, 2024) | 134,850 legitimate and 100,945 phishing URLs | CC BY 4.0 |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), active domains, 2026-10-25 | 392,178 phishing hosts still online | MIT |
| Chrome UX Report top 1M websites, via [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists) | 1,000,000 websites that Chrome users really visit, as legitimate examples | public Google data |

Each URL is reduced to its registered domain (the part someone buys). Domains with both labels (1,779) are dropped. That leaves 1,245,321 domains: 378,737 phishing and 866,584 legitimate. 80% (996,256) train the model and 20% (249,065) are held out, split by domain, so **no test domain was seen in training**.

### Why the model sees only the domain, and why it needs the Chrome list

- **Every legitimate URL in PhiUSIIL is a bare home page** (`https://www.<domain>`), while its phishing URLs have paths. A model that reads whole URLs learns "has a path = phishing", and every genuine SMS link has a path. So the model reads only the registered domain, and rules handle paths.
- **PhiUSIIL alone does not know Indian websites.** 45% of its 777 `.in` domains are phishing, so a model trained on it alone (held-out AUC 0.900) flagged 19 of 25 genuine domains from the India SMS collection, including `airtel.in`. Adding the Chrome list as legitimate examples brought that to 5 of 25.

## A. The model alone (held-out registered domains)

| Held-out set | Domains | Flagged at ≥ 0.5 | Flagged at ≥ 0.8 |
| --- | --- | --- | --- |
| Phishing.Database (phishing) | 61,828 | 80.4% caught | 69.1% caught |
| PhiUSIIL phishing | 13,920 | 67.2% caught | 54.3% caught |
| PhiUSIIL legitimate | 26,599 | 9.05% | 0.70% |
| Chrome top 1M (legitimate) | 146,718 | 7.56% | 1.12% |

ROC AUC is 0.920 over all held-out domains (0.856 on PhiUSIIL alone). The share of popular websites flagged at ≥ 0.5 hardly depends on popularity: 7.1% of the top 1,000, 5.7% of those ranked 5,001–10,000 and 8.0% of those ranked 500,001–1M. The most impersonated brands score high because their names fill the phishing lists (`paypal.com` 0.95, `facebook.com` 0.94). That is why the curated official domains are checked before the model.

## B. The whole checker on new links (rules + model, no lists)

One full link per held-out domain. This is what a brand-new phishing site meets: it is on no list yet.

| Held-out links | Links | Flagged (suspicious or dangerous) | Dangerous |
| --- | --- | --- | --- |
| Phishing.Database hosts | 63,361 | **80.9%** | 69.7% |
| PhiUSIIL phishing URLs | 13,920 | 67.7% | 54.8% |
| PhiUSIIL legitimate URLs | 26,599 | 9.0% | 0.7% |
| Chrome top 1M websites | 151,689 | **7.6%** | **1.1%** |

- **Free hosting:** 27,288 of the caught Phishing.Database hosts are on free hosting (`*.weebly.com`, `*.pages.dev`, ...).
- **Decisive rules** (a brand's name on someone else's site, the `@` trick, an `.apk` file) made 534 of them dangerous on their own.
- **Popular websites:** a decisive rule fired on 7 of 151,689.

## C. Indian phishing

Phishing.Database hosts in the held-out set whose name contains an Indian brand (chosen by plain text such as `hdfc`, `paytm`, `indiapost`, `myjio`, independently of the checker's own patterns), against held-out popular websites. No lists.

| Held-out links | Links | Flagged | Dangerous |
| --- | --- | --- | --- |
| Phishing hosts with an Indian brand's name | 21 | **20 (95%)** | 17 (81%) |
| Popular websites under `.in` | 3,312 | 158 (4.8%) | **10 (0.3%)** |
| Popular websites with an Indian brand's name | 48 | 13 (27%) | 10 (21%) |

- **21 phishing hosts is a small sample.** It shows that the brand rules work on real Indian phishing, not how often they do.
- **"Popular" is not the same as "safe".** 7 of the 10 popular sites called dangerous are lottery and cash pages using Jio's or PhonePe's name (`jiolottery4.vip`, `phonepecash.xyz`) or a fake tracking site (`bluedarttrackings.co.in`). Scams get millions of visits too, so the checker never trusts the Chrome list blindly (see D).
- **The other 3 are real false alarms:** a GitHub page, a partner site using ICICI's name, and Bank of Baroda's UAE site. The UAE site is now in the official list.

## D. Links in the India SMS collection

78 links in the 227 messages of `india_sms_collection_v9.xlsx`. The 36 scam links that were anonymised (`*.example`) cannot exist on the internet and are skipped.

| Label | Links | Flagged | Which |
| --- | --- | --- | --- |
| Normal (ham) | 23 | 2 | `bit.ly` short link (suspicious), `gs.im` (0.64) |
| Marketing (spam) | 48 | 11 | `onelink.to` ×6 and `bit.ly` (short links), `weurl.co` ×2, `h.1xpl.co`, `u1.mnge.co` |
| Fraud (smishing) | 7 | 1 | `wa.me` (a WhatsApp chat link) |

**Real Indian scam links fool the domain check, and this is the main finding of the evaluation.** The six scam links in the collection that are not anonymised are `kx3.in`, `po9.in`, `2lm.in`, `sr9.in`, `7kz1.com` and `connecto.live`. They scored between 0.05 and 0.50 (all safe).

They look exactly like the link domains that genuine Indian SMS marketing uses:

- `1kx.in` scored 0.07 and `1jx.in` 0.14, from bulk-SMS platforms.
- `c360.mobi` (Careers360) scored 0.21.

No model can tell them apart from the letters alone. `connecto.live` is even among Chrome's top 1M websites.

What does separate them is who sent them:

- TRAI has blocked SMS with links that the sender has not whitelisted since 1 October 2024. A link from a registered sender ID was approved by that business.
- The same short domain from a 10-digit mobile number was not.

This is why links adjust the sender-aware score instead of replacing it.

## E. Links inside SMS: the India SMS collection end to end

`eval_india.py` with the app's own decision. Text model, then the sender, then the links:

| Flagged | Messages | Text only | With sender | Sender + links |
| --- | --- | --- | --- | --- |
| Fraud | 100 | 94 | 96 | **96** |
| Marketing | 52 | 50 | 35 | **30** |
| Normal | 75 | 48 | 44 | 44 |

The links changed 11 verdicts:

- **9 better.**
  - 5 Airtel offers turned safe because their links are on Airtel's own sites.
  - 4 messages (3 normal, 1 marketing) went from dangerous to suspicious because their links are official (`sancharsaathi.gov.in`, `indiapost.gov.in`, `jio.com` twice).
- **2 worse.** A pension credit with a `gs.im` link, and a bus offer with `weurl.co`, went from suspicious to dangerous.

**No fraud was lost or gained.** The real scam links in this set are the short domains described in D, and the anonymised ones are skipped.

## What this shows

1. **On phishing sites in general, the checker catches about 81% of brand-new ones** (no list), with 7.6% of popular websites flagged and 1.1% called dangerous. **With the lists, every site already reported is caught at once:** about 392,000 hosts from Phishing.Database, updated daily, minus popular websites and official domains.
2. **Indian brand impersonation is the strongest part:** 20 of 21 held-out phishing hosts using an Indian brand's name were flagged. The rules behind it are the official zones (`.bank.in`, `.gov.in`), the brands' own domains, and a brand's name on someone else's site.
3. **Indian SMS scams with random short domains are not caught by the link.** They need the sender (TRAI's URL whitelisting) and the message text. In the app the three are combined.
4. **Official links lower false alarms on marketing** (35 → 30 flagged of 52) without losing fraud.

## Reproduce

```bash
python scripts/get_url_data.py --training      # data/url/: lists, Chrome top sites, PhiUSIIL
python detectors/url/train_url.py              # about 10 minutes and 3.6 GB on 2 cores; writes url_model.npz
python detectors/url/eval_url.py --india india_sms_collection_v9.xlsx
python detectors/sms/eval_india.py --train merged_sms.csv --test india_sms_collection_v9.xlsx
```

Phishing.Database changes every day, so numbers from a later download differ slightly. `train_url.py` saves the held-out domains in `data/url/url_test_domains.csv.gz`, and `eval_url.py` tests only those.
