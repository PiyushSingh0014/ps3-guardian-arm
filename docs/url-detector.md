# Phishing link checker (`home-hub/detectors/url`)

Checks every link: links inside SMS and chats from the Android companion, links in messages pasted on the page, and single links sent to `POST /url`. It runs on the Pi in about a millisecond per link, with no network: the lists are downloaded in advance and kept on the SD card.

Results are in [results/results_url.md](../results/results_url.md).

## How a link is judged

```
link ──► parse (links.py: registered domain, subdomain, path; punycode; "B.Tech" is not a link)
     ├─► 1. dangerous on its own
     │       an .apk file · the @ trick · on a phishing list (intel.py)
     │       · a brand's name on someone else's site, with sign-in words, a cheap ending,
     │         free hosting or a fake prefix ("sbi.co.in.kyc-check.xyz")
     ├─► 2. the name says nothing: short link, WhatsApp/Telegram chat link, shared file or form
     ├─► 3. official: .bank.in, .gov.in, .nic.in, .fin.in, the .sbi ending, brands' own domains
     └─► 4. otherwise: link model score for the registered domain (model.py)
             × odds for what the model cannot see: IP address 6, brand name 5 (3 in a
               subdomain), look-alike letters 3, sign-in words 2, many subdomains 1.5,
               one of the 10,000 most visited websites 0.1
```

- **Hidden websites.** A website hidden inside a link (`google.com/url?q=https://...`) or shown through Google Translate (`www-sbi-co-in.translate.goog`) or Google's AMP cache (`….cdn.ampproject.org/c/s/example.com/...`) is checked too, and the worse verdict counts.
- **Verdicts.** Score ≥ 0.5 is suspicious and ≥ 0.8 is dangerous, the same thresholds as for SMS.
- **Reasons.** Every verdict comes with reasons in plain English. They never contain the link itself, because they are passed to Llama.

### The model

- **What it is.** Logistic regression on character pieces (2–5 letters) of the registered domain only, plus 7 numbers: length, digits, hyphens, letter entropy, vowels, consonant runs and the ending.
- **What it was trained on.** 996,256 domains:
  - PhiUSIIL (CC BY 4.0) and Phishing.Database (MIT) for phishing;
  - the Chrome UX Report's top 1 million websites as legitimate examples.
- **Why it reads only the domain.** Training on whole URLs learns a shortcut in PhiUSIIL that flags every genuine SMS link. [results/results_url.md](../results/results_url.md) explains it.
- **How it is stored.** The model is saved as plain numbers (`url_model.npz`, 1.4 MB): idf weights, coefficients and scaling. `model.py` scores with numpy, so the file works with any scikit-learn version and loading it runs no pickled code.
- **Retraining.** `python home-hub/detectors/url/train_url.py` takes about 10 minutes and 3.6 GB of memory (measured on 2 cores). That is too heavy for the Pi while Llama is loaded, so the trained file comes with the repo; retrain on a laptop.

### The lists (`home-hub/scripts/get_url_data.py`)

| File | What | Source |
| --- | --- | --- |
| `data/url/intel.sqlite` | ~392,000 hosts reported for phishing, still online | [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (MIT), updated daily |
| `data/url/top_sites.txt` | registered domains of the 10,000 most visited websites | Chrome UX Report, monthly copy at [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists) |

- **Exceptions in the phishing list.** Official domains, services where anyone can publish (Google Docs, Weebly, ...) and the 10,000 most visited websites are never listed as a whole. The public lists contain mistakes such as an Amazon country site and Instagram's link redirector, and one bad page must not block every Google Doc.
  - **Background services too.** Gravatar (profile pictures) and Google's AMP cache are on the public list because their pages were abused, yet web pages load them in the background. A busy hour on the lab Wi-Fi looked both up, so they are never listed whole either. The lookup skips such hosts even in a list file built before they were added.
- **More lists.** You can add other lists you download yourself under their own terms, for example OpenPhish's community feed or abuse.ch URLhaus with an account: `--extra name=path`.
- **Updates.** The app picks up a new `intel.sqlite` within 10 minutes, without a restart.

### Links inside a message

The SMS detector checks each link and adjusts the message's score after the sender (`home-hub/detectors/sms/detector.py`, `apply_links`):

| The links in the message | Effect on the odds of fraud |
| --- | --- |
| any link dangerous on its own (rule 1 above) | the message is **dangerous**, whoever sent it |
| worst link dangerous | × 3 |
| worst link suspicious (not counting short links, which the text model already knows) | × 1.5 |
| every link official | × 0.3 |

Link reasons come first in the message's red flags. When the brand's name is only in the link (`indiapost-track.top`), the advisor still knows who the message pretends to be.

TRAI has blocked SMS whose links the sender has not whitelisted since 1 October 2024 ([TRAI press release 67/2024](https://trai.gov.in/sites/default/files/PR_No.67of2024.pdf)). So a link from a registered sender ID was approved by that business. That is why links adjust the sender-aware score instead of replacing it.

## Use it

- **On the page.** Paste a link on its own; the page shows the link's verdict.
- **Over the API, one link:**

  ```bash
  curl -s -X POST localhost:8000/url -H 'Content-Type: application/json' \
       -d '{"url": "hxxp://sbi-kyc-update.xyz/login"}'
  ```

- **From the command line, a message with links:**

  ```bash
  python -m advisor.cli "Your parcel is held. Pay Rs 25: hxxps://indiapost-track.top/fee" --sender 9812345678
  ```

- **Status.** `GET /health` shows what the checker has loaded: `links.model`, `links.blocklist.hosts` and `links.top_sites`.

Write test links as `hxxp://` (the checker reads them, phones do not make them clickable). Never open a link from a real scam message to "check" it.

## Set up on the Pi (update 9)

On the Pi, after pulling update 9:

```bash
cd ~/ps3-guardian/home-hub
~/ps3-venv/bin/pip install tldextract
~/ps3-venv/bin/python scripts/get_url_data.py       # about 20 MB; builds data/url/
sudo systemctl restart ps3-guardian
curl -s localhost:8000/health | python3 -m json.tool | grep -A12 '"links"'
```

`links.model.trained_on` should list the three sources, and `links.blocklist.hosts` should be about 390,000.

To keep the lists fresh, run the download weekly from cron (`crontab -e`):

```
17 4 * * 1  cd ~/ps3-guardian/home-hub && ~/ps3-venv/bin/python scripts/get_url_data.py >> logs/url_data.log 2>&1
```

Without the lists (no internet on the Pi), the checker still works with its rules and the model.

## Limits

- **Short random domains** (`po9.in`, `kx3.in`) look exactly like the link domains genuine Indian marketing SMS use (`1kx.in`). The link checker cannot tell them apart; the sender and the text do.
- **Brand lists need care.** A brand's name in a domain that is missing from the official list (`hdfcpension.com` was) makes a genuine site suspicious. Add official domains to `lists.py` as you meet them.
- **The model only sees names.** A phishing page on a hacked, ordinary-looking website, or one reached through a short link, is only caught once it is on a list.
- **Phishing.Database lists hosts, not single pages**, and only those still online. A page taken down yesterday and moved today is caught by the rules or the model, or not at all.
