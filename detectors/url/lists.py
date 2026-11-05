"""Curated lists for the link checker. Edit these as you meet new cases.

Every list here is about the *registered domain* (the part someone buys, such as
hdfcbank.com or sbi-kyc.xyz) unless it says otherwise. Matching is lower-case.
"""
import re

# --- Official zones -------------------------------------------------------
# Only verified organisations can register under these, so any site there is genuine.
BANK_ZONES = ("bank.in",)                 # RBI: every Indian bank, since 31 Oct 2025
GOV_ZONES = ("gov.in", "nic.in")          # Indian government
FIN_ZONES = ("fin.in",)                   # RBI's zone for other regulated financial firms
OFFICIAL_ZONES = BANK_ZONES + GOV_ZONES + FIN_ZONES
# Top-level domains that belong to one company: only it can create sites there.
BRAND_TLDS = {"sbi": ("SBI", "bank"), "statebank": ("SBI", "bank"), "google": ("Google", "app")}

# --- Brands scammers copy -------------------------------------------------
# (name shown to people, kind, pattern searched in the address,
#  registered domains that really belong to the brand). Government names have no
# domains here: their real sites are under .gov.in / .nic.in, which count as official.
_BRANDS = [
    ("SBI", "bank", r"(?<![a-z])sbi|onlinesbi|yonosbi|statebank",
     ["sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbisecurities.in",
      "sbigeneral.in", "sbipensionfunds.com", "sbicaps.com", "yonobusiness.sbi"]),
    ("HDFC Bank", "bank", r"hdfc",
     ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcfund.com", "hdfcsec.com",
      "hdfcbank.net", "hdfccredila.com", "hdfcsky.com", "hdfcpension.com"]),
    ("ICICI Bank", "bank", r"(?<![a-z])icici",
     ["icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicipruamc.com",
      "icicisecurities.com", "icicibank.co.in", "icicihfc.com"]),
    ("Axis Bank", "bank", r"axis-?bank", ["axisbank.com", "axisdirect.in", "axismf.com", "axisbank.co.in"]),
    ("Kotak Mahindra Bank", "bank", r"(?<![a-z])kotak",
     ["kotak.com", "kotaksecurities.com", "kotaklife.com", "kotakmf.com", "kotak811.com"]),
    ("Punjab National Bank", "bank", r"(?<![a-z])pnb(?![a-z])|pnbindia|netpnb",
     ["pnbindia.in", "netpnb.com", "pnbhousing.com", "pnbmetlife.com"]),
    ("Bank of Baroda", "bank", r"bankofbaroda|(?<![a-z])bob(?:card|ibanking|world)",
     ["bankofbaroda.in", "bankofbaroda.com", "bobibanking.com", "bobcard.co.in", "bankofbarodauae.ae"]),
    ("Canara Bank", "bank", r"canara-?bank", ["canarabank.com", "canarabank.in"]),
    ("the Reserve Bank of India", "regulator", r"(?<![a-z])rbi(?![a-z])|reservebank", ["rbi.org.in"]),
    ("Paytm", "payment app", r"paytm",
     ["paytm.com", "paytmbank.com", "paytmmoney.com", "paytm.in", "paytm.me", "paytmmall.com", "paytmpayments.com"]),
    ("PhonePe", "payment app", r"phone-?pe", ["phonepe.com", "phon.pe"]),
    ("Google Pay", "payment app", r"(?<![a-z])g-?pay(?![a-z])|googlepay", ["google.com"]),
    ("UPI / NPCI", "payment app", r"(?<![a-z])(?:upi|npci|bhim)(?![a-z])", ["npci.org.in", "bhimupi.org.in"]),
    ("Amazon", "online shop", r"amazon|amzn",
     ["amazon.in", "amazon.com", "amazonpay.in", "amzn.in", "amzn.to", "a.co", "amazon.jobs", "media-amazon.com",
      "amazon.co.uk", "amazon.ae", "amazon.work"]),
    ("Flipkart", "online shop", r"flipkart|fkrt",
     ["flipkart.com", "fkrt.it", "fkrt.cc", "flipkart.net", "flixcart.com", "flipkartwholesale.com"]),
    ("IRCTC", "government", r"irctc", ["irctc.co.in", "irctc.com", "irctctourism.com", "irctcipay.com"]),
    ("India Post", "government", r"india-?post|speed-?post", []),
    ("UIDAI (Aadhaar)", "government", r"uidai|aadhaar", []),       # not "aadhar": a common word in business names
    ("EPFO", "government", r"(?<![a-z])epfo|epfindia", []),
    ("the Income Tax Department", "government", r"income-?tax|itrefund|(?<![a-z])itr-?(?:refund|filing)", []),
    ("LIC", "insurer", r"(?<![a-z])lic(?![a-z])|licindia", ["licindia.in", "licindia.com", "licimf.com"]),
    ("Airtel", "mobile operator", r"airtel",
     ["airtel.in", "airtel.com", "airtelxstream.in", "airtelbank.com", "airtel.africa", "airtelthanks.in"]),
    # "jio" starts many unrelated names (jioujiang.com), so: "jio" alone, or with a Jio word.
    ("Jio", "mobile operator", r"(?<![a-z])(?:my)?jio(?![a-z])|"
     r"(?<![a-z])(?:my)?jio(?:mart|cinema|saavn|hotstar|fiber|tv|pay|"
     r"finance|lottery|lucky|recharge|offer|reward|prime|phone|bharat|money|coin|games|cloud|meet|sim|5g|airfiber|"
     r"care|kyc|bonus|gift|plan|data)",
     ["jio.com", "jiomart.com", "jiocinema.com", "jiosaavn.com", "jiohotstar.com", "jiofinance.com",
      "jiofinancial.com", "jiopay.in", "jiobp.com", "jioworldcentre.com", "jioblackrock.com", "jioblackrockamc.com",
      "ril.com"]),
    # Vodafone runs sites in many countries; Indian scams copy Vodafone Idea.
    ("Vodafone Idea (Vi)", "mobile operator", r"vodafone-?idea|vodafone-?(?:in|india)(?![a-z])",
     ["myvi.in", "vodafoneidea.com", "vodafone.in"]),
    ("BSNL", "mobile operator", r"bsnl", ["bsnl.co.in", "bsnl.in"]),
    ("Blue Dart", "courier", r"blue-?dart", ["bluedart.com"]),
    ("Delhivery", "courier", r"delhivery", ["delhivery.com"]),
    ("DTDC", "courier", r"dtdc", ["dtdc.in", "dtdc.com"]),
    ("FedEx", "courier", r"fedex", ["fedex.com"]),
    ("DHL", "courier", r"(?<![a-z])dhl", ["dhl.com", "dhl.co.in", "dhl.de"]),
    ("WhatsApp", "app", r"whats-?app", ["whatsapp.com", "whatsapp.net"]),
    ("Google", "app", r"(?<![a-z])google|gmail",
     ["google.com", "google.co.in", "gmail.com", "youtube.com", "youtu.be", "g.co", "googlevideo.com",
      "gstatic.com", "googletagmanager.com", "googlesyndication.com", "googleadservices.com", "withgoogle.com"]),
    ("Microsoft", "app", r"microsoft|hotmail|office-?365|onedrive",     # not "outlook": outlookindia.com
     ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com",
      "microsoft365.com", "onedrive.com"]),
    ("Apple", "app", r"(?<![a-z])apple(?![a-z])|icloud", ["apple.com", "icloud.com", "apple.co"]),
    ("PayPal", "payment app", r"paypal", ["paypal.com", "paypal.me", "paypalobjects.com"]),
    ("Netflix", "app", r"netflix", ["netflix.com", "netflix.net"]),
    ("Facebook / Instagram", "app", r"facebook|instagram",
     ["facebook.com", "fb.com", "instagram.com", "messenger.com", "fb.me", "facebook.net", "fbcdn.net"]),
    ("a crypto wallet", "app", r"metamask|binance|coinbase|trustwallet",
     ["metamask.io", "binance.com", "coinbase.com", "trustwallet.com"]),
]
BRANDS = [(name, kind, re.compile(rx), set(domains)) for name, kind, rx, domains in _BRANDS]
BRAND_DOMAINS = {d: (name, kind) for name, kind, _, domains in _BRANDS for d in domains}
# A brand's own infrastructure where other people's content lives (S3 buckets, files
# shared from Google): the brand name in it is not an imitation, and it is not official.
BRAND_INFRA = {"amazonaws.com", "googleapis.com", "googleusercontent.com", "appspot.com", "cloudfront.net",
               "azurewebsites.net", "windows.net", "sharepoint.com", "office.com", "live.com"}

# --- Where anyone can publish -------------------------------------------
# Free site builders, app hosting, tunnels and IPFS gateways: phishing pages are
# often put there because they cost nothing and carry a respectable name. Each
# person's site is <name>.<service>, so links.py treats these as domain endings:
# the registered domain of "sbi-kyc.weebly.com" is the whole "sbi-kyc.weebly.com".
FREE_HOSTING = {
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "github.io", "gitbook.io", "glitch.me", "repl.co", "replit.dev", "replit.app", "herokuapp.com", "appspot.com",
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.io", "godaddysites.com",
    "square.site", "blogspot.com", "wordpress.com", "webflow.io", "framer.app", "framer.website", "carrd.co",
    "mystrikingly.com", "duckdns.org", "ngrok-free.app", "ngrok.io", "ngrok.app", "trycloudflare.com",
    "serveo.net", "dweb.link", "cf-ipfs.com", "ipfs.io", "atwebpages.com", "byethost.com", "c1.biz",
    "serv00.net", "amplifyapp.com", "onrender.com", "fly.dev", "surge.sh", "translate.goog", "sharepoint.com",
    "s3.amazonaws.com", "azurewebsites.net", "cloudfront.net", "blob.core.windows.net", "web.core.windows.net",
    "notion.site", "canva.site", "my.canva.site", "gitlab.io", "bitbucket.io", "infinityfreeapp.com",
    "rf.gd", "epizy.com", "freevar.com", "yolasite.com", "jimdosite.com", "site123.me", "tilda.ws",
    "lovable.app", "bolt.host", "netlify.com", "tumblr.com", "fc2.com", "hostingersite.com", "wcomhost.com",
    "mybluehost.me", "odoo.com", "zohosites.in", "zohosites.com", "business.site", "ueniweb.com",
}
# Big services where anyone can upload a file or make a form or page; the content
# is in the path, so these are matched on the host.
SHARED_CONTENT = {
    "docs.google.com", "sites.google.com", "drive.google.com", "forms.gle", "script.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "forms.office.com", "sway.office.com",
    "onedrive.live.com", "1drv.ms", "dropbox.com", "dropboxusercontent.com", "telegra.ph",
    "docs.zoho.in", "forms.zohopublic.in", "jotform.com", "form.jotform.com", "typeform.com",
    "googleusercontent.com", "linktr.ee", "pastebin.com", "heyzine.com", "flipbookpdf.net",
    "s3.amazonaws.com", "objectstorage.ap-mumbai-1.oraclecloud.com", "storage.cloud.google.com",
    "app.box.com", "mediafire.com", "archive.org", "scribd.com", "issuu.com", "padlet.com",
    "l.instagram.com", "l.facebook.com", "lm.facebook.com", "l.wl.co", "plus.google.com", "appengine.google.com",
    # Services that web pages load in the background, which phishing lists carry because a
    # path was abused: profile pages on Gravatar, pages cached by Google's AMP cache
    # (".../c/s/<site>/..."). A busy hour on the lab Wi-Fi (5 November 2026) looked both up.
    "gravatar.com", "cdn.ampproject.org", "ampproject.org",
}

# --- Link shorteners --------------------------------------------------------
# The real website is hidden until the link is opened.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "v.gd", "t.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc",
    "s.id", "rebrand.ly", "t.co", "buff.ly", "surl.li", "clck.ru", "u.to", "shorturl.gg", "bit.do", "shrtco.de",
    "goo.su", "qr.ae", "l.ead.me", "goo.gl", "onelink.to", "app.link", "page.link", "short.gy", "tiny.one",
    "bl.ink", "lnkd.in", "qrco.de", "urlz.fr", "shorturl.asia", "zpr.io", "n9.cl", "acortar.link",
}

# --- Chats with strangers ------------------------------------------------
# Not websites: these open a WhatsApp or Telegram chat or group. Job and task scams
# move people there.
CHAT_HOSTS = {"wa.me", "chat.whatsapp.com", "api.whatsapp.com", "t.me", "telegram.me",
              "telegram.dog", "m.me", "ig.me", "line.me"}

# Endings used far more for throw-away scam sites than for real businesses (Spamhaus and
# Interisle phishing reports). Only used together with a brand name in the address.
CHEAP_TLDS = {
    "xyz", "top", "icu", "cfd", "sbs", "click", "link", "buzz", "rest", "shop", "online", "site", "live",
    "store", "club", "vip", "cc", "ws", "tk", "ml", "ga", "cf", "gq", "pw", "bond", "cyou", "monster", "quest",
    "lol", "mom", "beauty", "hair", "skin", "autos", "homes", "support", "help", "info", "work", "life", "today",
    "fun", "space", "website", "tech", "win", "bid", "loan", "men", "date", "party", "review", "cam", "best",
}
# Subdomain labels that make an address start like another website ("sbi.co.in.kyc-verify.xyz").
TLD_LIKE = {"com", "co", "in", "net", "org", "gov", "nic", "bank", "www"}

# Words in an address that ask you to sign in, verify or pay.
CREDENTIAL_WORDS = re.compile(
    r"(?<![a-z])(login|log-in|signin|sign-in|verify|verification|kyc|update|secure|account|wallet|"
    r"reward|refund|bonus|claim|otp|unlock|blocked|suspend|confirm|billing|payment|pay-?now|redeem|"
    r"netbanking|net-banking|ekyc|pan-?update|aadhaa?r-?update|support|helpdesk|customer-?care|"
    r"points|gift|offer|prize|lucky|free|recharge|cashback|activate|reactivate|validate|auth)(?![a-z])"
)


def brand_matches(text):
    """Brands whose pattern occurs in the given address text (lower-case)."""
    return [(name, kind, domains) for name, kind, rx, domains in BRANDS if rx.search(text or "")]


def within(host, names):
    """The entry of `names` that `host` is, or is under ("a.b.weebly.com" -> "weebly.com"); else None."""
    labels = host.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in names:
            return cand
    return None
