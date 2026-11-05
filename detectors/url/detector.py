"""Phishing link checker: is this link safe to open?

Checks, in this order:
  1. Tricks that make a link dangerous on their own: an app file (.apk), the "@" trick,
     a site on the public lists of phishing and malware links (intel.py), and a brand's
     name on someone else's website together with sign-in words, a cheap ending, free
     hosting, or a fake website name in front ("sbi.co.in.kyc-check.xyz").
  2. Services where the website name says nothing about the page: link shorteners,
     WhatsApp and Telegram chat links, and shared files and forms (Google Docs, Forms).
  3. Official websites: .bank.in, .gov.in, .nic.in and .fin.in, which only verified
     organisations can register, and the brands' own domains (lists.py).
  4. Everything else: the link model (train_url.py) reads the letters of the registered
     domain and gives the chance that it is a phishing site; rules for what it cannot see
     (IP addresses, free hosting, brand names, look-alike letters, sign-in words, many
     subdomains) then multiply the odds.

Without the model file (before train_url.py has run) an unknown website starts at 0.3.
Reasons never contain the link itself: they are passed to Llama, which must not see
text a scammer chose.
"""
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import unquote

from advisor.findings import Finding, verdict_from_score

from .intel import DB, ROOT, Blocklist
from .links import Link, find_links, parse_link
from .model import LinkModel
from .lists import (BANK_ZONES, BRAND_DOMAINS, BRAND_INFRA, BRAND_TLDS, CHAT_HOSTS, CHEAP_TLDS, CREDENTIAL_WORDS,
                    FIN_ZONES, FREE_HOSTING, GOV_ZONES, SHARED_CONTENT, SHORTENERS, TLD_LIKE, brand_matches, within)

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "url_model.npz")
TOP_SITES = os.path.join(ROOT, "data", "url", "top_sites.txt")

NO_MODEL_SCORE = 0.3        # an unknown website, when there is no model
WEAK_BRAND_KINDS = {"app", "online shop"}
OPAQUE_SCORE = 0.5          # short links, chat links and IP addresses: the name tells us nothing
SHARED_SCORE = 0.3          # a file or form on a big service: the service is fine, the page unknown
OFFICIAL_SCORE = 0.02
DECISIVE_SCORE = 0.97
LISTED_SCORE = 0.99

# Odds multipliers for what the model cannot see. Prior assumptions, like senders.py;
# eval_url.py measures the result.
ODDS = {"ip": 6.0, "punycode": 3.0, "hosting": 3.0, "brand_label": 5.0, "brand_sub": 3.0,
        "brand_path": 3.0, "words_host": 2.0, "words_path": 1.5, "many_parts": 1.5, "popular": 0.1}

R = {
    "apk": "the link downloads an app file (.apk) instead of using the Play Store",
    "at": "the link hides the real website after an @ sign",
    "listed": "the website is on public lists of reported phishing or malware sites",
    "bank": "the link is on an official Indian bank website (.bank.in)",
    "gov": "the link is on an official Indian government website (.gov.in or .nic.in)",
    "fin": "the link is on the official website of a regulated financial company (.fin.in)",
    "shortener": "uses a short link that hides the real website",
    "chat": "the link opens a WhatsApp or Telegram chat with a stranger",
    "shared": "the link opens a file, form or page that anyone can make on a big service such as Google Forms",
    "hosting": "the page is on a free website builder or hosting service, where anyone can publish",
    "ip": "the link uses a bare internet (IP) address instead of a website name",
    "punycode": "the website name uses look-alike letters from another alphabet",
    "words": "the website address has words like login, verify, KYC or reward",
    "many_parts": "the website name has many parts, a trick to look like a real site",
    "model_high": "the website name looks like the names used by phishing sites",
    "model_mid": "the website name looks unusual for a real company",
    "popular": "the website is one of the 10,000 most visited websites (Chrome UX Report)",
    "redirect": "the link sends you on to another website, hidden inside the link",
    "translate": "the link shows another website through Google Translate",
    "amp": "the link shows another website through Google's AMP cache",
}
_AMP_PATH_RE = re.compile(r"^/(?:c|v|i|r)/(?:s/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(/[^?#]*)?")
_EMBEDDED_RE = re.compile(r"(?:https?|hxxps?)(?::|%3a)(?:/|%2f){2}[^&\s\"'<>]+", re.I)


def translated_site(link):
    """"www-sbi-co-in.translate.goog" shows www.sbi.co.in through Google Translate: that site."""
    if not link.host.endswith(".translate.goog"):
        return None
    label = link.host[: -len(".translate.goog")].split(".")[-1]
    site = label.replace("--", "\0").replace("-", ".").replace("\0", "-")
    return parse_link("https://" + site + (link.path or "/"))


def amp_cached_site(link):
    """"x.cdn.ampproject.org/c/s/example.com/page" shows example.com/page from Google's AMP
    cache: that site."""
    if link.host != "cdn.ampproject.org" and not link.host.endswith(".cdn.ampproject.org"):
        return None
    m = _AMP_PATH_RE.match(link.path or "")
    return parse_link("https://" + m.group(1) + (m.group(2) or "/")) if m else None


def embedded_link(link):
    """A link hidden in another link's path or query, as open redirects use: ".../url?q=https://..."."""
    m = _EMBEDDED_RE.search(link.path or "")
    return parse_link(unquote(m.group(0))) if m else None


def _odds(p):
    p = min(max(p, 1e-6), 1 - 1e-6)
    return p / (1 - p)


def _prob(o):
    return o / (1 + o)


@dataclass
class LinkVerdict:
    host: str
    registered: str
    score: float
    verdict: str                 # "safe" | "suspicious" | "dangerous"
    kind: str                    # official, listed, shortener, chat, shared, hosting, ip, popular, site
    reasons: List[str] = field(default_factory=list)
    decisive: bool = False       # dangerous on its own, whatever else the message says
    brand: Optional[str] = None  # the brand it imitates, or owns it when kind == "official"
    brand_kind: Optional[str] = None
    model_score: Optional[float] = None
    listed: Optional[str] = None

    @property
    def official(self):
        return self.kind == "official"

    @property
    def imitates(self):
        return self.brand is not None and self.kind != "official"

    def shown(self):
        """The host, made safe to display (not clickable)."""
        return self.host.replace(".", "[.]")


def _official(link):
    """(reason, brand, kind) if the link is on an official website, else None."""
    for zones, key in ((BANK_ZONES, "bank"), (GOV_ZONES, "gov"), (FIN_ZONES, "fin")):
        if link.suffix in zones or any(link.suffix.endswith("." + z) for z in zones):
            return R[key], None, None
    if link.suffix in BRAND_TLDS:
        name, kind = BRAND_TLDS[link.suffix]
        return f"the link is on {name}'s official website", name, kind
    if link.registered in BRAND_DOMAINS:
        name, kind = BRAND_DOMAINS[link.registered]
        return f"the link is on {name}'s official website", name, kind
    return None


def load_top_sites(path=TOP_SITES):
    """Registered domains of the most visited websites (scripts/get_url_data.py writes the file)."""
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


class UrlDetector:
    """model_path, intel_path, top_sites: files to use; None switches that part off."""

    def __init__(self, model_path=MODEL, intel_path=DB, top_sites=TOP_SITES):
        self.model = None
        if model_path and os.path.exists(model_path):
            try:
                self.model = LinkModel.load(model_path)
            except (ValueError, KeyError, OSError) as e:
                print(f"[url] could not load {model_path} ({e}); checking links with rules only")
        self.blocklist = Blocklist(intel_path)
        self.top_sites = load_top_sites(top_sites) if isinstance(top_sites, (str, type(None))) else set(top_sites)

    def info(self):
        return {"model": self.model.meta if self.model else None, "blocklist": self.blocklist.info(),
                "top_sites": len(self.top_sites)}

    # --- the model -------------------------------------------------------
    def model_score(self, link):
        return None if self.model is None else self.model.score(link.domain, link.suffix)

    # --- one link --------------------------------------------------------
    def check_link(self, link: Link) -> LinkVerdict:
        """One link -> LinkVerdict. A website hidden inside the link ("...?url=https://...",
        or a page shown through Google Translate) is checked too, and the worse counts."""
        proxied = translated_site(link)
        if proxied is not None:                 # Google's proxy is fine; the site it shows decides
            return self._outer(link, self._check(proxied), R["translate"])
        cached = amp_cached_site(link)
        if cached is not None:                  # the same for Google's AMP cache, unless that page is listed
            v = self._check(link)
            return v if v.listed else self._outer(link, self._check(cached), R["amp"])
        v = self._check(link)
        inner = embedded_link(link)
        if inner is None or inner.registered == link.registered or v.decisive:
            return v
        iv = self._check(inner)
        return v if iv.score <= v.score else self._outer(link, iv, R["redirect"])

    @staticmethod
    def _outer(link, iv, reason):
        """The verdict on a site reached through `link`, reported under the link's own name."""
        return LinkVerdict(host=link.host, registered=link.registered, score=iv.score, verdict=iv.verdict,
                           kind=iv.kind, reasons=[reason] + iv.reasons, decisive=iv.decisive,
                           brand=iv.brand, brand_kind=iv.brand_kind, model_score=iv.model_score, listed=iv.listed)

    def _check(self, link: Link) -> LinkVerdict:
        host, path = link.host, link.path
        reasons = []

        def verdict(score, kind, decisive=False, brand=None, brand_kind=None, model=None, listed=None):
            return LinkVerdict(host=host, registered=link.registered, score=round(score, 4),
                               verdict=verdict_from_score(score), kind=kind, reasons=reasons,
                               decisive=decisive, brand=brand, brand_kind=brand_kind,
                               model_score=None if model is None else round(model, 4), listed=listed)

        # 1. Dangerous on their own.
        apk = path.split("?")[0].endswith(".apk") or ".apk?" in path
        if apk:
            reasons.append(R["apk"])
        if link.has_at:
            reasons.append(R["at"])
        listed = self.blocklist.lookup(link)
        if listed:
            reasons.append(R["listed"])

        shortener = within(host, SHORTENERS)
        chat = within(host, CHAT_HOSTS)
        shared = within(host, SHARED_CONTENT)
        hosting = within(host, FREE_HOSTING)
        official = None if (shortener or chat or shared or hosting or link.is_ip) else _official(link)

        # Brand names: in the registered label, in front of it, or (on services where
        # anyone publishes) in the path.
        brand, decisive_brand = None, False
        brand_odds = 1.0
        if not official and not link.is_ip and not chat and not shortener \
                and link.registered not in BRAND_INFRA:
            words_in_host = bool(CREDENTIAL_WORDS.search(f"{link.subdomain}.{link.domain}"))
            sub_labels = link.subdomain.split(".") if link.subdomain else []
            fake_prefix = any(lab in TLD_LIKE for lab in sub_labels[1:]) or link.domain.startswith(("com-", "in-"))
            cheap = link.suffix.rsplit(".", 1)[-1] in CHEAP_TLDS
            in_label = brand_matches(link.domain) if not shared else []
            in_sub = brand_matches(link.subdomain) if (link.subdomain and not shared) else []
            in_path = brand_matches(path) if (shared or hosting) else []
            # Banks, payment apps, couriers, operators and government offices are what Indian
            # phishing copies; for app and shop names (Google, WhatsApp, Amazon) on a blog or a
            # cheap ending, it takes sign-in words too: "google-turfs.blogspot.com" is a blog.
            if in_label:
                brand = in_label[0]
                strong = words_in_host or brand[1] not in WEAK_BRAND_KINDS
                decisive_brand = words_in_host or fake_prefix or (strong and (bool(hosting) or cheap))
                brand_odds = ODDS["brand_label"]
            elif in_sub:
                brand = in_sub[0]
                strong = words_in_host or brand[1] not in WEAK_BRAND_KINDS
                decisive_brand = fake_prefix or (strong and bool(hosting)) or (words_in_host and cheap)
                brand_odds = ODDS["brand_sub"]
            elif in_path:
                brand = in_path[0]
                decisive_brand = bool(CREDENTIAL_WORDS.search(path))
                brand_odds = ODDS["brand_path"]
            if brand:
                name = brand[0]
                if fake_prefix and in_sub:
                    reasons.append(f"the address starts with {name}'s website name, "
                                   "but the real website is a different one")
                elif in_path:
                    reasons.append(f"the page uses {name}'s name, but it is on a service where anyone can publish")
                else:
                    reasons.append(f"the website address uses {name}'s name, but it is not {name}'s official website")

        b_name, b_kind = (brand[0], brand[1]) if brand else (None, None)
        if apk or link.has_at or listed or decisive_brand:
            kind = "listed" if listed else ("shortener" if shortener else ("hosting" if hosting else "site"))
            score = LISTED_SCORE if listed else DECISIVE_SCORE
            if shortener:
                reasons.append(R["shortener"])
            return verdict(score, kind, True, b_name, b_kind, listed=listed)

        # 2. The website name says nothing about the page.
        if shortener:
            reasons.append(R["shortener"])
            return verdict(OPAQUE_SCORE, "shortener")
        if chat:
            reasons.append(R["chat"])
            return verdict(OPAQUE_SCORE, "chat")

        # 3. Official websites.
        if official:
            reason, name, kind = official
            reasons.append(reason)
            return verdict(OFFICIAL_SCORE, "official", brand=name, brand_kind=kind)

        # 4. Everything else: the model, then what it cannot see.
        p_model = None
        popular = False
        if link.is_ip:
            kind, base = "ip", OPAQUE_SCORE
        elif shared:
            kind, base = "shared", SHARED_SCORE
        else:
            popular = not hosting and link.registered in self.top_sites
            kind = "hosting" if hosting else ("popular" if popular else "site")
            p_model = self.model_score(link)
            base = NO_MODEL_SCORE if p_model is None else p_model
        odds = _odds(base) * brand_odds
        if popular:
            odds *= ODDS["popular"]
            reasons.append(R["popular"])
        if link.is_ip:
            odds *= ODDS["ip"]
            reasons.append(R["ip"])
        if "xn--" in host:
            odds *= ODDS["punycode"]
            reasons.append(R["punycode"])
        if hosting:
            if p_model is None:                 # the model already knows these endings
                odds *= ODDS["hosting"]
            reasons.append(R["hosting"])
        if shared:
            reasons.append(R["shared"])
        if CREDENTIAL_WORDS.search(f"{link.subdomain}.{link.domain}") and not shared:
            odds *= ODDS["words_host"]
            reasons.append(R["words"])
        elif CREDENTIAL_WORDS.search(path):
            odds *= ODDS["words_path"]
            reasons.append(R["words"])
        if link.subdomain.count(".") >= 3:
            odds *= ODDS["many_parts"]
            reasons.append(R["many_parts"])
        if p_model is not None and not popular:
            if p_model >= 0.8:
                reasons.append(R["model_high"])
            elif p_model >= 0.5:
                reasons.append(R["model_mid"])
        return verdict(_prob(odds), kind, brand=b_name, brand_kind=b_kind, model=p_model)

    # --- text and findings -----------------------------------------------
    def check_text(self, text) -> List[LinkVerdict]:
        """Every link in a message, checked."""
        return [self.check_link(link) for link in find_links(text)]

    def check(self, url: str, language: str = "en") -> Finding:
        """One link (as pasted on the page or sent to POST /url) -> Finding."""
        s = (url or "").strip()
        link = None
        if s and not any(c.isspace() for c in s):       # one pasted link: "http://" is optional
            link = parse_link(s if re.match(r"(?:https?|hxxps?)://", s, re.I) else "http://" + s)
        if link is None:
            links = find_links(url or "")
            link = links[0] if links else None
        if link is None:
            return Finding(source="url", verdict="safe", score=0.0, category="none",
                           reasons=["no website link found"], entities={}, raw_text=url, language=language)
        v = self.check_link(link)
        return finding_from(v, raw_text=url, language=language)


def category_for(v: LinkVerdict) -> str:
    if v.verdict == "safe":
        return "none"
    if v.reasons and v.reasons[0] == R["apk"]:
        return "apk_malware_link"
    if v.kind in ("shortener", "chat") and not v.decisive:
        return "generic_suspicious"
    return "phishing_link"


def finding_from(v: LinkVerdict, raw_text=None, language="en") -> Finding:
    entities = {"link": v.shown(), "link_kind": v.kind}
    if v.imitates:
        entities["claims_to_be"], entities["claims_kind"] = v.brand, v.brand_kind
    if v.official and v.brand:
        entities["official_site_of"] = v.brand
    if v.model_score is not None:
        entities["model_score"] = v.model_score
    if v.listed:
        entities["listed_by"] = v.listed
    return Finding(source="url", verdict=v.verdict, score=round(v.score, 3), category=category_for(v),
                   reasons=list(v.reasons), entities=entities, raw_text=raw_text, language=language)
