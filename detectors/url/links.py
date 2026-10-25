"""Find the links in a message and split each into the parts the link checker needs.

Works offline: the list of domain endings (the Public Suffix List) comes bundled with
the tldextract package, so nothing is downloaded when a link is checked.
"""
import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

import tldextract

from .lists import FREE_HOSTING

# Offline: use the bundled suffix list, never fetch a newer one. Private suffixes
# (vercel.app, github.io, ...) count as endings, so "x.vercel.app" belongs to "x".
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
# Endings newer than the bundled list (bank.in, fin.in), and free hosting services
# that are missing from it: "sbi-kyc.weebly.com" is someone's own site, not Weebly's.
_EXTRA_SUFFIXES = {"bank.in", "fin.in"} | FREE_HOSTING
# Reserved names (RFC 2606, 6761): no real website can have them. The test set uses
# ".example" for scam links that were anonymised.
_RESERVED = {"example", "invalid", "test", "localhost", "local", "internal", "lan", "home", "arpa"}
# A bare name such as "B.Tech", "Ref.ID", "Civil.No" or "placement.To" is usually not a
# link. Without "http", "www." or a path, only these endings count.
_BARE_OK = {"com", "in", "net", "org", "info", "co", "io", "app", "xyz", "top", "online", "site", "live",
            "shop", "store", "club", "vip", "icu", "link", "ai", "sbi", "biz", "cc", "me", "ly"}

_LINK_RE = re.compile(
    r"(?:(?:https?|hxxps?)://|www\d?\.)[^\s<>\"'`]+"                    # http(s)://... or www....
    r"|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"   # or a bare domain ...
    r"(?::\d{2,5})?(?:/[^\s<>\"'`]*)?"                                       # ... with an optional path
    r"|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?/[^\s<>\"'`]*",          # or an IP address with a path
    re.I)
_TRAILING = ".,;:!?)]}>'\"`"
_WWW_RE = re.compile(r"^www\d?\.")


@dataclass
class Link:
    raw: str             # as found in the text
    url: str             # with a scheme
    host: str            # lower-case, without "www." and port; non-Latin letters as punycode (xn--)
    path: str            # path and query, lower-case
    subdomain: str
    domain: str          # the name just before the ending, e.g. "hdfcbank"
    suffix: str          # the ending, e.g. "com", "co.in", "vercel.app"
    registered: str      # domain + "." + suffix: the part someone registers ("" for an IP address)
    is_ip: bool
    has_at: bool         # "https://www.sbi.co.in@evil.example": the real site comes after the @
    explicit: bool       # written with http(s):// or www.


def _split(host):
    """host -> (subdomain, domain, suffix), using the bundled suffix list plus _EXTRA_SUFFIXES."""
    r = _EXTRACT(host)
    sub, dom, suf = r.subdomain, r.domain, r.suffix
    labels = host.split(".")
    for i in range(1, len(labels)):            # longest ending first
        cand = ".".join(labels[i:])
        if cand in _EXTRA_SUFFIXES:
            if len(cand) > len(suf):
                return ".".join(labels[:i - 1]), labels[i - 1], cand
            break
    if suf and not dom:                        # the host is itself an ending: "github.io", "x.dweb.link"
        sub, dom, suf = "", labels[0], ".".join(labels[1:])
    return sub, dom, suf


def parse_link(raw: str) -> Optional[Link]:
    text = raw.strip().rstrip(_TRAILING)
    if not text:
        return None
    explicit = bool(re.match(r"(?:https?|hxxps?)://|www\d?\.", text, re.I))
    url = re.sub(r"^hxxp", "http", text, flags=re.I)
    if not re.match(r"https?://", url, re.I):
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".")
        written = parts.netloc.rsplit("@", 1)[-1].split(":")[0]     # the host as typed, with its capitals
    except ValueError:
        return None
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        pass
    host = _WWW_RE.sub("", host.lower())
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    path = (parts.path or "") + (("?" + parts.query) if parts.query else "")
    if is_ip:
        sub, dom, suffix, registered = "", host, "", ""
    else:
        if host.rsplit(".", 1)[-1] in _RESERVED:
            return None                     # cannot exist on the internet
        sub, dom, suffix = _split(host)
        if not suffix:
            if not explicit or "." not in host:
                return None                 # "Mr.Sharma" is not a link: no real ending
            labels = host.split(".")        # an unknown ending: treat its last label as one
            sub, dom, suffix = ".".join(labels[:-2]), labels[-2], labels[-1]
        if not explicit and not path.strip("/"):
            last = suffix.rsplit(".", 1)[-1]
            typed_ending = written[-len(last):]
            if (last not in _BARE_OK or len(dom) < 2
                    or (typed_ending != typed_ending.lower() and written != written.upper())):
                return None                 # "B.Tech", "Ref.ID", "placement.To"
        registered = f"{dom}.{suffix}"
    return Link(raw=raw, url=url, host=host, path=path.lower(), subdomain=sub, domain=dom,
                suffix=suffix, registered=registered, is_ip=is_ip,
                has_at=bool(parts.username), explicit=explicit)


def find_links(text: str) -> List[Link]:
    links, seen = [], set()
    for m in _LINK_RE.finditer(text or ""):
        link = parse_link(m.group(0))
        if link and link.url not in seen:
            seen.add(link.url)
            links.append(link)
    return links
