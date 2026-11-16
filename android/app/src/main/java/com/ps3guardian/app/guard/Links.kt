package com.ps3guardian.app.guard

import java.net.IDN
import java.text.Normalizer

/** One link found in a message, split as detectors/url/links.py splits it. */
class Link(
    val raw: String,
    val url: String,
    val host: String,          // lower case, without "www." and port; non-Latin letters as punycode
    val path: String,          // path and query, lower case
    val subdomain: String,
    val domain: String,        // the name just before the ending, e.g. "hdfcbank"
    val suffix: String,        // the ending, e.g. "com", "co.in", "vercel.app"
    val registered: String,    // domain + "." + suffix ("" for an IP address)
    val isIp: Boolean,
    val hasAt: Boolean,        // "https://www.sbi.co.in@evil.example": the real site comes after the @
    val explicit: Boolean,     // written with http(s):// or www.
)

/** The Public Suffix List as the Pi's tldextract reads it (private endings such as vercel.app included). */
internal class Psl(public: List<String>, private: List<String>) {
    private class Node {
        val matches = HashMap<String, Node>()
        var end = false
        var isPrivate = false
    }

    private val root = Node()

    init {
        for (s in public) add(s, false)
        for (s in private) add(s, true)
    }

    private fun add(suffix: String, isPrivate: Boolean) {
        var node = root
        for (label in suffix.split(".").reversed()) node = node.matches.getOrPut(label) { Node() }
        node.end = true
        node.isPrivate = isPrivate
    }

    private fun decode(label: String): String {
        val lower = label.lowercase()
        if (lower.startsWith("xn--")) {
            try {
                return IDN.toUnicode(lower, IDN.ALLOW_UNASSIGNED)
            } catch (e: Exception) {
                // as tldextract: keep the label
            }
        }
        return lower
    }

    /** The index of the first label of the ending, or -1 (tldextract's suffix_index). */
    private fun suffixIndex(labels: List<String>): Int {
        var node = root
        var suffixIdx = labels.size
        var labelIdx = labels.size
        for (label in labels.reversed()) {
            val decoded = decode(label)
            val next = node.matches[decoded]
            if (next != null) {
                labelIdx -= 1
                node = next
                if (node.end) suffixIdx = labelIdx
                continue
            }
            if ("*" in node.matches) return if ("!$decoded" in node.matches) labelIdx else labelIdx - 1
            break
        }
        return if (suffixIdx == labels.size) -1 else suffixIdx
    }

    /** (subdomain, domain, suffix) of a host, as tldextract.extract gives them. */
    fun split(host: String): Triple<String, String, String> {
        val h = host.replace('。', '.').replace('．', '.').replace('｡', '.')
        val labels = h.split(".")
        val idx = suffixIndex(labels)
        if (idx < 0) {
            if (labels.size == 4 && h.isNotEmpty() && h[0].isDigit() && IPV4.matches(h)) return Triple("", h, "")
            return Triple(labels.dropLast(1).joinToString("."), labels.last(), "")
        }
        val sub = if (idx >= 2) labels.subList(0, idx - 1).joinToString(".") else ""
        val dom = if (idx > 0) labels[idx - 1] else ""
        return Triple(sub, dom, labels.subList(idx, labels.size).joinToString("."))
    }

    companion object {
        private val IPV4 = Regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    }
}

/** Finds the links in a message (links.py: find_links, parse_link), offline. */
class LinkFinder internal constructor(lists: Map<String, Any?>, sms: Map<String, Any?>) {
    private val psl = Psl(lists["psl_public"].strings(), lists["psl_private"].strings())
    private val extraSuffixes = lists["extra_suffixes"].strings().toHashSet()
    private val reserved = lists["reserved"].strings().toHashSet()
    private val bareOk = lists["bare_ok"].strings().toHashSet()
    private val linkRe = PyRe.of(sms["patterns"].obj()["LINK_RE"])
    private val wwwRe = PyRe.of(sms["patterns"].obj()["WWW_RE"])
    private val explicitRe = PyRe.compile("(?:https?|hxxps?)://|www\\d?\\.", true)
    private val hxxpRe = PyRe.compile("^hxxp", true)
    private val httpRe = PyRe.compile("https?://", true)

    fun find(text: String): List<Link> {
        val out = ArrayList<Link>()
        val seen = HashSet<String>()
        for (m in linkRe.findAll(text)) {
            val link = parse(m.value) ?: continue
            if (seen.add(link.url)) out.add(link)
        }
        return out
    }

    private fun splitHost(host: String): Triple<String, String, String> {
        var (sub, dom, suf) = psl.split(host)
        val labels = host.split(".")
        for (i in 1 until labels.size) {                       // longest ending first
            val cand = labels.subList(i, labels.size).joinToString(".")
            if (cand in extraSuffixes) {
                if (cand.length > suf.length) {
                    return Triple(labels.subList(0, i - 1).joinToString("."), labels[i - 1], cand)
                }
                break
            }
        }
        if (suf.isNotEmpty() && dom.isEmpty()) {               // the host is itself an ending: "github.io"
            sub = ""
            dom = labels[0]
            suf = labels.drop(1).joinToString(".")
        }
        return Triple(sub, dom, suf)
    }

    fun parse(raw: String): Link? {
        val text = pyStrip(raw).trimEnd { it in TRAILING }
        if (text.isEmpty()) return null
        val explicit = explicitRe.matchStart(text)
        var url = hxxpRe.replaceFirst(text, "http")
        if (!httpRe.matchStart(url)) url = "http://$url"
        val parts = UrlSplit.split(url) ?: return null
        var host = (parts.hostname ?: "").trimEnd('.')
        val written = parts.netloc.substringAfterLast('@').split(":")[0]
        if (host.isEmpty()) return null
        if (host.any { it.code > 127 }) {
            try {
                host = IDN.toASCII(host)
            } catch (e: Exception) {
                // as Python: keep the name as it is
            }
        }
        host = wwwRe.replaceFirst(host.lowercase(), "")
        val isIp = IpAddress.valid(host.trim('[', ']'))
        val path = parts.path + (if (parts.query.isNotEmpty()) "?" + parts.query else "")
        var sub: String
        var dom: String
        var suffix: String
        val registered: String
        if (isIp) {
            sub = ""; dom = host; suffix = ""; registered = ""
        } else {
            if (host.substringAfterLast('.') in reserved) return null       // cannot exist on the internet
            val s = splitHost(host)
            sub = s.first; dom = s.second; suffix = s.third
            if (suffix.isEmpty()) {
                if (!explicit || '.' !in host) return null               // "Mr.Sharma": no real ending
                val labels = host.split(".")
                sub = labels.dropLast(2).joinToString(".")
                dom = labels[labels.size - 2]
                suffix = labels.last()
            }
            if (!explicit && path.trim('/').isEmpty()) {
                val last = suffix.substringAfterLast('.')
                val typed = if (last.length <= written.length) written.substring(written.length - last.length) else written
                if (last !in bareOk || dom.length < 2 ||
                    (typed != typed.lowercase() && written != written.uppercase())) return null   // "B.Tech", "Ref.ID"
            }
            registered = "$dom.$suffix"
        }
        return Link(raw, url, host, path.lowercase(), sub, dom, suffix, registered, isIp,
            !parts.username.isNullOrEmpty(), explicit)
    }

    companion object {
        private const val TRAILING = ".,;:!?)]}>'\"`"
    }
}

/** Python's urllib.parse.urlsplit, as far as the link checker uses it. */
internal object UrlSplit {
    class Parts(val netloc: String, val path: String, val query: String, val hostname: String?, val username: String?)

    fun split(input: String): Parts? {
        var url = input.trimStart { it.code <= 0x20 }.replace("\t", "").replace("\r", "").replace("\n", "")
        val colon = url.indexOf(':')
        if (colon > 0 && url[0].code < 128 && url[0].isLetter() &&
            url.substring(0, colon).all { it.code < 128 && (it.isLetterOrDigit() || it in "+-.") }) {
            url = url.substring(colon + 1)
        }
        var netloc = ""
        if (url.startsWith("//")) {
            var delim = url.length
            for (c in "/?#") {
                val w = url.indexOf(c, 2)
                if (w >= 0) delim = minOf(delim, w)
            }
            netloc = url.substring(2, delim)
            url = url.substring(delim)
            if (('[' in netloc) != (']' in netloc)) return null                 // "Invalid IPv6 URL"
            if ('[' in netloc && !bracketOk(netloc)) return null
        }
        if ('#' in url) url = url.substringBefore('#')
        var query = ""
        if ('?' in url) {
            query = url.substringAfter('?')
            url = url.substringBefore('?')
        }
        if (!netlocOk(netloc)) return null
        val at = netloc.lastIndexOf('@')
        val hostinfo = if (at >= 0) netloc.substring(at + 1) else netloc
        val username = if (at >= 0) netloc.substring(0, at).substringBefore(':') else null
        val hostname: String = if ('[' in hostinfo) {
            hostinfo.substringAfter('[').substringBefore(']')
        } else hostinfo.substringBefore(':')
        val host = if (hostname.isEmpty()) null else {
            val pct = hostname.indexOf('%')
            if (pct >= 0) hostname.substring(0, pct).lowercase() + hostname.substring(pct) else hostname.lowercase()
        }
        return Parts(netloc, url, query, host, username)
    }

    private fun bracketOk(netloc: String): Boolean {
        val hp = netloc.substringAfterLast('@')
        val open = hp.indexOf('[')
        if (open < 0) return true
        if (open > 0) return false
        val inside = hp.substring(1).substringBefore(']')
        val port = hp.substring(1).substringAfter(']', "")
        if (port.isNotEmpty() && !port.startsWith(":")) return false
        return IpAddress.valid6(inside.substringBefore('%')) || inside.startsWith("v") || inside.startsWith("V")
    }

    /** _checknetloc: a name that NFKC turns into "/", "?", "#", "@" or ":" is refused. */
    private fun netlocOk(netloc: String): Boolean {
        if (netloc.isEmpty() || netloc.all { it.code < 128 }) return true
        val n = netloc.replace("@", "").replace(":", "").replace("#", "").replace("?", "")
        val k = Normalizer.normalize(n, Normalizer.Form.NFKC)
        if (n == k) return true
        return k.none { it in "/?#@:" }
    }
}

/** Python's ipaddress.ip_address, as a yes or no. */
internal object IpAddress {
    fun valid(s: String): Boolean = valid4(s) || valid6(s)

    fun valid4(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return false
            if (p.length > 1 && p[0] == '0') return false
            if (p.toInt() > 255) return false
        }
        return true
    }

    fun valid6(input: String): Boolean {
        var s = input
        val pct = s.indexOf('%')
        if (pct >= 0) {
            if (pct == s.length - 1) return false
            s = s.substring(0, pct)
        }
        if (':' !in s) return false
        var parts = s.split(":")
        var limit = 8
        if (parts.last().contains('.')) {                       // an IPv4 address at the end
            if (!valid4(parts.last())) return false
            parts = parts.dropLast(1) + "0"
            limit = 7
        }
        if (parts.size < 3 || parts.size > limit + 1) return false
        val empties = (1 until parts.size - 1).count { parts[it].isEmpty() }
        if (empties > 1) return false
        if (parts.first().isEmpty() && parts[1].isNotEmpty()) return false
        if (parts.last().isEmpty() && parts[parts.size - 2].isNotEmpty()) return false
        val groups = parts.filter { it.isNotEmpty() }
        if (groups.any { it.length > 4 || !it.all { c -> c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' } }) return false
        return if (empties == 1 || (parts.first().isEmpty() && parts.last().isEmpty())) groups.size < limit
        else parts.size == limit
    }
}
