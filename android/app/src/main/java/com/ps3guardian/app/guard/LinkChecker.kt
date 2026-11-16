package com.ps3guardian.app.guard

import java.io.ByteArrayOutputStream

/** One checked link (detectors/url/detector.py: LinkVerdict). */
class LinkVerdict(
    val host: String,
    val registered: String,
    val score: Double,
    val verdict: String,                // safe, suspicious or dangerous
    val kind: String,                   // official, listed, shortener, chat, shared, hosting, ip, popular, site
    val reasons: MutableList<String>,
    val decisive: Boolean = false,      // dangerous on its own, whatever else the message says
    val brand: String? = null,
    val brandKind: String? = null,
    val modelScore: Double? = null,
) {
    val official get() = kind == "official"
    val imitates get() = brand != null && kind != "official"
    fun shown() = host.replace(".", "[.]")
}

/**
 * The Pi's link checker (detectors/url/detector.py), without the public phishing list: the list
 * (392,000 sites) stays on the Pi, which adds it when the phone is at home. The rest is the same:
 * app files, the "@" trick, brand names on other websites, short and chat links, official websites,
 * and the link model with the odds for what it cannot see.
 */
class LinkChecker internal constructor(l: Map<String, Any?>, sms: Map<String, Any?>, private val model: LinkModel) {
    val finder = LinkFinder(l, sms)
    private val bankZones = l["bank_zones"].strings()
    private val govZones = l["gov_zones"].strings()
    private val finZones = l["fin_zones"].strings()
    private val brandTlds = l["brand_tlds"].obj().mapValues { it.value.strings() }
    private class Brand(val name: String, val kind: String, val rx: Regex)
    private val brands = l["brands"].list().map { b -> b.list().let { Brand(it[0] as String, it[1] as String, PyRe.compile(it[2] as String)) } }
    private val brandDomains = HashMap<String, Pair<String, String>>().apply {
        for (b in l["brands"].list()) {
            val e = b.list()
            for (d in e[3].strings()) put(d, Pair(e[0] as String, e[1] as String))
        }
    }
    private val brandInfra = l["brand_infra"].strings().toHashSet()
    private val freeHosting = l["free_hosting"].strings().toHashSet()
    private val sharedContent = l["shared_content"].strings().toHashSet()
    private val shorteners = l["shorteners"].strings().toHashSet()
    private val chatHosts = l["chat_hosts"].strings().toHashSet()
    private val cheapTlds = l["cheap_tlds"].strings().toHashSet()
    private val tldLike = l["tld_like"].strings().toHashSet()
    private val topSites = l["top_sites"].strings().toHashSet()
    private val r = l["reasons"].obj().mapValues { it.value as String }
    private val odds = l["odds"].obj().mapValues { it.value.num() }
    private val weakKinds = l["weak_brand_kinds"].strings().toHashSet()
    private val scores = l["scores"].obj().mapValues { it.value.num() }
    private val patterns = sms["patterns"].obj()
    private val credentialWords = PyRe.of(patterns["CREDENTIAL_WORDS"])
    private val ampPath = PyRe.of(patterns["AMP_PATH_RE"])
    private val embedded = PyRe.of(patterns["EMBEDDED_RE"])
    private val suspiciousAt = sms["suspicious_at"].num()
    private val dangerousAt = sms["dangerous_at"].num()

    fun verdictFor(score: Double) = when {
        score >= dangerousAt -> "dangerous"
        score >= suspiciousAt -> "suspicious"
        else -> "safe"
    }

    /** Every link in a message, checked. */
    fun checkText(text: String): List<LinkVerdict> = finder.find(text).map { check(it) }

    private fun within(host: String, names: Set<String>): String? {
        val labels = host.split(".")
        for (i in labels.indices) {
            val cand = labels.subList(i, labels.size).joinToString(".")
            if (cand in names) return cand
        }
        return null
    }

    private fun brandMatches(text: String) = brands.filter { it.rx.containsMatchIn(text) }

    private fun translatedSite(link: Link): Link? {
        if (!link.host.endsWith(".translate.goog")) return null
        val label = link.host.removeSuffix(".translate.goog").split(".").last()
        val site = label.replace("--", "\u0000").replace("-", ".").replace("\u0000", "-")
        return finder.parse("https://" + site + link.path.ifEmpty { "/" })
    }

    private fun ampCachedSite(link: Link): Link? {
        if (link.host != "cdn.ampproject.org" && !link.host.endsWith(".cdn.ampproject.org")) return null
        val m = ampPath.toPattern().matcher(link.path)
        if (!m.lookingAt()) return null
        return finder.parse("https://" + m.group(1) + (m.group(2) ?: "/"))
    }

    private fun embeddedLink(link: Link): Link? {
        val m = embedded.find(link.path) ?: return null
        return finder.parse(unquote(m.value))
    }

    private fun official(link: Link): Triple<String, String?, String?>? {
        for ((zones, key) in listOf(bankZones to "bank", govZones to "gov", finZones to "fin")) {
            if (link.suffix in zones || zones.any { link.suffix.endsWith(".$it") }) return Triple(r[key]!!, null, null)
        }
        brandTlds[link.suffix]?.let { return Triple("the link is on ${it[0]}'s official website", it[0], it[1]) }
        brandDomains[link.registered]?.let { return Triple("the link is on ${it.first}'s official website", it.first, it.second) }
        return null
    }

    /** One link. A website hidden inside it (a redirect, Google Translate, the AMP cache) is checked too. */
    fun check(link: Link): LinkVerdict {
        translatedSite(link)?.let { return outer(link, single(it), r["translate"]!!) }
        val cached = ampCachedSite(link)
        if (cached != null) return outer(link, single(cached), r["amp"]!!)    // no phishing list on the phone
        val v = single(link)
        val inner = embeddedLink(link)
        if (inner == null || inner.registered == link.registered || v.decisive) return v
        val iv = single(inner)
        return if (iv.score <= v.score) v else outer(link, iv, r["redirect"]!!)
    }

    private fun outer(link: Link, iv: LinkVerdict, reason: String) = LinkVerdict(
        link.host, link.registered, iv.score, iv.verdict, iv.kind, (listOf(reason) + iv.reasons).toMutableList(),
        iv.decisive, iv.brand, iv.brandKind, iv.modelScore)

    private fun odds(p: Double): Double {
        val q = p.coerceIn(1e-6, 1 - 1e-6)
        return q / (1 - q)
    }

    private fun single(link: Link): LinkVerdict {
        val host = link.host
        val path = link.path
        val reasons = ArrayList<String>()
        fun verdict(score: Double, kind: String, decisive: Boolean = false, brand: String? = null,
                    brandKind: String? = null, model: Double? = null) =
            LinkVerdict(host, link.registered, pyRound(score, 4), verdictFor(score), kind, reasons, decisive,
                brand, brandKind, model?.let { pyRound(it, 4) })

        // 1. Dangerous on their own.
        val apk = path.substringBefore('?').endsWith(".apk") || ".apk?" in path
        if (apk) reasons.add(r["apk"]!!)
        if (link.hasAt) reasons.add(r["at"]!!)
        val shortener = within(host, shorteners)
        val chat = within(host, chatHosts)
        val shared = within(host, sharedContent)
        val hosting = within(host, freeHosting)
        val official = if (shortener != null || chat != null || shared != null || hosting != null || link.isIp) null
        else official(link)

        var brand: Brand? = null
        var decisiveBrand = false
        var brandOdds = 1.0
        if (official == null && !link.isIp && chat == null && shortener == null && link.registered !in brandInfra) {
            val wordsInHost = credentialWords.containsMatchIn("${link.subdomain}.${link.domain}")
            val subLabels = if (link.subdomain.isNotEmpty()) link.subdomain.split(".") else emptyList()
            val fakePrefix = subLabels.drop(1).any { it in tldLike } ||
                link.domain.startsWith("com-") || link.domain.startsWith("in-")
            val cheap = link.suffix.substringAfterLast('.') in cheapTlds
            val inLabel = if (shared == null) brandMatches(link.domain) else emptyList()
            val inSub = if (link.subdomain.isNotEmpty() && shared == null) brandMatches(link.subdomain) else emptyList()
            val inPath = if (shared != null || hosting != null) brandMatches(path) else emptyList()
            if (inLabel.isNotEmpty()) {
                brand = inLabel[0]
                val strong = wordsInHost || brand.kind !in weakKinds
                decisiveBrand = wordsInHost || fakePrefix || (strong && (hosting != null || cheap))
                brandOdds = odds["brand_label"]!!
            } else if (inSub.isNotEmpty()) {
                brand = inSub[0]
                val strong = wordsInHost || brand.kind !in weakKinds
                decisiveBrand = fakePrefix || (strong && hosting != null) || (wordsInHost && cheap)
                brandOdds = odds["brand_sub"]!!
            } else if (inPath.isNotEmpty()) {
                brand = inPath[0]
                decisiveBrand = credentialWords.containsMatchIn(path)
                brandOdds = odds["brand_path"]!!
            }
            if (brand != null) {
                val name = brand.name
                reasons.add(when {
                    fakePrefix && inSub.isNotEmpty() ->
                        "the address starts with $name's website name, but the real website is a different one"
                    inPath.isNotEmpty() ->
                        "the page uses $name's name, but it is on a service where anyone can publish"
                    else -> "the website address uses $name's name, but it is not $name's official website"
                })
            }
        }
        val bName = brand?.name
        val bKind = brand?.kind
        if (apk || link.hasAt || decisiveBrand) {
            val kind = if (shortener != null) "shortener" else if (hosting != null) "hosting" else "site"
            if (shortener != null) reasons.add(r["shortener"]!!)
            return verdict(scores["decisive"]!!, kind, true, bName, bKind)
        }

        // 2. The website name says nothing about the page.
        if (shortener != null) {
            reasons.add(r["shortener"]!!)
            return verdict(scores["opaque"]!!, "shortener")
        }
        if (chat != null) {
            reasons.add(r["chat"]!!)
            return verdict(scores["opaque"]!!, "chat")
        }

        // 3. Official websites.
        if (official != null) {
            reasons.add(official.first)
            return verdict(scores["official"]!!, "official", brand = official.second, brandKind = official.third)
        }

        // 4. Everything else: the model, then what it cannot see.
        var pModel: Double? = null
        var popular = false
        val kind: String
        val base: Double
        if (link.isIp) {
            kind = "ip"; base = scores["opaque"]!!
        } else if (shared != null) {
            kind = "shared"; base = scores["shared"]!!
        } else {
            popular = hosting == null && link.registered in topSites
            kind = if (hosting != null) "hosting" else if (popular) "popular" else "site"
            pModel = model.score(link.domain, link.suffix)
            base = pModel
        }
        var o = odds(base) * brandOdds
        if (popular) { o *= odds["popular"]!!; reasons.add(r["popular"]!!) }
        if (link.isIp) { o *= odds["ip"]!!; reasons.add(r["ip"]!!) }
        if ("xn--" in host) { o *= odds["punycode"]!!; reasons.add(r["punycode"]!!) }
        if (hosting != null) {
            if (pModel == null) o *= odds["hosting"]!!            // the model already knows these endings
            reasons.add(r["hosting"]!!)
        }
        if (shared != null) reasons.add(r["shared"]!!)
        if (credentialWords.containsMatchIn("${link.subdomain}.${link.domain}") && shared == null) {
            o *= odds["words_host"]!!; reasons.add(r["words"]!!)
        } else if (credentialWords.containsMatchIn(path)) {
            o *= odds["words_path"]!!; reasons.add(r["words"]!!)
        }
        if (link.subdomain.count { it == '.' } >= 3) { o *= odds["many_parts"]!!; reasons.add(r["many_parts"]!!) }
        if (pModel != null && !popular) {
            if (pModel >= 0.8) reasons.add(r["model_high"]!!) else if (pModel >= 0.5) reasons.add(r["model_mid"]!!)
        }
        return verdict(o / (1 + o), kind, brand = bName, brandKind = bKind, model = pModel)
    }

    /** Python's urllib.parse.unquote: %xx sequences as UTF-8, bad bytes replaced. */
    private fun unquote(s: String): String {
        if ('%' !in s) return s
        val out = StringBuilder()
        val bytes = ByteArrayOutputStream()
        var i = 0
        fun flush() {
            if (bytes.size() > 0) { out.append(String(bytes.toByteArray(), Charsets.UTF_8)); bytes.reset() }
        }
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length && s[i + 1].isHex() && s[i + 2].isHex()) {
                bytes.write(s.substring(i + 1, i + 3).toInt(16))
                i += 3
            } else {
                flush()
                out.append(c)
                i++
            }
        }
        flush()
        return out.toString()
    }

    private fun Char.isHex() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
