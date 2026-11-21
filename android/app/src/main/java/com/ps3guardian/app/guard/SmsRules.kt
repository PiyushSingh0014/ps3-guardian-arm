package com.ps3guardian.app.guard

/** The red flags of one message (detectors/sms/rules_india.py: Signals). */
class Signals {
    var hasUrl = 0
    var hasShortener = 0
    var hasApk = 0
    var asksSecret = 0
    var hasUpi = 0
    var urgency = 0
    var mentionsMoney = 0
    var bankContext = 0
    var rewardBait = 0
    var bankLinkNotBankin = 0
    var senderIs10Digit = 0
    val reasons = ArrayList<String>()

    fun vector() = intArrayOf(hasUrl, hasShortener, hasApk, asksSecret, hasUpi, urgency, mentionsMoney, bankContext,
        rewardBait, bankLinkNotBankin, senderIs10Digit)
}

/** Who sent the SMS (detectors/sms/senders.py: SenderInfo). */
class SenderInfo(val kind: String, val suffix: String = "", val header: String = "")

/**
 * The India rules, the sender rules and the scam types: detectors/sms/rules_india.py, brands.py,
 * senders.py, detector.decide() and advisor/categorize.py, with their patterns and numbers copied
 * from the Pi by scripts/export_phone_guard.py.
 */
class SmsRules internal constructor(s: Map<String, Any?>) {
    private val p = s["patterns"].obj().mapValues { PyRe.of(it.value) }
    private fun rx(name: String) = p[name] ?: throw IllegalStateException("no pattern $name")
    private class Brand(val name: String, val kind: String, val rx: Regex)
    private val brands = s["brands"].list().map { b -> b.list().let { Brand(it[0] as String, it[1] as String, PyRe.compile(it[2] as String, it[3] as Boolean)) } }
    private val headerRoots = s["header_roots"].obj().mapValues { it.value.strings() }
    private val headerOdds = s["header_odds"].obj().mapValues { it.value.num() }
    private val mobileRiskyOdds = s["mobile_risky_odds"].num()
    private val noSuffixOdds = s["no_suffix_odds"].num()
    val senderRules: Set<String> = s["sender_rules"].strings().toSet()
    private val linkOdds = s["link_odds"].obj().mapValues { it.value.num() }
    private val officialLinkOdds = s["official_link_odds"].num()
    private val riskyKinds = s["risky_kinds"].strings().toSet()
    private val appExt = s["app_ext"].strings().toSet()
    val suspiciousAt = s["suspicious_at"].num()
    val dangerousAt = s["dangerous_at"].num()

    private val reBankIn = rx("BANK_IN_RE")
    private val genericLink = "contains a link"
    private val genericBankLink = "claims to be from a bank, but the link is not on an official .bank.in website"

    fun verdictFor(score: Double) = when {
        score >= dangerousAt -> "dangerous"
        score >= suspiciousAt -> "suspicious"
        else -> "safe"
    }

    // --- rules_india.py ---------------------------------------------------------------------
    fun asksForSecret(message: String): Boolean {
        for (hit in rx("ASK_SECRET_RE").findAll(message)) {
            val before = message.substring(maxOf(0, hit.range.first - 24), hit.range.first)
            if (!rx("NEGATION_RE").containsMatchIn(before) && !rx("NEGATION_RE").containsMatchIn(hit.value)) return true
        }
        return false
    }

    private fun namedKinds(message: String) = brands.filter { it.rx.containsMatchIn(message) }.map { it.kind }.toSet()

    fun normalizeSender(sender: String?): String {
        val s = pyStrip(sender ?: "")
        val digits = s.replace(PyRe.compile("[\\s()-]"), "").trimStart('+')
        if (digits.isNotEmpty() && digits.all { Character.isDigit(it) }) {
            if (digits.length == 12 && digits.startsWith("91")) return digits.substring(2)
            if (digits.length == 11 && digits.startsWith("0")) return digits.substring(1)
            return digits
        }
        return s
    }

    fun signals(message: String, sender: String? = null): Signals {
        val s = Signals()
        val m = message
        s.hasUrl = flag(rx("URL_RE").containsMatchIn(m) || rx("BARE_DOMAIN_RE").containsMatchIn(m))
        s.hasShortener = flag(rx("SHORTENER_RE").containsMatchIn(m))
        s.hasApk = flag(rx("APK_RE").containsMatchIn(m))
        s.asksSecret = flag(rx("SECRET_RE").containsMatchIn(m))
        s.hasUpi = flag(rx("UPI_RE").containsMatchIn(m))
        s.urgency = flag(rx("URGENCY_RE").containsMatchIn(m))
        s.mentionsMoney = flag(rx("MONEY_RE").containsMatchIn(m))
        s.bankContext = flag(rx("BANK_WORDS_RE").containsMatchIn(m))
        s.rewardBait = flag(rx("REWARD_RE").containsMatchIn(m))
        s.bankLinkNotBankin = flag(s.bankContext == 1 && s.hasUrl == 1 && !reBankIn.containsMatchIn(m))
        s.senderIs10Digit = flag(!sender.isNullOrEmpty() && rx("TEN_DIGIT_RE").matchStart(normalizeSender(sender)))

        val kinds = namedKinds(m)
        val namesBank = "bank" in kinds || "regulator" in kinds || rx("NETBANKING_RE").containsMatchIn(m)
        val r = s.reasons
        var linkReason = false
        if (s.hasApk == 1) {
            r.add("asks you to install an app file (.apk) from a link instead of the Play Store")
            linkReason = true
        }
        if (s.asksSecret == 1) r.add("talks about your OTP, PIN, CVV or password")
        else if (rx("BANK_DETAILS_RE").containsMatchIn(m)) r.add("asks for your bank account details")
        if (s.bankLinkNotBankin == 1 && namesBank) {
            r.add(genericBankLink)
            linkReason = true
        } else if (s.hasUrl == 1 && "government" in kinds && !rx("GOV_SITE_RE").containsMatchIn(m)) {
            r.add("claims to be from a government office, but the link is not on an official .gov.in website")
            linkReason = true
        }
        if (s.senderIs10Digit == 1 && namesBank) {
            r.add("sent from a 10-digit mobile number, but real banks send SMS from registered sender IDs")
        } else if (s.senderIs10Digit == 1 &&
            (s.hasUrl == 1 || s.mentionsMoney == 1 || s.urgency == 1 || s.asksSecret == 1 || s.bankContext == 1)) {
            r.add("sent from a personal 10-digit mobile number, not a registered business sender ID")
        }
        if (rx("CALL_NUMBER_RE").containsMatchIn(m)) r.add("asks you to call or WhatsApp a mobile number")
        if (s.hasShortener == 1) {
            r.add("uses a short link that hides the real website")
            linkReason = true
        }
        if (s.hasUpi == 1) r.add("contains a UPI ID for sending money")
        if (s.rewardBait == 1) r.add("promises a prize, refund or cashback")
        if (s.urgency == 1) r.add("rushes you with a deadline or a threat to block or cut off a service")
        if (s.hasUrl == 1 && !linkReason) r.add(genericLink)
        return s
    }

    private fun flag(b: Boolean) = if (b) 1 else 0

    // --- senders.py --------------------------------------------------------------------------
    fun classifySender(sender: String?): SenderInfo {
        val raw = pyStrip(sender ?: "")
        if (raw.isEmpty()) return SenderInfo("unknown")
        if (rx("TEN_DIGIT_RE").matchStart(normalizeSender(raw))) return SenderInfo("mobile")
        val up = raw.replace(PyRe.compile("\\s+"), "").uppercase()
        val m = rx("HEADER_RE").toPattern().matcher(up)
        if (m.lookingAt()) {
            val g2 = m.group(2)
            if (m.group(1) != null || !(g2.isNotEmpty() && g2.all { Character.isDigit(it) })) {
                return SenderInfo("business", m.group(3) ?: "", up)
            }
        }
        return SenderInfo("other")
    }

    private fun root(info: SenderInfo): String {
        val m = rx("HEADER_RE").toPattern().matcher(info.header)
        return if (m.lookingAt()) m.group(2) ?: "" else ""
    }

    private fun senderOdds(info: SenderInfo, sig: Signals, rules: Set<String>): Double {
        if (info.kind == "business") {
            if (info.suffix.isEmpty() && "suffix" in rules) return noSuffixOdds
            return headerOdds[info.suffix] ?: 1.0
        }
        val risky = sig.hasUrl == 1 || sig.mentionsMoney == 1 || sig.urgency == 1 || sig.asksSecret == 1 ||
            sig.bankContext == 1 || sig.rewardBait == 1
        if (info.kind == "mobile" && risky) return mobileRiskyOdds
        return 1.0
    }

    // --- brands.py -----------------------------------------------------------------------------
    private fun brandsNamed(text: String) = brands.filter { it.rx.containsMatchIn(text) }

    private fun headerBelongs(root: String, names: List<String>): Boolean {
        val r = root.uppercase()
        return names.any { name -> (headerRoots[name] ?: emptyList()).any { it in r } }
    }

    // --- detector.py ---------------------------------------------------------------------------
    private fun oddsTimes(p: Double, k: Double): Double {
        val q = p.coerceIn(1e-6, 1 - 1e-6)
        val o = q / (1 - q) * k
        return o / (1 + o)
    }

    private fun applyLinks(score: Double, links: List<LinkVerdict>, sig: Signals): Pair<Double, Boolean> {
        if (links.isEmpty()) return Pair(score, false)
        if (links.all { it.official }) {
            sig.reasons.remove(genericBankLink)                  // the link is the bank's own site
            return Pair(oddsTimes(score, officialLinkOdds), false)
        }
        val risky = links.filter { it.verdict != "safe" }
        val new = ArrayList<String>()
        for (v in risky.sortedByDescending { it.score }) {
            for (r in v.reasons.take(2)) {
                if (r !in new && r !in sig.reasons && !(sig.hasApk == 1 && ".apk" in r)) new.add(r)
            }
        }
        if (new.isNotEmpty()) {                                  // link reasons first: the most specific
            val rest = sig.reasons.filter { it != genericLink }
            sig.reasons.clear()
            sig.reasons.addAll(new + rest)
        }
        if (links.any { it.decisive }) return Pair(maxOf(score, 0.95), true)
        val k = risky.filter { it.kind != "shortener" }.map { linkOdds[it.verdict] ?: 1.0 }.maxOrNull() ?: 1.0
        return Pair(if (k != 1.0) oddsTimes(score, k) else score, false)
    }

    private fun unsafeLink(links: List<LinkVerdict>) = links.any { it.verdict != "safe" }

    private fun brandMismatch(text: String, info: SenderInfo, links: List<LinkVerdict>): String? {
        val named = brandsNamed(text)
        val risky = named.filter { it.kind in riskyKinds && it.name in headerRoots }.map { it.name }
        if (risky.isEmpty() || info.kind != "business") return null
        if (!(rx("RISKY_CLAIM_RE").containsMatchIn(text) || asksForSecret(text) ||
                rx("BANK_DETAILS_RE").containsMatchIn(text) || unsafeLink(links))) return null
        return if (headerBelongs(root(info), named.map { it.name })) null else risky[0]
    }

    private fun capReason(text: String, links: List<LinkVerdict>): String? {
        if (asksForSecret(text)) return "asks you to share or enter an OTP, PIN or password, which a genuine sender never does"
        if (unsafeLink(links) && brandsNamed(text).any { it.kind in riskyKinds }) {
            return "names a bank, payment app or government office and carries a link that is not safe"
        }
        return null
    }

    class Decision(val score: Double, val verdict: String, val sig: Signals)

    /** detector.decide(): the text score, then the sender's odds, the links and the sender rules. */
    fun decide(textScore: Double, text: String, sender: String?, links: List<LinkVerdict>,
               rules: Set<String> = senderRules): Decision {
        var score = textScore
        val sig = signals(text, sender)
        var cap: String? = null
        val info = classifySender(sender)
        var k = senderOdds(info, sig, rules)
        if (k < 1 && "brand" in rules) {
            val brand = brandMismatch(text, info, links)
            if (brand != null) {
                k = 1.0
                sig.reasons.add(0, "names $brand, but its sender ID does not look like one of $brand's")
            }
        }
        if (k < 1 && "cap" in rules && score >= suspiciousAt) cap = capReason(text, links)
        if (k != 1.0) score = oddsTimes(score, k)
        val (linked, decisive) = applyLinks(score, links, sig)
        score = linked
        if (cap != null && score < suspiciousAt) {               // the sender (and official links) may not clear it
            score = suspiciousAt
            sig.reasons.add(0, cap)
        }
        var verdict = verdictFor(score)
        if (sig.hasApk == 1 && sig.hasUrl == 1) {                // an .apk link is near-certainly malicious
            verdict = "dangerous"
            score = maxOf(score, 0.95)
        }
        if (decisive) verdict = "dangerous"
        return Decision(score, verdict, sig)
    }

    /** advisor/categorize.py: which playbook. */
    fun category(text: String, s: Signals): String {
        if (s.hasApk == 1) return "apk_malware_link"
        if (rx("DIGITAL_ARREST_RE").containsMatchIn(text)) return "digital_arrest_scam"
        if (rx("DELIVERY_RE").containsMatchIn(text)) return "delivery_fee_scam"
        if (rx("JOB_RE").containsMatchIn(text)) return "job_task_scam"
        if (s.rewardBait == 1) return "lottery_reward_scam"
        if (rx("UTILITY_RE").containsMatchIn(text)) return "utility_disconnection_scam"
        if (s.asksSecret == 1 && s.bankContext == 0) return "otp_theft"
        if (s.bankContext == 1) return "bank_kyc_scam"
        val risky = s.hasUrl == 1 || s.hasApk == 1 || s.asksSecret == 1 || s.hasUpi == 1 || s.urgency == 1 ||
            s.bankContext == 1 || s.rewardBait == 1
        return if (risky) "generic_suspicious" else "promo_spam"
    }

    /** detectors/files/names.app_file_in_text: an app or program file named in a chat ("apk"), or null. */
    fun appFileInText(text: String): String? {
        for (m in rx("CHAT_FILE_RE").findAll(text)) {
            val before = text.substring(maxOf(0, m.range.first - 8), m.range.first).lowercase()
            if ("http" in before || "www." in before) continue
            return m.groupValues[2].lowercase()
        }
        return null
    }

    fun isAppExt(ext: String) = ext in appExt
}
