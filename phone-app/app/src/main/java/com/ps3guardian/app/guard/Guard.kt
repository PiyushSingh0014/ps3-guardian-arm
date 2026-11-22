package com.ps3guardian.app.guard

/** Where the guard's data files come from: the app's assets, or a folder in the tests. */
fun interface GuardFiles {
    fun read(name: String): ByteArray
}

/** What the phone decided about one message, with the playbook's advice. */
class GuardResult(
    val verdict: String,                 // safe, suspicious or dangerous
    val score: Double,
    val category: String,                // the playbook, e.g. bank_kyc_scam ("none" when safe)
    val reasons: List<String>,
    val headline: String,
    val what: String,
    val why: String,
    val steps: List<String>,
    val links: List<LinkVerdict>,
    val millis: Double,                  // how long the check took on this phone
    // Who the message claims to be (from the fixed brand list, or the brand a link imitates) and its
    // kind ("bank"): the only words about the sender that Llama is told (detector.py: entities).
    val claimsToBe: String? = null,
    val claimsKind: String? = null,
    // What the message says, in fixed words (detectors/sms/says.py): shown to Llama (prompt v5) and on the alert.
    val says: List<String> = emptyList(),
) {
    /** The advice as notification text: what, why, then the steps (as Notifier.adviceText). */
    fun adviceText(): String {
        val sb = StringBuilder()
        for (part in listOf(what, why)) if (part.isNotBlank()) sb.append(part).append(' ')
        for (s in steps) sb.append("\n• ").append(s)
        return sb.toString().trim()
    }
}

/**
 * Phone Guard (update 43): the Pi's checks for messages and links, run on the phone itself, so a
 * verdict needs no network at all. Same model, rules, lists and playbooks as the Pi, copied by
 * scripts/export_phone_guard.py; only the public phishing list stays on the Pi, which adds it when
 * the phone is at home. Llama's prompt and answer checks are here too ([llama], update 44); the
 * model itself is copied from the Pi (PhoneLlama).
 */
class Guard(private val files: GuardFiles) {
    private fun json(name: String) = Json.parse(String(files.read(name), Charsets.UTF_8)).obj()

    private val smsData = json("sms.json")
    private val cleaner = Cleaner(json("text.json"))
    private val model = SmsModel(json("sms_model.json"))
    val links = LinkChecker(json("links.json"), smsData, LinkModel(files.read("link_model.bin")))
    val rules = SmsRules(smsData)
    private val playbooks = json("playbooks.json")
    private val books = playbooks["books"].obj()
    private val maxSteps = playbooks["max_steps"].num().toInt()
    private val safe = playbooks["safe"].obj()
    private val llamaData = json("llama.json")
    private val preferred = llamaData["preferred"].obj().mapValues { it.value.strings() }

    /** The Pi's Llama prompt and answer checks for messages (update 44), for Llama on this phone. */
    val llama = LlamaText(llamaData, books)

    /** The message as the model reads it (the Pi's clean_text). */
    fun clean(text: String) = cleaner.clean(text)

    /** detectors/sms/detector.SmsDetector.check(), on the phone. */
    fun check(message: String, sender: String?): GuardResult {
        val start = System.nanoTime()
        val text = cleaner.clean(message)
        val linkVerdicts = links.checkText(text)
        val (pThreat, pNormal) = model.probs(text, rules.signals(text).vector())
        val info = rules.classifySender(sender)
        val textScore = if (info.kind == "business") pThreat else 1.0 - pNormal
        val d = rules.decide(textScore, text, sender, linkVerdicts)
        var score = d.score
        var verdict = d.verdict
        var category = if (verdict != "safe") rules.category(text, d.sig) else "none"
        if ((category == "generic_suspicious" || category == "promo_spam") &&
            linkVerdicts.any { it.verdict != "safe" && it.kind != "shortener" && it.kind != "chat" }) {
            category = "phishing_link"
        }
        // Who it claims to be, from the brand list (or the brand a link's address imitates), picked
        // for the scam type before an app file makes it "app_file", as on the Pi.
        var claims = rules.claimedIdentity(text, category, preferred)
        if (claims == null) {
            linkVerdicts.firstOrNull { it.imitates && it.verdict != "safe" }?.let { claims = Pair(it.brand!!, it.brandKind ?: "") }
        }
        var reasons = d.sig.reasons.toMutableList()
        val app = rules.appFileInText(message)          // "Wedding_Invitation.apk": the name a chat app shows
        if (app != null) {
            score = maxOf(score, 0.97)
            verdict = "dangerous"
            category = "app_file"
            if (linkVerdicts.isEmpty()) reasons = reasons.filter { "app file (.apk) from a link" !in it }.toMutableList()
            reasons.add(0, if (rules.isAppExt(app)) "the chat brought an Android app (APK) file, not a document or a photo"
            else "the chat brought a program file, not a document or a photo")
        }
        score = pyRound(score, 3)
        val millis = (System.nanoTime() - start) / 1e6
        val claimsToBe = claims?.first
        val claimsKind = claims?.second?.ifEmpty { null }
        if (verdict == "safe") {
            return GuardResult(verdict, score, category, reasons, safe["headline"] as String, safe["what"] as String,
                safe["why"] as String, safe["steps"].strings(), linkVerdicts, millis, claimsToBe, claimsKind)
        }
        val says = rules.says(text)                     // flagged only, as on the Pi (detector.py)
        val book = (books[category] ?: books["generic_suspicious"]).obj()
        val steps = book["steps"].strings()
        val chosen = (1..minOf(maxSteps, steps.size)).toMutableList()
        steps.forEachIndexed { i, s -> if ("1930" in s && (i + 1) !in chosen) chosen.add(i + 1) }
        val why = if (reasons.isNotEmpty()) "Red flags: " + reasons.take(3).joinToString("; ") + "."
        else "It matches text patterns common in scam messages."
        return GuardResult(verdict, score, category, reasons, "${verdict.uppercase()}: ${book["title"]}",
            book["summary"] as String, why, chosen.map { steps[it - 1] }, linkVerdicts, millis, claimsToBe, claimsKind, says)
    }
}
