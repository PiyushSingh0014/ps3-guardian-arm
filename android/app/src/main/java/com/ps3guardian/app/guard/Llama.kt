package com.ps3guardian.app.guard

/** What Llama is asked about one message, and the case its answer is held to. */
class LlamaPrompt(val text: String, val evidence: String, val maxNewTokens: Int, val language: String)

/** Llama's answer after the Pi's checks (advisor/validator.Checked): sentence 1, sentence 2. */
class LlamaChecked(val what: String, val why: String, val flags: List<String>, val ok: Boolean)

/**
 * The Pi's Llama prompt for messages (advisor/prompt.py, v4: evidence only, never the message
 * text, and worked examples) and its answer checker (advisor/validator.py: the verdict, the
 * language, links and phone numbers, and every sentence held to its evidence), from llama.json.
 */
class LlamaText internal constructor(d: Map<String, Any?>, private val books: Map<String, Any?>) {
    private val system = d["system"] as String
    private val langNames = d["lang_names"].obj().mapValues { it.value as String }
    private val resultText = d["result_text"].obj().mapValues { it.value as String }
    private val examples = d["examples"].list().map { it.obj() }
    private val maxSigns = d["max_signs"].num().toInt()
    private val maxNew = d["max_new_tokens"].obj().mapValues { it.value.num().toInt() }
    private val includeBos = d["include_bos"] as Boolean
    private val special = PyRe.compile(d["special_token"] as String)
    private val kindLabel = d["kind_label"].obj().mapValues { it.value as String }
    private val skip = d["skip_severities"].strings().toSet()
    private val allowedDomains = d["allowed_domains"].strings().toSet()
    private val allowedNumbers = d["allowed_numbers"].strings().toSet()
    private val maxSentences = d["max_sentences"].num().toInt()
    private val maxWords = d["max_words"].obj().mapValues { it.value.num().toInt() }
    private val p = d["patterns"].obj().mapValues { PyRe.of(it.value) }
    private fun rx(name: String) = p[name] ?: throw IllegalStateException("no pattern $name")

    private class Sub(val rx: Regex, val repl: String)

    private fun subs(key: String, d: Map<String, Any?>) = d[key].list().map {
        val e = it.list()
        Sub(PyRe.compile(e[0] as String, e[1] as Boolean), pyReplacement(e[2] as String))
    }

    private val hedges = subs("hedges", d)
    private val glossary = subs("glossary", d)
    private val organisations = d["organisations"].list().map {
        val e = it.list()
        Pair(e[0] as String, PyRe.compile(e[1] as String, e[2] as Boolean))
    }
    private val schemeWww = Regex("^(?:https?://)?(?:www\\.)?")
    private val nonDigit = PyRe.compile("\\D")

    // --- the prompt (advisor/prompt.py) ----------------------------------------------------------

    private fun field(text: String, limit: Int = 220): String =
        cutCodePoints(pySplit(special.replace(text, " ")).joinToString(" "), limit)

    private fun header(role: String) = "<|start_header_id|>$role<|end_header_id|>\n\n"

    private fun formatCase(result: String, scamType: String, pretends: String, signs: List<String>,
                           fact: String, wants: String): String {
        val lines = mutableListOf("Scam type: ${field(scamType)}")
        if (wants.isNotEmpty()) lines.add("Scammer wants: ${field(wants)}")
        if (fact.isNotEmpty()) lines.add("Fact: ${field(fact, 300)}")
        lines += listOf("Scanner result: ${field(result)}", "Pretends to be: ${field(pretends)}", "Warning signs:")
        val s = signs.take(maxSigns).map { "- ${field(it)}" }
        lines += s.ifEmpty { listOf("- text patterns common in scam messages") }
        return lines.joinToString("\n")
    }

    private fun staticPrefix(language: String): String {
        val lang = if (language in langNames) language else "en"
        val sb = StringBuilder()
        if (includeBos) sb.append("<|begin_of_text|>")
        sb.append(header("system")).append(system.replace("{lang}", langNames[lang]!!)).append("<|eot_id|>")
        for (ex in examples) {
            val case = formatCase(ex["result"] as String, ex["scam_type"] as String, ex["pretends"] as String,
                ex["signs"].strings(), ex["fact"] as String, ex["wants"] as String)
            sb.append(header("user")).append(case).append("<|eot_id|>").append(header("assistant"))
                .append(ex["answer"].obj()[lang] as String).append("<|eot_id|>")
        }
        return sb.toString()
    }

    /** The prompt for a phone verdict, or null when there is nothing to explain (safe, or promotional). */
    fun prompt(r: GuardResult, language: String): LlamaPrompt? =
        prompt(r.verdict, r.category, r.reasons, r.claimsToBe, r.claimsKind, language)

    /** advisor.needs_llm and prompt.build_prompt for a message: verdict, scam type, warning signs, and who it claims to be. */
    fun prompt(verdict: String, category: String, reasons: List<String>, claimsToBe: String?, claimsKind: String?,
               language: String): LlamaPrompt? {
        if (verdict == "safe") return null
        val book = (books[category] ?: books["generic_suspicious"]).obj()
        if ((book["severity"] as String) in skip) return null
        val result = resultText[verdict] ?: resultText["suspicious"]!!
        val pretends = if (!claimsToBe.isNullOrEmpty()) {
            claimsKind?.let { kindLabel[it] }?.let { "$claimsToBe ($it)" } ?: claimsToBe     // findings.describe_org
        } else (book["pretends"] as String).ifEmpty { "someone you might trust" }
        val case = formatCase(result, book["title"] as String, pretends, reasons, book["fact"] as String,
            book["wants"] as String)
        val text = staticPrefix(language) + header("user") + case + "<|eot_id|>" + header("assistant")
        return LlamaPrompt(text, case, maxNew[language] ?: maxNew["en"]!!, language)
    }

    // --- the answer checker (advisor/validator.py) ----------------------------------------------

    fun check(raw: String, verdict: String, language: String, evidence: String?): LlamaChecked {
        val flags = ArrayList<String>()
        var text = rx("_SPECIAL_RE").split(raw, 2)[0]                // stop at the first chat-template token
        text = rx("_PREAMBLE_RE").replace(pySplit(text).joinToString(" "), "")
        if (text.isEmpty()) {
            flags.add("empty LLM output")
            return LlamaChecked("", "", flags, false)
        }
        if ((verdict == "suspicious" || verdict == "dangerous") && rx("_CONTRADICTION_RE").containsMatchIn(text)) {
            flags.add("LLM output contradicts the verdict; template used instead")
            return LlamaChecked("", "", flags, false)
        }
        if (language == "hi" && !rx("_DEVANAGARI_RE").containsMatchIn(text)) {
            flags.add("LLM answer is not in Hindi; template used instead")
            return LlamaChecked("", "", flags, false)
        }
        val sentences = splitSentences(text)
        val complete = sentences.filter { it.isNotEmpty() && it.last() in ".!?।" }
        if (complete.size < sentences.size) flags.add("dropped an unfinished sentence (token limit)")
        if (complete.size > maxSentences) flags.add("kept the first $maxSentences of ${complete.size} sentences")
        val kept = ArrayList<String>()
        for (rawS in complete.take(maxSentences)) {
            val before = flags.size
            val s = scrub(rawS, flags)
            if (flags.size > before) {
                flags.add("dropped a sentence that contained a number or link")
                kept.add("")
                continue
            }
            val whyNot = if (evidence != null) ungrounded(s, evidence, language) else null
            if (whyNot != null) {
                flags.add("dropped a sentence: $whyNot")
                kept.add("")
                continue
            }
            val fixed = fixGlossary(if (verdict == "dangerous") dehedge(s) else s)
            if (fixed != s) flags.add("fixed wording (hedge or KYC expansion)")
            kept.add(upperFirst(fixed))
        }
        val limit = maxWords[language] ?: maxWords["en"]!!
        while (kept.isNotEmpty() && kept.sumOf { pySplit(it).size } > limit) {
            kept.removeAt(kept.size - 1)                              // drop sentence 2 first
            flags.add("answer longer than $limit words; shortened")
        }
        val what = kept.getOrElse(0) { "" }
        val why = kept.getOrElse(1) { "" }
        val ok = what.isNotEmpty() || why.isNotEmpty()
        if (!ok && "empty LLM output" !in flags) flags.add("no usable sentence in the LLM answer")
        return LlamaChecked(what, why, flags, ok)
    }

    private fun splitSentences(text: String): List<String> {
        val out = ArrayList<String>()
        for (part in rx("_SPLIT_RE").split(pyStrip(text))) {
            if (out.isNotEmpty() && rx("_ABBREV_RE").containsMatchIn(out.last())) out[out.size - 1] = out.last() + " " + part
            else if (pyStrip(part).isNotEmpty()) out.add(pyStrip(part))
        }
        return out
    }

    private fun scrub(text: String, flags: MutableList<String>): String {
        val noLinks = rx("_URL_RE").replace(text) { m ->
            val raw = m.value
            val host = schemeWww.replace(raw.lowercase(), "").split("/")[0].trimEnd { it in ".,;:)" }
            if (host in allowedDomains) raw else {
                flags.add("removed link: $raw")
                "[link removed]"
            }
        }
        return rx("_PHONE_RE").replace(noLinks) { m ->
            val raw = m.value
            val digits = nonDigit.replace(raw, "")
            if (digits in allowedNumbers || digits.codePointCount(0, digits.length) < 6) raw else {
                flags.add("removed number: ${pyStrip(raw)}")
                "[number removed]"
            }
        }
    }

    private fun asciiDigits(s: String): String {
        if (s.none { it in '०'..'९' }) return s
        val sb = StringBuilder(s.length)
        for (c in s) sb.append(if (c in '०'..'९') '0' + (c - '०') else c)
        return sb.toString()
    }

    private fun saysAbsolute(word: String, evidence: String): Boolean {
        if (PyRe.compile("\\b$word\\b", true).containsMatchIn(evidence)) return true
        return word == "never" && rx("_NO_EVER_RE").containsMatchIn(evidence)
    }

    private fun factLine(evidence: String): String =
        pySplitLines(evidence).firstOrNull { it.startsWith("Fact:") }?.substring("Fact:".length) ?: ""

    /** Why a sentence says more than the evidence Llama was given, or null. */
    fun ungrounded(sentence: String, evidence: String, language: String): String? {
        val sent = asciiDigits(sentence)
        val ev = asciiDigits(evidence)
        val known = rx("_NUMBER_RE").findAll(ev).map { it.value }.toSet() + allowedNumbers
        rx("_NUMBER_RE").findAll(sent).map { it.value }.firstOrNull { it !in known }?.let {
            return "a number the evidence does not have ($it)"
        }
        for ((name, orx) in organisations) {
            if (orx.containsMatchIn(sent) && !orx.containsMatchIn(ev)) return "names $name, which the evidence does not"
        }
        if (rx("_DOMAIN_CLAIM_RE").containsMatchIn(sent)) {
            return "says where the link goes, or that .bank.in or .gov.in sites are not real"
        }
        if (language == "en") {
            for (word in rx("_ABSOLUTE_RE").findAll(sent).map { it.groupValues[1].lowercase() }.toCollection(LinkedHashSet())) {
                if (!saysAbsolute(word, ev)) return "says \"$word\", which the evidence does not"
            }
            if (rx("_RULE_RE").containsMatchIn(sent) && !rx("_FACT_RULE_RE").containsMatchIn(factLine(ev))) {
                return "a rule about what real companies or people do, which the fact does not state"
            }
        }
        return null
    }

    private fun dehedge(s: String): String {
        var t = s
        for (h in hedges) t = h.rx.replace(t, h.repl)
        return t
    }

    private fun fixGlossary(s: String): String {
        var t = s
        for (g in glossary) t = g.rx.replace(t, g.repl)
        return t
    }

    private fun upperFirst(s: String): String {
        if (s.isEmpty()) return s
        val n = Character.charCount(s.codePointAt(0))
        return s.substring(0, n).uppercase() + s.substring(n)
    }

    companion object {
        /** Python's replacement text ("\1 ") in Java's form ("$1 "). */
        internal fun pyReplacement(r: String): String {
            val sb = StringBuilder()
            var i = 0
            while (i < r.length) {
                val c = r[i]
                when {
                    c == '\\' && i + 1 < r.length && r[i + 1].isDigit() -> { sb.append('$').append(r[i + 1]); i += 2 }
                    c == '$' -> { sb.append("\\$"); i++ }
                    c == '\\' -> { sb.append("\\\\"); i++ }
                    else -> { sb.append(c); i++ }
                }
            }
            return sb.toString()
        }

        internal fun cutCodePoints(s: String, limit: Int): String =
            if (s.codePointCount(0, s.length) <= limit) s else s.substring(0, s.offsetByCodePoints(0, limit))

        /** Python's str.splitlines(): \n, \r, \r\n, \v, \f, \x1c-\x1e, \x85, \u2028 and \u2029 end a line. */
        internal fun pySplitLines(s: String): List<String> {
            val out = ArrayList<String>()
            var start = 0
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '\n' || c == '\r' || c == '\u000B' || c == '\u000C' || c in '\u001C'..'\u001E' ||
                    c == '\u0085' || c == '\u2028' || c == '\u2029') {
                    out.add(s.substring(start, i))
                    i += if (c == '\r' && i + 1 < s.length && s[i + 1] == '\n') 2 else 1
                    start = i
                } else i++
            }
            if (start < s.length) out.add(s.substring(start))
            return out
        }
    }
}
