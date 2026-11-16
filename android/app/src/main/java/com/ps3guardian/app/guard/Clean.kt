package com.ps3guardian.app.guard

import java.math.BigInteger
import java.text.Normalizer

/**
 * The Pi's text cleaning (detectors/sms/train_baseline.clean_text), so the model on the phone reads
 * the same text as the one on the Pi: HTML entities decoded as Python's html.unescape does, ftfy's
 * simple fixes (C1 controls read as Windows-1252, ligatures, full-width letters, curly quotes,
 * line breaks, terminal escapes, control characters, NFC), the UCI "<#>" placeholder and lost
 * characters removed, and the whitespace collapsed. ftfy's repair of mojibake ("IÂ’m") is left
 * out: a phone receives proper Unicode.
 */
class Cleaner internal constructor(t: Map<String, Any?>) {
    private val entities: Map<String, String> = t["entities"].obj().mapValues { it.value as String }
    private val invalidCharrefs: Map<Int, String> =
        t["invalid_charrefs"].obj().entries.associate { it.key.toInt() to it.value as String }
    private val invalidCodepoints: Set<Int> = t["invalid_codepoints"].list().map { it.num().toInt() }.toSet()
    private val c1: Map<Char, String> = t["c1"].obj().entries.associate { it.key.toInt().toChar() to it.value as String }
    private val ligatures: Map<Char, String> =
        t["ligatures"].obj().entries.associate { it.key.toInt().toChar() to it.value as String }
    private val width: Map<Char, String> = t["width"].obj().entries.associate { it.key.toInt().toChar() to it.value as String }
    private val controls: Set<Int> = t["control_chars"].list().map { it.num().toInt() }.toSet()
    private val singleQuote = PyRe.compile(t["single_quote"] as String)
    private val doubleQuote = PyRe.compile(t["double_quote"] as String)

    private val charref = Regex("&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\\t\\n\\f <\\&#;]{1,32};?)")
    private val ansi = Regex("\u001B\\[((?:\\d|;)*)([a-zA-Z])")
    private val maxCodepoint = BigInteger.valueOf(0x10FFFF)

    /** clean_text(): what the model, the rules and the link checker read. */
    fun clean(text: String): String {
        var t = unescape(text)
        t = ftfy(t)
        t = t.replace("<#>", " ").replace("�", " ")
        return pySplit(t).joinToString(" ")
    }

    /** Python's html.unescape. */
    fun unescape(s: String): String {
        if ('&' !in s) return s
        return charref.replace(s) { m -> charref(m.groupValues[1]) }
    }

    private fun charref(s: String): String {
        if (s[0] == '#') {
            val hex = s[1] == 'x' || s[1] == 'X'
            val digits = (if (hex) s.substring(2) else s.substring(1)).trimEnd(';')
            val big = BigInteger(digits, if (hex) 16 else 10)
            val n = if (big > maxCodepoint) -1 else big.toInt()
            if (n >= 0) invalidCharrefs[n]?.let { return it }
            if (n < 0 || n in 0xD800..0xDFFF) return "�"
            if (n in invalidCodepoints) return ""
            return String(Character.toChars(n))
        }
        entities[s]?.let { return it }
        for (x in s.length - 1 downTo 2) {
            entities[s.substring(0, x)]?.let { return it + s.substring(x) }
        }
        return "&$s"
    }

    /** ftfy.fix_text's fixes that matter for text from a phone, in ftfy's order, until nothing changes. */
    private fun ftfy(text: String): String {
        var t = text
        while (true) {
            val before = t
            t = mapChars(t, c1)
            t = mapChars(t, ligatures)
            t = mapChars(t, width)
            t = singleQuote.replace(doubleQuote.replace(t, "\""), "'")
            t = t.replace("\r\n", "\n").replace("\r", "\n").replace(" ", "\n").replace(" ", "\n")
                .replace("\u0085", "\n")
            t = ansi.replace(t, "")
            t = removeControls(t)
            t = Normalizer.normalize(t, Normalizer.Form.NFC)
            if (t == before) return t
        }
    }

    private fun mapChars(s: String, map: Map<Char, String>): String {
        if (s.none { it in map }) return s
        val sb = StringBuilder(s.length)
        for (c in s) sb.append(map[c] ?: c)
        return sb.toString()
    }

    private fun removeControls(s: String): String {
        if (s.none { it.code in controls }) return s
        val sb = StringBuilder(s.length)
        for (c in s) if (c.code !in controls) sb.append(c)
        return sb.toString()
    }
}
