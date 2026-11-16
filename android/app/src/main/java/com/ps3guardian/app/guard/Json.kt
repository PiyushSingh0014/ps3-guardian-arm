package com.ps3guardian.app.guard

/**
 * Reads the guard's own asset files (written by scripts/export_phone_guard.py). Objects become
 * Map<String, Any?>, arrays List<Any?>, numbers Double; strings, booleans and null as they are.
 * Plain Kotlin, so the same code runs in the app and in the tests on a computer.
 */
internal class Json private constructor(private val s: String) {
    private var i = 0

    companion object {
        fun parse(text: String): Any? {
            val p = Json(text)
            p.ws()
            val v = p.value()
            p.ws()
            require(p.i == p.s.length) { "extra text after the JSON value at ${p.i}" }
            return v
        }
    }

    private fun ws() {
        while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++
    }

    private fun value(): Any? {
        require(i < s.length) { "the JSON ends too early" }
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> word("true", true)
            'f' -> word("false", false)
            'n' -> word("null", null)
            else -> if (c == '-' || c in '0'..'9') num() else throw IllegalArgumentException("bad JSON at $i")
        }
    }

    private fun word(w: String, v: Any?): Any? {
        require(s.startsWith(w, i)) { "bad JSON at $i" }
        i += w.length
        return v
    }

    private fun obj(): Map<String, Any?> {
        i++
        val m = LinkedHashMap<String, Any?>()
        ws()
        if (s[i] == '}') { i++; return m }
        while (true) {
            ws()
            val k = str()
            ws()
            require(s[i] == ':') { "bad JSON at $i" }
            i++
            ws()
            m[k] = value()
            ws()
            when (s[i]) {
                ',' -> i++
                '}' -> { i++; return m }
                else -> throw IllegalArgumentException("bad JSON at $i")
            }
        }
    }

    private fun arr(): List<Any?> {
        i++
        val a = ArrayList<Any?>()
        ws()
        if (s[i] == ']') { i++; return a }
        while (true) {
            ws()
            a.add(value())
            ws()
            when (s[i]) {
                ',' -> i++
                ']' -> { i++; return a }
                else -> throw IllegalArgumentException("bad JSON at $i")
            }
        }
    }

    private fun str(): String {
        require(s[i] == '"') { "bad JSON at $i" }
        i++
        val sb = StringBuilder()
        while (true) {
            val c = s[i++]
            when (c) {
                '"' -> return sb.toString()
                '\\' -> when (val e = s[i++]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> throw IllegalArgumentException("bad escape \\$e at $i")
                }
                else -> sb.append(c)
            }
        }
    }

    private fun num(): Double {
        val start = i
        while (i < s.length && (s[i] in '0'..'9' || s[i] == '-' || s[i] == '+' || s[i] == '.' || s[i] == 'e' || s[i] == 'E')) i++
        return s.substring(start, i).toDouble()
    }
}

@Suppress("UNCHECKED_CAST")
internal fun Any?.obj(): Map<String, Any?> = this as Map<String, Any?>

@Suppress("UNCHECKED_CAST")
internal fun Any?.list(): List<Any?> = this as List<Any?>

internal fun Any?.strings(): List<String> = list().map { it as String }

internal fun Any?.num(): Double = this as Double

/** The JSON reader for the tests on a computer (scripts/check_phone_guard.py). */
object JsonForTests {
    fun parse(text: String): Any? = Json.parse(text)
}
