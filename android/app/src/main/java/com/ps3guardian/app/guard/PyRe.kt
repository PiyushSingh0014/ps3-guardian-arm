package com.ps3guardian.app.guard

/**
 * Python `re` patterns run by Java's regex engine (and Android's), with Python's meaning of \w, \b,
 * \d and \s for text: Unicode letters, numbers and spaces. Java's own \w and \b are ASCII-only and
 * Android's are Unicode, so they are spelled out here: the phone, the tests on a computer and the
 * Pi then agree, also on Hindi.
 */
object PyRe {
    private const val W = "\\p{L}\\p{N}_"                     // Python's \w: str.isalnum() or "_"
    private const val D = "\\p{Nd}"                           // Python's \d: any decimal digit
    // Python's \s: what str.isspace() accepts
    private const val S = "\\t\\n\\x0B\\f\\r\\x1C-\\x1F \\x85\\xA0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000"
    private const val B = "(?:(?<=[$W])(?![$W])|(?<![$W])(?=[$W]))"
    private const val NB = "(?:(?<=[$W])(?=[$W])|(?<![$W])(?![$W]))"

    fun translate(src: String): String {
        val out = StringBuilder()
        var inClass = false
        var i = 0
        while (i < src.length) {
            val c = src[i]
            if (c == '\\' && i + 1 < src.length) {
                val e = src[i + 1]
                val rep: String? = if (inClass) when (e) {
                    'w' -> W
                    'd' -> D
                    's' -> S
                    'W' -> "[^$W]"
                    'D' -> "[^$D]"
                    'S' -> "[^$S]"
                    else -> null
                } else when (e) {
                    'w' -> "[$W]"
                    'W' -> "[^$W]"
                    'd' -> "[$D]"
                    'D' -> "[^$D]"
                    's' -> "[$S]"
                    'S' -> "[^$S]"
                    'b' -> B
                    'B' -> NB
                    'Z' -> "\\z"
                    else -> null
                }
                if (rep != null) out.append(rep) else out.append(c).append(e)
                i += 2
                continue
            }
            if (inClass) {
                when (c) {
                    ']' -> { inClass = false; out.append(c) }
                    '[' -> out.append("\\[")          // literal in Python, a nested class in Java
                    '&' -> out.append("\\&")          // "&&" is an intersection in Java
                    else -> out.append(c)
                }
                i++
                continue
            }
            if (c == '[') {
                inClass = true
                out.append(c)
                i++
                if (i < src.length && src[i] == '^') { out.append('^'); i++ }
                if (i < src.length && src[i] == ']') { out.append("\\]"); i++ }   // "[]...]": a literal ]
                continue
            }
            if (c == '(' && src.startsWith("(?P<", i)) {
                out.append("(?<")
                i += 4
                continue
            }
            out.append(c)
            i++
        }
        return out.toString()
    }

    fun compile(src: String, ignoreCase: Boolean = false): Regex =
        if (ignoreCase) Regex(translate(src), RegexOption.IGNORE_CASE) else Regex(translate(src))

    /** A pattern exported as [source, ignore case]. */
    fun of(pair: Any?): Regex {
        val p = pair.list()
        return compile(p[0] as String, p[1] as Boolean)
    }
}

/** Python's re.match: a match that starts at the beginning. */
internal fun Regex.matchStart(s: String): Boolean = toPattern().matcher(s).lookingAt()

/** What Python's str.isspace() accepts. */
internal fun isPySpace(c: Char): Boolean = c == ' ' || c in '\t'..'\r' || c in '\u001C'..'\u001F' ||
    c == '\u0085' || c == ' ' || c == ' ' || c in ' '..' ' || c == ' ' ||
    c == ' ' || c == ' ' || c == ' ' || c == '　'

/** Python's str.split() with no arguments. */
internal fun pySplit(s: String): List<String> {
    val out = ArrayList<String>()
    var start = -1
    for (i in s.indices) {
        if (isPySpace(s[i])) {
            if (start >= 0) { out.add(s.substring(start, i)); start = -1 }
        } else if (start < 0) start = i
    }
    if (start >= 0) out.add(s.substring(start))
    return out
}

/** Python's str.strip() with no arguments. */
internal fun pyStrip(s: String): String {
    var a = 0
    var b = s.length
    while (a < b && isPySpace(s[a])) a++
    while (b > a && isPySpace(s[b - 1])) b--
    return s.substring(a, b)
}

/** Python's round(x, digits): the exact binary value, rounded half to even. */
internal fun pyRound(x: Double, digits: Int): Double =
    if (x.isNaN() || x.isInfinite()) x
    else java.math.BigDecimal(x).setScale(digits, java.math.RoundingMode.HALF_EVEN).toDouble()
