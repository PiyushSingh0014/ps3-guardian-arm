package com.ps3guardian.app.guard

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.sqrt

/**
 * scikit-learn's "char_wb" analyzer: lower case, split on whitespace, each word padded with a space
 * on both sides, then its pieces of 2 to 5 characters. Python counts code points, so this does too.
 */
internal object CharWb {
    fun pieces(text: String, minN: Int = 2, maxN: Int = 5, add: (String) -> Unit) {
        for (word in pySplit(text.lowercase())) {
            val w = (" $word ").codePoints().toArray()
            val len = w.size
            for (n in minN..maxN) {
                var offset = 0
                add(cut(w, offset, n))
                while (offset + n < len) {
                    offset++
                    add(cut(w, offset, n))
                }
                if (offset == 0) break           // a short word counts once
            }
        }
    }

    private fun cut(cp: IntArray, from: Int, n: Int): String {
        val to = minOf(cp.size, from + n)
        return String(cp, from, to - from)
    }
}

/** sigmoid, as scikit-learn's expit. */
internal fun expit(z: Double): Double = 1.0 / (1.0 + exp(-z))

/**
 * The SMS text model (detectors/sms/train_baseline.py, v1): TF-IDF of the text's character pieces
 * (20,000 of them, unit length), the 11 numbers from the India rules, and a logistic regression.
 */
class SmsModel internal constructor(m: Map<String, Any?>) {
    private val vocab: HashMap<String, Int> = HashMap<String, Int>(40_000).apply {
        for ((k, v) in m["vocab"].obj()) put(k, v.num().toInt())
    }
    private val idf: DoubleArray = m["idf"].list().map { it.num() }.toDoubleArray()
    private val coef: DoubleArray = m["coef"].list().map { it.num() }.toDoubleArray()
    private val intercept: Double = m["intercept"].num()
    val messages: Int? = (m["messages"] as Double?)?.toInt()

    init {
        require(coef.size == idf.size + 11) { "the SMS model does not match the 11 rule features" }
    }

    /** (chance of a threat, chance of a normal message), as predict_proba gives them. */
    fun probs(cleanText: String, ruleVector: IntArray): Pair<Double, Double> {
        val counts = HashMap<Int, Int>()
        CharWb.pieces(cleanText) { p -> vocab[p]?.let { counts[it] = (counts[it] ?: 0) + 1 } }
        val order = counts.keys.sorted()                 // scikit-learn sums in index order
        var norm = 0.0
        for (j in order) {
            val v = counts[j]!! * idf[j]
            norm += v * v
        }
        norm = sqrt(norm)
        var z = 0.0
        if (norm > 0) for (j in order) z += counts[j]!! * idf[j] / norm * coef[j]
        for (k in ruleVector.indices) z += ruleVector[k] * coef[idf.size + k]
        z += intercept
        val p = expit(z)
        return Pair(p, 1.0 - p)
    }
}

/** MurmurHash3 x86 32-bit, as scikit-learn's HashingVectorizer uses it (seed 0, signed). */
internal fun murmur3(data: ByteArray, seed: Int = 0): Int {
    val c1 = 0xcc9e2d51.toInt()
    val c2 = 0x1b873593
    var h = seed
    val blocks = data.size / 4
    for (b in 0 until blocks) {
        val i = b * 4
        var k = (data[i].toInt() and 0xff) or ((data[i + 1].toInt() and 0xff) shl 8) or
            ((data[i + 2].toInt() and 0xff) shl 16) or ((data[i + 3].toInt() and 0xff) shl 24)
        k *= c1
        k = Integer.rotateLeft(k, 15)
        k *= c2
        h = h xor k
        h = Integer.rotateLeft(h, 13)
        h = h * 5 + 0xe6546b64.toInt()
    }
    val t = blocks * 4
    var k = 0
    val rest = data.size and 3
    if (rest >= 3) k = k xor ((data[t + 2].toInt() and 0xff) shl 16)
    if (rest >= 2) k = k xor ((data[t + 1].toInt() and 0xff) shl 8)
    if (rest >= 1) {
        k = k xor (data[t].toInt() and 0xff)
        k *= c1
        k = Integer.rotateLeft(k, 15)
        k *= c2
        h = h xor k
    }
    h = h xor data.size
    h = h xor (h ushr 16)
    h *= 0x85ebca6b.toInt()
    h = h xor (h ushr 13)
    h *= 0xc2b2ae35.toInt()
    h = h xor (h ushr 16)
    return h
}

/**
 * The link model (detectors/url/model.py): hashed character pieces of the registered domain
 * (1 + log of each count, times idf, unit length), 7 numbers about the name, a logistic regression.
 */
class LinkModel internal constructor(bytes: ByteArray) {
    private val nText: Int
    private val idf: FloatArray
    private val coef: FloatArray
    private val intercept: Double
    private val mean = DoubleArray(7)
    private val scale = DoubleArray(7)

    init {
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val magic = ByteArray(4).also { b.get(it) }
        require(String(magic, Charsets.US_ASCII) == "PS3L") { "not a link model file" }
        nText = b.int
        val nCoef = b.int
        require(nCoef == nText + 7) { "the link model does not match the 7 name numbers" }
        idf = FloatArray(nText) { b.float }
        coef = FloatArray(nCoef) { b.float }
        intercept = b.double
        for (i in 0 until 7) mean[i] = b.double
        for (i in 0 until 7) scale[i] = b.double
    }

    private fun index(piece: String): Int {
        val h = murmur3(piece.toByteArray(Charsets.UTF_8))
        return if (h == Int.MIN_VALUE) (Int.MAX_VALUE - (nText - 1)) % nText else abs(h) % nText
    }

    fun score(domain: String, suffix: String): Double {
        val text = if (suffix.isNotEmpty()) "$domain.$suffix" else domain
        val counts = HashMap<Int, Int>()
        CharWb.pieces(text) { p -> val j = index(p); counts[j] = (counts[j] ?: 0) + 1 }
        var norm = 0.0
        var dot = 0.0
        for (j in counts.keys.sorted()) {
            val v = (1.0 + ln(counts[j]!!.toDouble())) * idf[j].toDouble()
            norm += v * v
            dot += v * coef[j].toDouble()
        }
        norm = sqrt(norm)
        if (norm == 0.0) norm = 1.0
        val num = numbers(domain, suffix)
        var numPart = 0.0
        for (i in 0 until 7) numPart += (num[i] - mean[i]) / scale[i] * coef[nText + i].toDouble()
        return expit(dot / norm + numPart + intercept)
    }

    /** features.numeric(): length, share of digits, hyphens, letter entropy, share of vowels, longest consonant run, suffix parts. */
    private fun numbers(domain: String, suffix: String): DoubleArray {
        val d = domain.lowercase().codePoints().toArray()
        val n = if (d.isEmpty()) 1 else d.size
        val letters = d.filter { Character.isLetter(it) }
        val counts = LinkedHashMap<Int, Int>()
        for (c in d) counts[c] = (counts[c] ?: 0) + 1
        var entropy = 0.0
        if (d.isNotEmpty()) {
            for (k in counts.values) entropy += k.toDouble() / n * (ln(k.toDouble() / n) / ln(2.0))
            entropy = -entropy
        }
        var run = 0
        var best = 0
        for (c in d) {
            run = if (Character.isLetter(c) && c.toChar() !in "aeiou") run + 1 else 0
            best = maxOf(best, run)
        }
        val vowels = if (letters.isEmpty()) 0.0 else letters.count { it.toChar() in "aeiou" }.toDouble() / letters.size
        return doubleArrayOf(d.size.toDouble(), d.count { Character.isDigit(it) }.toDouble() / n,
            d.count { it == '-'.code }.toDouble(), entropy, vowels, best.toDouble(),
            if (suffix.isNotEmpty()) (suffix.count { it == '.' } + 1).toDouble() else 0.0)
    }
}
