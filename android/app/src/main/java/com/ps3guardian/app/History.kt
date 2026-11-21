package com.ps3guardian.app

import android.content.Context
import com.ps3guardian.app.guard.GuardResult
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Every checked message, newest first, for the Home and Alerts screens and an alert's own screen
 * (app 3.0). Kept only on this phone. The text is kept only for flagged messages (to show "The
 * message" with its links broken) and never for safe ones; at most [MAX] entries, newest kept.
 */
object History {
    const val KEY = "history"
    private const val MAX = 60

    /** One checked message (or shared file), as the screens read it. */
    class Entry(val o: JSONObject) {
        val id: String get() = o.optString("id")
        val time: Long get() = o.optLong("time")
        val channel: String get() = o.optString("channel", "sms")      // sms, chat, share, file, test
        val app: String? get() = o.optString("app").ifBlank { null }   // chats: ChatApps.WHATSAPP or MESSAGES
        val sender: String get() = o.optString("sender")
        val verdict: String get() = o.optString("verdict", "checking") // checking, safe, suspicious, dangerous, unknown
        val title: String get() = o.optString("title")
        val what: String get() = o.optString("what")
        val why: String get() = o.optString("why")
        val steps: List<String> get() = strings(o.optJSONArray("steps"))
        val reasons: List<String> get() = strings(o.optJSONArray("reasons"))
        val text: String? get() = o.optString("text").ifBlank { null }
        val name: String? get() = o.optString("name").ifBlank { null } // a shared file's name
        val by: String get() = o.optString("by")                       // phone or hub: whose verdict this is
        val checkMs: Double get() = o.optDouble("check_ms", -1.0)
        val hub: String get() = o.optString("hub")                     // waiting, later, unreachable, refused or ""
        val hubAt: Long get() = o.optLong("hub_at")
        val explanation: String? get() = o.optString("explanation").ifBlank { null }
        val explainedBy: String get() = o.optString("explained_by")    // phone or hub
        val explainNote: String get() = o.optString("explain_note")    // timings of Llama on this phone
        val llama: String get() = o.optString("llama")                 // writing, done, failed or ""
        val notifyId: Int get() = o.optInt("notify")
        val flagged: Boolean get() = verdict == "dangerous" || verdict == "suspicious"
    }

    private fun strings(a: JSONArray?): List<String> =
        if (a == null) emptyList() else List(a.length()) { a.optString(it) }

    private fun all(c: Context): JSONArray = JSONArray(Settings.prefs(c).getString(KEY, null) ?: "[]")

    private fun save(c: Context, a: JSONArray) {
        Settings.prefs(c).edit().putString(KEY, a.toString()).apply()
    }

    /** Newest first. */
    fun entries(c: Context): List<Entry> {
        val a = all(c)
        return (0 until a.length()).mapNotNull { a.optJSONObject(it) }.map { Entry(it) }
    }

    fun get(c: Context, id: String): Entry? = entries(c).firstOrNull { it.id == id }

    /** A new entry, still being checked. Returns its id. */
    @Synchronized
    fun create(c: Context, channel: String, app: String?, sender: String, time: Long, name: String? = null): String {
        val id = UUID.randomUUID().toString()
        val o = JSONObject().put("id", id).put("time", time).put("channel", channel).put("app", app ?: "")
            .put("sender", sender.take(64)).put("verdict", "checking").put("name", name ?: "")
        val old = all(c)
        val out = JSONArray().put(o)
        for (i in 0 until minOf(old.length(), MAX - 1)) out.put(old.get(i))
        save(c, out)
        return id
    }

    /** Changes one entry in place; nothing happens if it is gone (more than MAX newer ones). */
    @Synchronized
    fun update(c: Context, id: String, change: (JSONObject) -> Unit) {
        if (id.isEmpty()) return
        val a = all(c)
        for (i in 0 until a.length()) {
            val o = a.optJSONObject(i) ?: continue
            if (o.optString("id") == id) {
                change(o)
                save(c, a)
                return
            }
        }
    }

    /** "DANGEROUS: Fake bank KYC (Know Your Customer) message" -> "Fake bank KYC message". */
    fun cleanTitle(headline: String): String {
        val t = headline.substringAfter(": ", headline).replace(Regex("\\s*\\([^)]*\\)"), "").trim()
        return t.replaceFirstChar { it.uppercaseChar() }
    }

    private fun verdictOf(headline: String, fallback: String): String = when {
        headline.startsWith("DANGEROUS") -> "dangerous"
        headline.startsWith("SUSPICIOUS") -> "suspicious"
        headline.startsWith("LIKELY SAFE") || headline.startsWith("SAFE") -> "safe"
        else -> fallback
    }

    private fun put(o: JSONObject, verdict: String, headline: String, what: String, why: String, steps: List<String>,
                    reasons: List<String>, text: String?) {
        o.put("verdict", verdict).put("title", cleanTitle(headline)).put("what", what).put("why", why)
            .put("steps", JSONArray(steps)).put("reasons", JSONArray(reasons.take(8)))
        if (verdict == "dangerous" || verdict == "suspicious") {
            if (text != null) o.put("text", text.take(1200))
        } else {
            o.remove("text")                                  // safe: no text kept
        }
    }

    /** Phone Guard's verdict (update 43), with the playbook's advice. */
    fun fromPhone(c: Context, id: String, r: GuardResult, text: String?) = update(c, id) { o ->
        put(o, r.verdict, r.headline, r.what, r.why, r.steps, r.reasons, text)
        o.put("by", "phone").put("check_ms", r.millis)
    }

    /** The Home Hub's answer: its verdict replaces the phone's (it also has the phishing list). */
    fun fromHub(c: Context, id: String, res: JSONObject, text: String?, late: Boolean) = update(c, id) { o ->
        val finding = res.optJSONObject("finding") ?: JSONObject()
        val advice = res.optJSONObject("advice") ?: JSONObject()
        val headline = advice.optString("headline")
        val verdict = finding.optString("verdict").ifBlank { verdictOf(headline, "safe") }
        val reasons = strings(finding.optJSONArray("reasons"))
        put(o, verdict, headline, advice.optString("what"), advice.optString("why"), strings(advice.optJSONArray("steps")),
            reasons.ifEmpty { strings(o.optJSONArray("reasons")) }, text ?: o.optString("text").ifBlank { null })
        o.put("by", "hub").put("hub", if (late) "later" else "").put("hub_at", System.currentTimeMillis())
        if (res.optJSONObject("explain") != null && verdict != "safe") o.put("llama", "writing")
    }

    /** Llama's explanation, from the Home Hub or from this phone. note: its timings, if any. */
    fun explained(c: Context, id: String, what: String, why: String, by: String, note: String = "") = update(c, id) { o ->
        o.put("explanation", listOf(what, why).filter { it.isNotBlank() }.joinToString(" "))
            .put("explained_by", by).put("explain_note", note).put("llama", "done")
    }

    fun set(c: Context, id: String, key: String, value: Any) = update(c, id) { it.put(key, value) }
}
