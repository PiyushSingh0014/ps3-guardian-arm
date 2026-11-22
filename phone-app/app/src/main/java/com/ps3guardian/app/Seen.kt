package com.ps3guardian.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Remembers recent SMS and checked chat messages (as short hashes, not their text), so that
 * one message is not checked twice: an SMS also appears as a Messages notification, and chat
 * apps post the same notification again when it is updated.
 *
 * A chat message is known by its app, sender, text and the time its app gives it (app 3.2): the
 * same notification posted again is skipped, but the same words sent again later are a new
 * message and are checked again. Before, the same words from the same sender were skipped for 2
 * days, so a scam sent twice gave no second alert. Without a time, the same words are skipped for
 * 10 minutes only.
 */
object Seen {
    private const val SMS_KEY = "seen_sms"
    private const val CHAT_KEY = "seen_chat"
    private const val SMS_WINDOW_MS = 10 * 60 * 1000L
    private const val CHAT_WINDOW_MS = 2 * 24 * 3600 * 1000L
    private const val CHAT_TEXT_KEY = "seen_chat_text"         // chat messages that came without a time
    private const val CHAT_TEXT_WINDOW_MS = 10 * 60 * 1000L
    private const val MAX = 300

    private fun hash(s: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun norm(text: String) = text.trim().take(300)

    /** Adds the hash unless it is already there; drops entries older than the window. True if it was there. */
    @Synchronized
    private fun remember(c: Context, key: String, h: String, windowMs: Long): Boolean {
        val now = System.currentTimeMillis()
        val old = JSONArray(Settings.prefs(c).getString(key, null) ?: "[]")
        val kept = JSONArray()
        var found = false
        for (i in maxOf(0, old.length() - MAX) until old.length()) {
            val o = old.getJSONObject(i)
            if (now - o.optLong("t") > windowMs) continue
            if (o.optString("h") == h) found = true
            kept.put(o)
        }
        if (!found) kept.put(JSONObject().put("h", h).put("t", now))
        Settings.prefs(c).edit().putString(key, kept.toString()).apply()
        return found
    }

    @Synchronized
    private fun contains(c: Context, key: String, h: String, windowMs: Long): Boolean {
        val now = System.currentTimeMillis()
        val arr = JSONArray(Settings.prefs(c).getString(key, null) ?: "[]")
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("h") == h && now - o.optLong("t") <= windowMs) return true
        }
        return false
    }

    fun noteSms(c: Context, text: String) {
        remember(c, SMS_KEY, hash(norm(text)), SMS_WINDOW_MS)
    }

    fun isRecentSms(c: Context, text: String) = contains(c, SMS_KEY, hash(norm(text)), SMS_WINDOW_MS)

    /** True the first time this chat message is seen (and remembers it). time: from its app, or 0. */
    fun firstTimeChat(c: Context, app: String, sender: String, text: String, time: Long = 0L) =
        if (time > 0L) !remember(c, CHAT_KEY, hash("$app|$sender|${norm(text)}|$time"), CHAT_WINDOW_MS)
        else !remember(c, CHAT_TEXT_KEY, hash("$app|$sender|${norm(text)}"), CHAT_TEXT_WINDOW_MS)
}
