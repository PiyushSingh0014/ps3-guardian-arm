package com.example.ps3guardian

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Kept in the app's private storage: the Pi address and pairing token typed on the main
 * screen, the last results, and SMS that arrived while the Pi could not be reached.
 */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 30
    private const val MAX_PENDING = 500
    const val KEY_RECENT = "recent"
    const val KEY_PENDING = "pending"
    const val DEFAULT_URL = "http://10.140.209.76:8000"

    fun prefs(c: Context): SharedPreferences = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The Pi address; "10.140.209.76:8000" typed without http:// works too. */
    fun piUrl(c: Context): String {
        val url = (prefs(c).getString("pi_url", null) ?: "").trim().trimEnd('/').ifBlank { DEFAULT_URL }
        return if ("://" in url) url else "http://$url"
    }

    fun token(c: Context): String = (prefs(c).getString("token", null) ?: "").trim()

    fun save(c: Context, url: String, token: String) {
        prefs(c).edit().putString("pi_url", url.trim()).putString("token", token.trim()).apply()
    }

    private fun array(c: Context, key: String) = JSONArray(prefs(c).getString(key, null) ?: "[]")

    @Synchronized
    fun addRecent(c: Context, line: String) {
        val old = array(c, KEY_RECENT)
        val out = JSONArray().put(line)
        for (i in 0 until minOf(old.length(), MAX_RECENT - 1)) out.put(old.getString(i))
        prefs(c).edit().putString(KEY_RECENT, out.toString()).apply()
    }

    fun recent(c: Context): List<String> {
        val arr = array(c, KEY_RECENT)
        return List(arr.length()) { arr.getString(it) }
    }

    /** An SMS the Pi has not checked yet. */
    class Pending(val id: String, val sender: String, val text: String, val received: Long)

    /** Keeps an SMS until the Pi answers; beyond MAX_PENDING the oldest are dropped. */
    @Synchronized
    fun addPending(c: Context, sender: String, text: String, received: Long) {
        val all = array(c, KEY_PENDING)
        all.put(
            JSONObject().put("id", UUID.randomUUID().toString()).put("sender", sender)
                .put("text", text).put("received", received)
        )
        val out = JSONArray()
        for (i in maxOf(0, all.length() - MAX_PENDING) until all.length()) out.put(all.getJSONObject(i))
        prefs(c).edit().putString(KEY_PENDING, out.toString()).apply()
    }

    @Synchronized
    fun firstPending(c: Context): Pending? {
        val all = array(c, KEY_PENDING)
        if (all.length() == 0) return null
        val o = all.getJSONObject(0)
        return Pending(o.getString("id"), o.optString("sender"), o.getString("text"), o.optLong("received"))
    }

    @Synchronized
    fun removePending(c: Context, id: String) {
        val all = array(c, KEY_PENDING)
        val out = JSONArray()
        for (i in 0 until all.length()) {
            val o = all.getJSONObject(i)
            if (o.optString("id") != id) out.put(o)
        }
        prefs(c).edit().putString(KEY_PENDING, out.toString()).apply()
    }

    fun pendingCount(c: Context): Int = array(c, KEY_PENDING).length()
}
