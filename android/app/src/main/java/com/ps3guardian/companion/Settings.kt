package com.ps3guardian.companion

import android.content.Context
import org.json.JSONArray

/** The Pi address and pairing token typed on the main screen, and the last results. */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 30
    const val DEFAULT_URL = "http://10.140.209.76:8000"

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The Pi address; "10.140.209.76:8000" typed without http:// works too. */
    fun piUrl(c: Context): String {
        val url = (prefs(c).getString("pi_url", null) ?: "").trim().trimEnd('/').ifBlank { DEFAULT_URL }
        return if ("://" in url) url else "http://$url"
    }

    fun token(c: Context): String = (prefs(c).getString("token", "") ?: "").trim()

    fun save(c: Context, url: String, token: String) {
        prefs(c).edit().putString("pi_url", url.trim()).putString("token", token.trim()).apply()
    }

    private fun recentArray(c: Context) = JSONArray(prefs(c).getString("recent", null) ?: "[]")

    @Synchronized
    fun addRecent(c: Context, line: String) {
        val old = recentArray(c)
        val out = JSONArray().put(line)
        for (i in 0 until minOf(old.length(), MAX_RECENT - 1)) out.put(old.getString(i))
        prefs(c).edit().putString("recent", out.toString()).apply()
    }

    fun recent(c: Context): List<String> {
        val arr = recentArray(c)
        return List(arr.length()) { arr.getString(it) }
    }
}
