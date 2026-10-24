package com.ps3guardian.companion

import android.content.Context
import org.json.JSONArray

/** The Pi address and pairing token typed on the main screen, and the last results. */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 30
    const val DEFAULT_URL = "http://10.140.209.76:8000"

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun piUrl(c: Context): String =
        (prefs(c).getString("pi_url", DEFAULT_URL) ?: DEFAULT_URL).trim().trimEnd('/')

    fun token(c: Context): String = (prefs(c).getString("token", "") ?: "").trim()

    fun save(c: Context, url: String, token: String) {
        prefs(c).edit().putString("pi_url", url.trim()).putString("token", token.trim()).apply()
    }

    @Synchronized
    fun addRecent(c: Context, line: String) {
        val old = JSONArray(prefs(c).getString("recent", "[]"))
        val out = JSONArray().put(line)
        for (i in 0 until minOf(old.length(), MAX_RECENT - 1)) out.put(old.getString(i))
        prefs(c).edit().putString("recent", out.toString()).apply()
    }

    fun recent(c: Context): List<String> {
        val arr = JSONArray(prefs(c).getString("recent", "[]"))
        return List(arr.length()) { arr.getString(it) }
    }
}
