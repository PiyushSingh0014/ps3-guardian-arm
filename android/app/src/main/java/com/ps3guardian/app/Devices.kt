package com.ps3guardian.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * The devices on the Pi's lab Wi-Fi (GET /devices), riskiest first. Each has a risk level from
 * its network alerts of the last 24 hours: At risk (a dangerous one), Check (a suspicious one)
 * or OK. Only for the main screen: fetched while it is open, never in the background.
 */
object Devices {
    private val LABELS = mapOf("at_risk" to "AT RISK", "check" to "CHECK", "ok" to "OK")

    /** Asks the Pi once and keeps the list. False if the Pi could not be reached. */
    fun check(c: Context): Boolean {
        val reply = try {
            PiClient.of(c).devices()
        } catch (e: Exception) {
            return false
        }
        val arr = reply.optJSONArray("devices") ?: JSONArray()
        Settings.saveDevList(c, (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }.map { line(it) })
        return true
    }

    /** A text value, or "" when it is missing or JSON null (optString would give "null"). */
    private fun text(o: JSONObject, key: String): String = if (o.isNull(key)) "" else o.optString(key)

    /** One device in the main screen's list. */
    fun line(d: JSONObject): String {
        val ip = text(d, "ip")
        val name = text(d, "name").take(32)                      // chosen by the device: shown as text only
        val risk = text(d, "risk")
        val sb = StringBuilder(LABELS[risk] ?: risk.uppercase())
        sb.append(": ").append(if (name.isNotBlank()) "$name ($ip)" else ip)
        val meta = mutableListOf<String>()
        text(d, "last_active").let { if (it.isNotBlank()) meta += "last active $it" }
        text(d, "learning_until").let { if (it.isNotBlank()) meta += "learning its normal until $it" }
        if (meta.isNotEmpty()) sb.append('\n').append(meta.joinToString(" | "))
        sb.append('\n').append(text(d, "summary"))
        val latest = d.optJSONArray("latest")
        if (latest != null) {
            for (i in 0 until latest.length()) {
                val a = latest.optJSONObject(i) ?: continue
                sb.append("\n• ").append(text(a, "time").drop(5).take(11)).append("  ").append(text(a, "headline"))
            }
        }
        return sb.toString()
    }
}
