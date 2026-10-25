package com.example.ps3guardian

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Kept in the app's private storage: the Pi address, pairing token and phone name typed on the
 * main screen, the chat switches, the last results, and messages that arrived while the Pi could
 * not be reached.
 */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 30
    private const val MAX_PENDING = 500
    const val KEY_RECENT = "recent"
    const val KEY_PENDING = "pending"
    const val CHAT_CONTACTS = "chat_contacts"
    const val DEFAULT_URL = "http://10.140.209.76:8000"

    fun prefs(c: Context): SharedPreferences = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The Pi address; "10.140.209.76:8000" typed without http:// works too. */
    fun piUrl(c: Context): String {
        val url = (prefs(c).getString("pi_url", null) ?: "").trim().trimEnd('/').ifBlank { DEFAULT_URL }
        return if ("://" in url) url else "http://$url"
    }

    fun token(c: Context): String = (prefs(c).getString("token", null) ?: "").trim()

    /** This phone's name in the Pi's log, for example "A": each person labels their own phone's messages. */
    fun device(c: Context): String = (prefs(c).getString("device", null) ?: "").trim()

    fun save(c: Context, url: String, token: String, device: String) {
        prefs(c).edit().putString("pi_url", url.trim()).putString("token", token.trim())
            .putString("device", device.trim()).apply()
    }

    fun chatKey(app: String) = "chat_$app"

    /** Chats from this app (ChatApps.MESSAGES or ChatApps.WHATSAPP) are checked. Off until switched on. */
    fun chatOn(c: Context, app: String): Boolean = prefs(c).getBoolean(chatKey(app), false)

    /** Testing only: also check chats from saved contacts (normally only unknown numbers). */
    fun chatContacts(c: Context): Boolean = prefs(c).getBoolean(CHAT_CONTACTS, false)

    fun setSwitch(c: Context, key: String, on: Boolean) {
        prefs(c).edit().putBoolean(key, on).apply()
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

    /** A message the Pi has not checked yet. */
    class Pending(val id: String, val msg: Msg)

    /** Keeps a message until the Pi answers; beyond MAX_PENDING the oldest are dropped. */
    @Synchronized
    fun addPending(c: Context, m: Msg) {
        val all = array(c, KEY_PENDING)
        all.put(
            JSONObject().put("id", UUID.randomUUID().toString()).put("channel", m.channel)
                .put("app", m.app ?: "").put("sender", m.sender).put("text", m.text).put("received", m.received)
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
        val app = o.optString("app").ifBlank { null }
        val msg = Msg(o.optString("channel", "sms"), app, o.optString("sender"), o.getString("text"), o.optLong("received"))
        return Pending(o.getString("id"), msg)
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
