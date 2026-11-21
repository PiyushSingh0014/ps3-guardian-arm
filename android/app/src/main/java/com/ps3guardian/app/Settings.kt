package com.ps3guardian.app

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Kept in the app's private storage: the Pi address, pairing token and phone name typed on the
 * main screen, the Pi's certificate fingerprint confirmed when pairing, the study and chat switches,
 * the last results, messages that arrived while the Pi could not be reached, and the network alerts
 * last fetched from the Pi.
 */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 30
    private const val MAX_PENDING = 500
    const val KEY_RECENT = "recent"
    const val KEY_PENDING = "pending"
    const val CHAT_CONTACTS = "chat_contacts"
    const val DEFAULT_URL = "https://10.42.0.1:8443"
    const val STUDY = "study"
    private const val PIN = "tls_pin"
    const val NET_ON = "net_on"
    const val KEY_NET_LIST = "net_list"
    const val KEY_DEV_LIST = "dev_list"
    private const val NET_SEEN = "net_seen"
    private const val NET_WAITING = "net_waiting"
    private const val NET_CHECKED = "net_checked"
    private const val NET_FAILED = "net_failed"
    private const val MAX_NET_SEEN = 300

    fun prefs(c: Context): SharedPreferences = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The Pi address; "10.42.0.1:8443" typed without https:// works too. */
    fun piUrl(c: Context): String {
        val url = (prefs(c).getString("pi_url", null) ?: "").trim().trimEnd('/').ifBlank { DEFAULT_URL }
        return if ("://" in url) url else "https://$url"
    }

    /** The fingerprint of the Pi's certificate, confirmed by the owner when pairing ("" = not paired). */
    fun pin(c: Context): String = (prefs(c).getString(PIN, null) ?: "").trim()

    fun setPin(c: Context, pin: String) {
        prefs(c).edit().putString(PIN, pin.trim()).apply()
    }

    /** "Share message texts with the study": off until its owner switches it on. */
    fun study(c: Context): Boolean = prefs(c).getBoolean(STUDY, false)

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
                .put("phone", m.phoneVerdict ?: "").put("notify", m.notifyId)
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
        val msg = Msg(o.optString("channel", "sms"), app, o.optString("sender"), o.getString("text"), o.optLong("received"),
            o.optString("phone").ifBlank { null }, o.optInt("notify"))
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

    /** Network alerts from the Pi's lab Wi-Fi: on unless switched off on the main screen. */
    fun netOn(c: Context): Boolean = prefs(c).getBoolean(NET_ON, true)

    private fun strings(c: Context, key: String): List<String> {
        val arr = array(c, key)
        return List(arr.length()) { arr.getString(it) }
    }

    private fun jsonOf(items: List<String>): String {
        val arr = JSONArray()
        for (item in items) arr.put(item)
        return arr.toString()
    }

    /** Network alert ids already handled (notified, or listed only), oldest first. */
    fun netSeen(c: Context): List<String> = strings(c, NET_SEEN)

    /** Network alerts notified with the playbook's text: their notification gets Llama's text once it is ready. */
    fun netWaiting(c: Context): List<String> = strings(c, NET_WAITING)

    /** The network alerts for the main screen, newest first, as text. */
    fun netList(c: Context): List<String> = strings(c, KEY_NET_LIST)

    /** One answer from the Pi: the alerts handled, those still waiting for Llama, the list, the time. */
    @Synchronized
    fun saveNet(c: Context, seen: List<String>, waiting: List<String>, list: List<String>) {
        prefs(c).edit().putString(NET_SEEN, jsonOf(seen.takeLast(MAX_NET_SEEN)))
            .putString(NET_WAITING, jsonOf(waiting)).putString(KEY_NET_LIST, jsonOf(list))
            .putLong(NET_CHECKED, System.currentTimeMillis()).apply()
    }

    /** The devices on the Pi's Wi-Fi for the main screen, riskiest first, as text. */
    fun devList(c: Context): List<String> = strings(c, KEY_DEV_LIST)

    fun saveDevList(c: Context, list: List<String>) {
        prefs(c).edit().putString(KEY_DEV_LIST, jsonOf(list)).apply()
    }

    fun netFailed(c: Context) {
        prefs(c).edit().putLong(NET_FAILED, System.currentTimeMillis()).apply()
    }

    /** When the Pi last answered, and when it last could not be reached (ms; 0 = never). */
    fun netCheckedAt(c: Context): Long = prefs(c).getLong(NET_CHECKED, 0L)

    fun netFailedAt(c: Context): Long = prefs(c).getLong(NET_FAILED, 0L)
}
