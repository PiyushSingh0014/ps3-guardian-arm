package com.ps3guardian.app

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Kept in the app's private storage: the Home Hub's address, the pairing code and the phone's name,
 * the Hub's certificate fingerprint confirmed when pairing, the switches, the activity log, messages
 * that arrived while the Hub could not be reached, the network alerts and devices last fetched from
 * the Hub, and whether the Hub answered last time.
 */
object Settings {
    private const val PREFS = "guardian"
    private const val MAX_RECENT = 60
    private const val MAX_PENDING = 500
    const val KEY_RECENT = "recent"
    const val KEY_PENDING = "pending"
    const val CHAT_CONTACTS = "chat_contacts"
    const val DEFAULT_URL = "https://10.42.0.1:8443"
    const val STUDY = "study"
    const val SMS_ON = "sms_on"
    private const val PIN = "tls_pin"
    const val NET_ON = "net_on"
    const val KEY_NET_LIST = "net_list"
    const val KEY_DEV_LIST = "dev_list"
    const val KEY_HUB = "hub_state"
    private const val SETUP_DONE = "setup_done"
    private const val ALERTS_SEEN = "alerts_seen"
    private const val NET_SEEN = "net_seen"
    private const val NET_WAITING = "net_waiting"
    private const val NET_CHECKED = "net_checked"
    private const val NET_FAILED = "net_failed"
    private const val MAX_NET_SEEN = 300

    fun prefs(c: Context): SharedPreferences = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The Home Hub's address; "10.42.0.1:8443" typed without https:// works too. */
    fun piUrl(c: Context): String {
        val url = (prefs(c).getString("pi_url", null) ?: "").trim().trimEnd('/').ifBlank { DEFAULT_URL }
        return if ("://" in url) url else "https://$url"
    }

    /** The fingerprint of the Hub's certificate, confirmed by the owner when pairing ("" = not paired). */
    fun pin(c: Context): String = (prefs(c).getString(PIN, null) ?: "").trim()

    fun setPin(c: Context, pin: String) {
        prefs(c).edit().putString(PIN, pin.trim()).apply()
    }

    /** "Help improve detection" (the study switch): off until its owner switches it on. */
    fun study(c: Context): Boolean = prefs(c).getBoolean(STUDY, false)

    fun token(c: Context): String = (prefs(c).getString("token", null) ?: "").trim()

    /** This phone's name in the Hub's log, for example "A": each person labels their own phone's messages. */
    fun device(c: Context): String = (prefs(c).getString("device", null) ?: "").trim()

    fun save(c: Context, url: String, token: String, device: String) {
        prefs(c).edit().putString("pi_url", url.trim()).putString("token", token.trim())
            .putString("device", device.trim()).apply()
    }

    fun saveUrl(c: Context, url: String) = prefs(c).edit().putString("pi_url", url.trim()).apply()

    fun saveToken(c: Context, token: String) = prefs(c).edit().putString("token", token.trim()).apply()

    fun saveDevice(c: Context, device: String) = prefs(c).edit().putString("device", device.trim().take(32)).apply()

    /** Incoming SMS are checked (app 3.0 can pause it). On unless switched off. */
    fun smsOn(c: Context): Boolean = prefs(c).getBoolean(SMS_ON, true)

    /** The set-up screens were finished or skipped once (or the phone was paired before app 3.0). */
    fun setupDone(c: Context): Boolean = prefs(c).getBoolean(SETUP_DONE, false) || pin(c).isNotBlank()

    fun setSetupDone(c: Context) = prefs(c).edit().putBoolean(SETUP_DONE, true).apply()

    /** When the Alerts page was last opened: newer flagged messages make the tab's badge. */
    fun alertsSeen(c: Context): Long = prefs(c).getLong(ALERTS_SEEN, 0L)

    fun setAlertsSeen(c: Context) = prefs(c).edit().putLong(ALERTS_SEEN, System.currentTimeMillis()).apply()

    fun chatKey(app: String) = "chat_$app"

    /** Chats from this app (ChatApps.MESSAGES or ChatApps.WHATSAPP) are checked. Off until switched on. */
    fun chatOn(c: Context, app: String): Boolean = prefs(c).getBoolean(chatKey(app), false)

    /** Testing only: also check chats from saved contacts (normally only unknown numbers). */
    fun chatContacts(c: Context): Boolean = prefs(c).getBoolean(CHAT_CONTACTS, false)

    fun setSwitch(c: Context, key: String, on: Boolean) {
        prefs(c).edit().putBoolean(key, on).apply()
    }

    private fun array(c: Context, key: String) = try {
        JSONArray(prefs(c).getString(key, null) ?: "[]")
    } catch (e: Exception) {
        JSONArray()
    }

    /** The activity log (Settings, Advanced): one line per step, with timings, newest first. */
    @Synchronized
    fun addRecent(c: Context, line: String) {
        val old = array(c, KEY_RECENT)
        val out = JSONArray().put(line)
        for (i in 0 until minOf(old.length(), MAX_RECENT - 1)) out.put(old.optString(i))
        prefs(c).edit().putString(KEY_RECENT, out.toString()).apply()
    }

    fun recent(c: Context): List<String> {
        val arr = array(c, KEY_RECENT)
        return List(arr.length()) { arr.optString(it) }
    }

    /** A message the Hub has not checked yet. */
    class Pending(val id: String, val msg: Msg)

    /** Keeps a message until the Hub answers; beyond MAX_PENDING the oldest are dropped. */
    @Synchronized
    fun addPending(c: Context, m: Msg) {
        val all = array(c, KEY_PENDING)
        all.put(
            JSONObject().put("id", UUID.randomUUID().toString()).put("channel", m.channel)
                .put("app", m.app ?: "").put("sender", m.sender).put("text", m.text).put("received", m.received)
                .put("phone", m.phoneVerdict ?: "").put("notify", m.notifyId).put("history", m.historyId)
        )
        val out = JSONArray()
        for (i in maxOf(0, all.length() - MAX_PENDING) until all.length()) out.put(all.optJSONObject(i))
        prefs(c).edit().putString(KEY_PENDING, out.toString()).apply()
    }

    @Synchronized
    fun firstPending(c: Context): Pending? {
        val all = array(c, KEY_PENDING)
        if (all.length() == 0) return null
        val o = all.getJSONObject(0)
        val app = o.optString("app").ifBlank { null }
        val msg = Msg(o.optString("channel", "sms"), app, o.optString("sender"), o.getString("text"), o.optLong("received"),
            o.optString("phone").ifBlank { null }, o.optInt("notify"), o.optString("history"))
        return Pending(o.getString("id"), msg)
    }

    @Synchronized
    fun removePending(c: Context, id: String) {
        val all = array(c, KEY_PENDING)
        val out = JSONArray()
        for (i in 0 until all.length()) {
            val o = all.optJSONObject(i) ?: continue
            if (o.optString("id") != id) out.put(o)
        }
        prefs(c).edit().putString(KEY_PENDING, out.toString()).apply()
    }

    fun pendingCount(c: Context): Int = array(c, KEY_PENDING).length()

    /** Network alerts from the Home Hub: on unless switched off. */
    fun netOn(c: Context): Boolean = prefs(c).getBoolean(NET_ON, true)

    private fun strings(c: Context, key: String): List<String> {
        val arr = array(c, key)
        return List(arr.length()) { arr.optString(it) }
    }

    private fun objects(c: Context, key: String): List<JSONObject> {
        val arr = array(c, key)
        return (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }    // app 2.x kept text lines: skipped
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

    /** The network alerts for the Network page, newest first (NetAlerts.toJson). */
    fun netList(c: Context): List<JSONObject> = objects(c, KEY_NET_LIST)

    /** One answer from the Hub: the alerts handled, those still waiting for Llama, the list, the time. */
    @Synchronized
    fun saveNet(c: Context, seen: List<String>, waiting: List<String>, list: List<JSONObject>) {
        prefs(c).edit().putString(NET_SEEN, jsonOf(seen.takeLast(MAX_NET_SEEN)))
            .putString(NET_WAITING, jsonOf(waiting)).putString(KEY_NET_LIST, JSONArray(list).toString())
            .putLong(NET_CHECKED, System.currentTimeMillis()).apply()
    }

    /** The devices on the home Wi-Fi, riskiest first, as the Hub sent them (GET /devices). */
    fun devList(c: Context): List<JSONObject> = objects(c, KEY_DEV_LIST)

    fun saveDevList(c: Context, list: List<JSONObject>) {
        prefs(c).edit().putString(KEY_DEV_LIST, JSONArray(list).toString()).apply()
    }

    fun netFailed(c: Context) {
        prefs(c).edit().putLong(NET_FAILED, System.currentTimeMillis()).apply()
    }

    /** When the Hub last sent network alerts, and when it last could not be reached (ms; 0 = never). */
    fun netCheckedAt(c: Context): Long = prefs(c).getLong(NET_CHECKED, 0L)

    fun netFailedAt(c: Context): Long = prefs(c).getLong(NET_FAILED, 0L)

    /** Whether the Home Hub answered the last request, and when: ok, away or refused (wrong code). */
    class Hub(val state: String, val at: Long, val error: String)

    fun hub(c: Context): Hub {
        val o = try {
            JSONObject(prefs(c).getString(KEY_HUB, null) ?: "{}")
        } catch (e: Exception) {
            JSONObject()
        }
        return Hub(o.optString("state"), o.optLong("at"), o.optString("error"))
    }

    /**
     * Records a request's outcome. The same state is written again at most once a minute, so that
     * the screens listening for changes are not redrawn after every request.
     */
    @Synchronized
    fun hubSeen(c: Context, state: String, error: String = "") {
        val old = hub(c)
        val now = System.currentTimeMillis()
        if (old.state == state && old.error == error && now - old.at < 60_000L) return
        val o = JSONObject().put("state", state).put("at", now).put("error", error.take(200))
        prefs(c).edit().putString(KEY_HUB, o.toString()).apply()
    }
}
