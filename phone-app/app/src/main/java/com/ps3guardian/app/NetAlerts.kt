package com.ps3guardian.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Network alerts from the Home Hub (GET /alerts): what its network monitor found on the home Wi-Fi,
 * for every device there, newest first. The Network page lists them; each opens its own screen.
 *
 * A new alert becomes a notification, dangerous and suspicious alike. If Llama's explanation is
 * not ready yet, the notification first shows the playbook's checked text; once the Hub has
 * Llama's text, the same notification shows it instead, without sounding again. Alerts older
 * than an hour are only listed, so a phone that comes back to the home Wi-Fi is not flooded.
 */
object NetAlerts {
    private const val LIMIT = 20                         // the Hub's page lists 20 too
    const val NOTIFY_WITHIN_MS = 60 * 60_000L
    const val MAX_NOTIFY = 3                             // new notifications per check, the newest

    /** One alert, as the phone shows it: json is what the Network page and the alert's screen read. */
    class Alert(
        val id: String,
        val timeMs: Long,             // when the connection that set it off started (0 if unknown)
        val explained: Boolean,       // the text is Llama's
        val llamaComing: Boolean,     // Llama is still going to explain it
        val json: JSONObject
    )

    /** What one answer from the Hub changes. */
    class Plan(val notify: List<Alert>, val update: List<Alert>, val seen: List<String>, val waiting: List<String>)

    /**
     * Which alerts to notify, which notifications to update with Llama's text, and what to
     * remember. alerts: newest first; seen: ids handled before; waiting: ids notified before
     * Llama's text was ready.
     */
    fun plan(alerts: List<Alert>, seen: List<String>, waiting: Collection<String>, now: Long): Plan {
        val handled = LinkedHashSet(seen)
        val wait = waiting.toMutableSet()
        val notify = mutableListOf<Alert>()
        val update = mutableListOf<Alert>()
        for (a in alerts) {
            if (a.id.isEmpty()) continue
            if (handled.add(a.id)) {                     // first time this phone sees it
                if (now - a.timeMs < NOTIFY_WITHIN_MS && notify.size < MAX_NOTIFY) {
                    notify += a
                    if (!a.explained && a.llamaComing) wait += a.id
                }
            } else if (a.id in wait) {
                if (a.explained) {
                    update += a
                    wait -= a.id
                } else if (!a.llamaComing) {
                    wait -= a.id                         // Llama could not explain it: the first text stays
                }
            }
        }
        wait.retainAll(alerts.map { it.id }.toSet())     // no longer among the Hub's newest: stop waiting
        return Plan(notify, update, handled.toList(), wait.toList())
    }

    /** Asks the Hub once and handles the answer. False if the Hub could not be reached. */
    fun check(c: Context): Boolean {
        val reply = try {
            PiClient.of(c).alerts(LIMIT)
        } catch (e: Exception) {
            Settings.netFailed(c)
            return false
        }
        val arr = reply.optJSONArray("alerts") ?: JSONArray()
        handle(c, (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }.map { parse(it) })
        return true
    }

    @Synchronized
    private fun handle(c: Context, alerts: List<Alert>) {
        val p = plan(alerts, Settings.netSeen(c), Settings.netWaiting(c), System.currentTimeMillis())
        for (a in p.notify.asReversed()) {               // oldest first, so the newest ends up on top
            Notifier.netAlert(c, a.json, notificationId(a.id))
        }
        for (a in p.update) {
            if (Notifier.isShowing(c, notificationId(a.id))) Notifier.netAlert(c, a.json, notificationId(a.id))
        }
        Settings.saveNet(c, p.seen, p.waiting, alerts.map { it.json })
    }

    private fun notificationId(alertId: String) = ("net:$alertId").hashCode()

    /** A text value, or "" when it is missing or JSON null (optString would give "null"). */
    private fun text(o: JSONObject, key: String): String = if (o.isNull(key)) "" else o.optString(key)

    /** One alert of the Hub's answer: Llama's what and why once they are ready, else the playbook's. */
    fun parse(a: JSONObject): Alert {
        val advice = a.optJSONObject("advice") ?: JSONObject()
        val explain = a.optJSONObject("explain")
        val status = explain?.optString("status") ?: ""
        val llama = if (status == "done") explain?.optJSONObject("advice") else null
        val finding = a.optJSONObject("finding") ?: JSONObject()
        val e = finding.optJSONObject("entities") ?: JSONObject()
        val ip = text(e, "device")
        val name = text(e, "device_name").take(32)               // chosen by the device: shown as text only
        val headline = text(advice, "headline").ifBlank { "Network alert" }
        val verdict = text(finding, "verdict").ifBlank { if (headline.startsWith("DANGEROUS")) "dangerous" else "suspicious" }
        val shown = llama ?: advice
        val json = JSONObject()
            .put("id", text(a, "id")).put("time", text(a, "time")).put("time_ms", e.optLong("time_ms", 0L))
            .put("verdict", verdict).put("title", History.cleanTitle(headline)).put("category", text(finding, "category"))
            .put("device", name.ifBlank { ip }).put("ip", ip)
            .put("what", text(shown, "what")).put("why", text(shown, "why"))
            .put("steps", advice.optJSONArray("steps") ?: JSONArray())
            .put("reasons", finding.optJSONArray("reasons") ?: JSONArray())
            .put("explained", llama != null)
        return Alert(text(a, "id"), e.optLong("time_ms", 0L), llama != null, status == "queued" || status == "pending", json)
    }

    /** One of the newest alerts kept for the Network page, by id (from a notification, for example). */
    fun find(c: Context, id: String): JSONObject? = Settings.netList(c).firstOrNull { it.optString("id") == id }
}
