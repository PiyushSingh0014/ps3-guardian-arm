package com.example.ps3guardian

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Network alerts from the Pi (GET /alerts): what its network monitor found on the lab Wi-Fi
 * PS3-Guardian-Lab, for every device there, newest first. The main screen lists them.
 *
 * A new alert becomes a notification, dangerous and suspicious alike. If Llama's explanation is
 * not ready yet, the notification first shows the playbook's checked text; once the Pi has
 * Llama's text, the same notification shows it instead, without sounding again. Alerts older
 * than an hour are only listed, so a phone that comes back to the lab Wi-Fi is not flooded.
 */
object NetAlerts {
    private const val LIMIT = 20                         // the Pi's page lists 20 too
    const val NOTIFY_WITHIN_MS = 60 * 60_000L
    const val MAX_NOTIFY = 3                             // new notifications per check, the newest

    /** One alert, as the phone shows it. */
    class Alert(
        val id: String,
        val timeMs: Long,             // when the connection that set it off started (0 if unknown)
        val title: String,            // e.g. "DANGEROUS: Malware looking for its controller ..."
        val text: String,             // notification text: Llama's once ready, else the playbook's
        val explained: Boolean,       // text is Llama's
        val llamaComing: Boolean,     // Llama is still going to explain it
        val line: String              // the main screen's list
    )

    /** What one answer from the Pi changes. */
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
        wait.retainAll(alerts.map { it.id }.toSet())     // no longer among the Pi's newest: stop waiting
        return Plan(notify, update, handled.toList(), wait.toList())
    }

    /** Asks the Pi once and handles the answer. False if the Pi could not be reached. */
    fun check(c: Context): Boolean {
        val reply = try {
            PiClient(Settings.piUrl(c), Settings.token(c)).alerts(LIMIT)
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
            Notifier.show(c, a.title, a.text, notificationId(a.id), Notifier.NET)
        }
        for (a in p.update) {
            if (Notifier.isShowing(c, notificationId(a.id))) {
                Notifier.show(c, a.title, a.text, notificationId(a.id), Notifier.NET)
            }
        }
        Settings.saveNet(c, p.seen, p.waiting, alerts.map { it.line })
    }

    private fun notificationId(alertId: String) = ("net:$alertId").hashCode()

    /** One alert of the Pi's answer. */
    fun parse(a: JSONObject): Alert {
        val advice = a.optJSONObject("advice") ?: JSONObject()
        val explain = a.optJSONObject("explain")
        val status = explain?.optString("status") ?: ""
        val llama = if (status == "done") explain?.optJSONObject("advice") else null
        val e = a.optJSONObject("finding")?.optJSONObject("entities") ?: JSONObject()
        val ip = e.optString("device")
        val name = e.optString("device_name").take(32)           // chosen by the device: shown as text only
        val device = if (name.isNotBlank()) "$name ($ip)" else ip
        val time = a.optString("time")
        val title = advice.optString("headline").ifBlank { "Network alert" }

        val head = listOf(device, time.takeLast(8)).filter { it.isNotBlank() }.joinToString(", ")
        val text = (head + "\n" + Notifier.adviceText(llama ?: advice)).trim()

        val line = StringBuilder(title).append('\n').append(time).append(" | ").append(device)
        if (llama != null) {
            line.append('\n').append((llama.optString("what") + " " + llama.optString("why")).trim())
            line.append("\n(Explained by Llama 3.2 on the Pi)")
        } else {
            line.append('\n').append(advice.optString("why"))
        }
        val steps = advice.optJSONArray("steps")
        if (steps != null && steps.length() > 0) line.append("\nFirst step: ").append(steps.optString(0))

        return Alert(a.optString("id"), e.optLong("time_ms", 0L), title, text, llama != null,
            status == "queued" || status == "pending", line.toString())
    }
}
