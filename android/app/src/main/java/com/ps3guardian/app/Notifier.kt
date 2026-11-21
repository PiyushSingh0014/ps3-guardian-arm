package com.ps3guardian.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

/**
 * Scam alerts and network alerts, each with its own channel. Safe messages get no notification.
 * App 3.0: "Dangerous · Fake bank KYC message", the explanation, then "What to do" (the alert's
 * own screen) and "Call 1930" (the dialler, with the number filled in; nothing is called by itself).
 * App 3.1: each alert first says which message it is about (the sender, the start of the message
 * with its links broken, and the time it arrived), so the alerts that come together when the
 * phone reaches the Home Hub again can be told apart. The lock screen shows none of the message.
 */
object Notifier {
    private const val CHANNEL = "alerts"
    private const val SNIPPET = 120                     // characters of the message shown in an alert
    private val SPACES = Regex("\\s+")
    const val NET = "net"

    fun ensureChannel(c: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = c.getSystemService(NotificationManager::class.java) ?: return
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "Scam alerts", NotificationManager.IMPORTANCE_HIGH)
            )
            manager.createNotificationChannel(
                NotificationChannel(NET, "Network alerts", NotificationManager.IMPORTANCE_HIGH)
            )
        }
    }

    /** The advice from the Hub as text: what, why, then the steps. */
    fun adviceText(advice: JSONObject): String {
        val sb = StringBuilder()
        for (key in listOf("what", "why")) {
            val part = advice.optString(key)
            if (part.isNotBlank()) sb.append(part).append(' ')
        }
        val steps = advice.optJSONArray("steps")
        if (steps != null) for (i in 0 until steps.length()) sb.append("\n• ").append(steps.optString(i))
        return sb.toString().trim()
    }

    private fun newId() = (System.currentTimeMillis() % Int.MAX_VALUE).toInt()

    /**
     * The alert for a checked message, from its History entry; with id, the alert already shown is
     * updated (without sounding again). Returns the notification id.
     */
    fun alert(c: Context, historyId: String, id: Int = newId()): Int {
        val e = History.get(c, historyId) ?: return id
        if (!e.flagged) return id
        val look = Ui.look(c, e.verdict)
        val where = Ui.channelLabel(e.channel, e.app)
        val source = source(e, where)
        val big = StringBuilder(source).append("\n\n").append(e.summary)
        for (s in e.steps) big.append("\n• ").append(s)
        val by = when {
            e.explanation != null && e.explainedBy == "phone" -> "Explained on this phone by Llama 3.2."
            e.explanation != null -> "Explained by Llama 3.2 on your Home Hub."
            e.by == "phone" -> "Checked on this phone."
            else -> ""
        }
        if (by.isNotEmpty()) big.append("\n").append(by)
        val open = Intent(c, AlertActivity::class.java).putExtra(AlertActivity.EXTRA_ID, historyId)
        return post(c, id, CHANNEL, "${look.word} · ${e.title}", where, source, big.toString(), look.color, open,
            dial = true, time = e.time, hidden = "Unlock to see which message it is and what to do.")
    }

    /** Which message an alert is about: "VM-SBIINB: “Dear customer your SBI account will be…”". */
    private fun source(e: History.Entry, where: String): String {
        val from = e.sender.ifBlank { if (e.channel == "chat") "A saved contact" else where }
        val text = e.text?.replace(SPACES, " ")?.trim().orEmpty()
        if (text.isEmpty()) return from
        val cut = if (text.length > SNIPPET) text.take(SNIPPET).trimEnd() + "…" else text
        return "$from: “${Ui.defang(cut)}”"
    }

    /** A network alert from the Hub (NetAlerts.toJson); opens its own screen. */
    fun netAlert(c: Context, a: JSONObject, id: Int): Int {
        val verdict = a.optString("verdict")
        val look = Ui.look(c, verdict)
        val text = listOf(a.optString("what"), a.optString("why")).filter { it.isNotBlank() }.joinToString(" ")
        val big = StringBuilder(text)
        val steps = a.optJSONArray("steps")
        if (steps != null) for (i in 0 until steps.length()) big.append("\n• ").append(steps.optString(i))
        if (a.optBoolean("explained")) big.append("\nExplained by Llama 3.2 on your Home Hub.")
        val open = Intent(c, AlertActivity::class.java).putExtra(AlertActivity.EXTRA_NET, a.optString("id"))
        return post(c, id, NET, "${look.word} · ${a.optString("title")}", a.optString("device"), text, big.toString(),
            look.color, open, dial = false, time = a.optLong("time_ms", 0L), hidden = "Unlock to see which device and what to do.")
    }

    @SuppressLint("MissingPermission")     // checked just below
    private fun post(c: Context, id: Int, channel: String, title: String, sub: String, text: String, big: String,
                     color: Int, open: Intent, dial: Boolean, time: Long = 0L, hidden: String = ""): Int {
        ensureChannel(c)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(c, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) return id
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val tap = PendingIntent.getActivity(c, id, open, flags)
        val b = NotificationCompat.Builder(c, channel)
            .setSmallIcon(R.drawable.ic_stat_sajag)
            .setColor(color)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(big))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .addAction(R.drawable.ic_shield, "What to do", tap)
        if (sub.isNotBlank()) b.setSubText(sub)
        if (time > 0L) b.setWhen(time).setShowWhen(true)    // when the message arrived, not when it was checked
        if (hidden.isNotBlank()) {
            // On a locked phone: the verdict and the scam type only, never the sender or the message.
            val locked = NotificationCompat.Builder(c, channel).setSmallIcon(R.drawable.ic_stat_sajag).setColor(color)
                .setContentTitle(title).setContentText(hidden)
            if (time > 0L) locked.setWhen(time).setShowWhen(true)
            b.setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setPublicVersion(locked.build())
        }
        if (dial) {
            val call = PendingIntent.getActivity(c, 1930, Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930")), flags)
            b.addAction(R.drawable.ic_call, "Call 1930", call)
        }
        NotificationManagerCompat.from(c).notify(id, b.build())
        return id
    }

    /** Is this notification still on screen (not swiped away or opened)? */
    fun isShowing(c: Context, id: Int): Boolean =
        c.getSystemService(NotificationManager::class.java)?.activeNotifications?.any { it.id == id } == true
}
