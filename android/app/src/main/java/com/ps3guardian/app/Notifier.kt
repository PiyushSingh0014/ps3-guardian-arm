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
 */
object Notifier {
    private const val CHANNEL = "alerts"
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
        val text = e.explanation ?: listOf(e.what, e.why).filter { it.isNotBlank() }.joinToString(" ")
        val big = StringBuilder(text)
        for (s in e.steps) big.append("\n• ").append(s)
        val by = when {
            e.explanation != null && e.explainedBy == "phone" -> "Explained on this phone by Llama 3.2."
            e.explanation != null -> "Explained by Llama 3.2 on your Home Hub."
            e.by == "phone" -> "Checked on this phone."
            else -> ""
        }
        if (by.isNotEmpty()) big.append("\n").append(by)
        val open = Intent(c, AlertActivity::class.java).putExtra(AlertActivity.EXTRA_ID, historyId)
        return post(c, id, CHANNEL, "${look.word} · ${e.title}", where, text, big.toString(), look.color, open, dial = true)
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
            look.color, open, dial = false)
    }

    @SuppressLint("MissingPermission")     // checked just below
    private fun post(c: Context, id: Int, channel: String, title: String, sub: String, text: String, big: String,
                     color: Int, open: Intent, dial: Boolean): Int {
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
