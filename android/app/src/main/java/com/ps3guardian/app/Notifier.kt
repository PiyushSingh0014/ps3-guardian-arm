package com.ps3guardian.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

/** Scam alerts and network alerts, each with its own channel. Safe messages get no notification. */
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

    /** The advice from the Pi as notification text: what, why, then the steps. */
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

    /**
     * Shows a notification, or updates the one with this id. An update (Llama's text replacing
     * the first one) does not sound or vibrate again.
     */
    @SuppressLint("MissingPermission")     // checked just below
    fun show(c: Context, title: String, text: String,
             id: Int = (System.currentTimeMillis() % Int.MAX_VALUE).toInt(), channel: String = CHANNEL): Int {
        ensureChannel(c)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(c, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) return id
        val open = PendingIntent.getActivity(
            c, 0, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(c, channel)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text.lineSequence().firstOrNull() ?: "")
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .build()
        NotificationManagerCompat.from(c).notify(id, notification)
        return id
    }

    /** Is this notification still on screen (not swiped away or opened)? */
    fun isShowing(c: Context, id: Int): Boolean =
        c.getSystemService(NotificationManager::class.java)?.activeNotifications?.any { it.id == id } == true
}
