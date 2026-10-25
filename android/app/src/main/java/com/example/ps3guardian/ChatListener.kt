package com.example.ps3guardian

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Android shows this service every notification once you allow "Notification access" for the
 * app. It reads only chat messages from the messaging apps you switched on (Messages for RCS and
 * MMS, WhatsApp), only from senders shown as a phone number (not saved contacts or businesses,
 * unless the testing switch is on), and checks them like an SMS. Everything else is ignored.
 */
class ChatListener : NotificationListenerService() {
    private val worker = Executors.newSingleThreadScheduledExecutor()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val app = ChatApps.appOf(sbn.packageName) ?: return
        if (!Settings.chatOn(this, app)) return
        val n = sbn.notification ?: return
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return       // "3 new messages" summaries
        val msg = ChatApps.latestIncoming(n) ?: return
        val sender = ChatApps.unknownNumber(msg.sender)
            ?: (if (Settings.chatContacts(this)) msg.sender else return)
        val context = applicationContext
        // Wait a few seconds: an SMS also shows up as a Messages notification, and the SMS
        // receiver must have noted it first, so it is not checked a second time as a chat.
        worker.schedule(Runnable {
            try {
                if (Seen.isRecentSms(context, msg.text)) return@Runnable
                if (!Seen.firstTimeChat(context, app, sender, msg.text)) return@Runnable
                Checker.onChat(context, app, sender, msg.text)
            } catch (e: Exception) {
                // never let one unusual notification stop the service
            }
        }, 5, TimeUnit.SECONDS)
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }
}
