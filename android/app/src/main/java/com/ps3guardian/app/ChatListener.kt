package com.ps3guardian.app

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
 * A business's SMS sender ID (JD-BOBSMS-S) is never read here: that message is an SMS, which
 * the SMS receiver checks with its real sender ID.
 *
 * One exception for saved contacts: a friend's account that was taken over can send fake
 * "wedding invitation" apps too, so when a contact's message names an app or program file
 * ("Wedding_Invitation.apk"), that name alone goes to the Pi, never the message or the contact.
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
            ?: (if (Settings.chatContacts(this) && !ChatApps.isSenderId(msg.sender)) msg.sender else null)
        val appFile = if (sender == null && !ChatApps.isSenderId(msg.sender)) ChatApps.appFileName(msg.text) else null
        if (sender == null && appFile == null) return
        val context = applicationContext
        // Wait a few seconds: an SMS also shows up as a Messages notification, and the SMS
        // receiver must have noted it first, so it is not checked a second time as a chat.
        worker.schedule(Runnable {
            try {
                if (sender == null) {                        // a saved contact: only the file's name
                    val name = appFile ?: return@Runnable
                    if (!Seen.firstTimeChat(context, app, CONTACT, name)) return@Runnable
                    Checker.onChat(context, app, CONTACT, "Attachment: $name")
                    return@Runnable
                }
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

    companion object {
        const val CONTACT = "a saved contact"    // sent instead of the contact's name
    }
}
