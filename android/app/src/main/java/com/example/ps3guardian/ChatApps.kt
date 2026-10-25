package com.example.ps3guardian

import android.app.Notification
import androidx.core.app.NotificationCompat

/** Which chat apps are read, and how a chat message is taken from their notification. */
object ChatApps {
    const val MESSAGES = "messages"      // Google Messages and Samsung Messages: RCS chats and MMS
    const val WHATSAPP = "whatsapp"

    private val PACKAGES = mapOf(
        "com.google.android.apps.messaging" to MESSAGES,
        "com.samsung.android.messaging" to MESSAGES,
        "com.whatsapp" to WHATSAPP,
        "com.whatsapp.w4b" to WHATSAPP,
    )

    fun appOf(packageName: String): String? = PACKAGES[packageName]

    fun label(app: String) = when (app) {
        MESSAGES -> "Messages"
        WHATSAPP -> "WhatsApp"
        else -> app
    }

    class Incoming(val sender: String, val text: String)

    /** The newest message in the notification that someone else sent (not you), or null. */
    fun latestIncoming(n: Notification): Incoming? {
        val style = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(n)
        if (style != null) {
            val me = style.user.name?.toString()
            val m = style.messages.lastOrNull { msg ->
                val person = msg.person
                person != null && person.name?.toString() != me
            } ?: return null
            val sender = m.person?.name?.toString() ?: return null
            val text = m.text?.toString() ?: return null
            return if (text.isBlank()) null else Incoming(sender, text)
        }
        // Apps without the messaging layout: the title is the sender, the text the message.
        val title = n.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: return null
        val text = n.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: return null
        return if (text.isBlank()) null else Incoming(title, text)
    }

    private val NUMBER = Regex("^\\+?[0-9]{8,15}$")
    private val SPACING = Regex("[\\s()\\-.\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]")

    /**
     * The phone number, if the app shows the sender as a number: someone who is not in your
     * contacts. A saved contact or a business shows as a name, so this returns null for them.
     */
    fun unknownNumber(sender: String): String? {
        val s = sender.substringBefore('~').replace(SPACING, "")
        return if (NUMBER.matches(s)) s else null
    }
}
