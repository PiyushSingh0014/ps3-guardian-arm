package com.example.ps3guardian

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/**
 * Android calls this for every incoming SMS. originatingAddress is the raw sender:
 * a registered sender ID such as "JD-HDFCBK-S" for businesses, or "+919812345678"
 * for a phone number. That raw ID is what the Pi's sender-aware scoring needs.
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (parts.isNullOrEmpty()) return

        // One broadcast carries all the parts of one long SMS from one sender.
        val sender = parts[0].originatingAddress ?: parts[0].displayOriginatingAddress ?: ""
        val text = parts.joinToString("") { it.messageBody ?: "" }
        if (text.isBlank()) return

        // Keep the receiver alive for the network call (a few seconds at most):
        // the Pi answers the verdict at once; Llama's explanation follows later.
        // If the Pi cannot be reached, the SMS is kept on the phone and sent later.
        val app = context.applicationContext
        val pending = goAsync()
        Thread {
            try {
                Checker.onSms(app, sender, text)
            } finally {
                pending.finish()
            }
        }.start()
    }
}
