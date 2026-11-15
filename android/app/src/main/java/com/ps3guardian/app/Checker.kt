package com.ps3guardian.app

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One message to check: an SMS, or a chat message (RCS, MMS, WhatsApp) read from a notification. */
class Msg(val channel: String, val app: String?, val sender: String, val text: String, val received: Long)

/** Sends messages to the Pi and shows the answer. Blocking: call it from a background thread. */
object Checker {
    private val DEVANAGARI = Regex("[\\u0900-\\u097F]")
    private const val LATE_MS = 2 * 60 * 1000L          // checked more than 2 minutes after it arrived
    private val flushLock = Any()

    /** A real SMS as it arrives: checked now, or kept on the phone until the Pi can be reached. */
    fun onSms(context: Context, sender: String, text: String) =
        onMessage(context, Msg("sms", null, sender, text, System.currentTimeMillis()))

    /** A chat message read by ChatListener: the same, marked as a chat from that app. */
    fun onChat(context: Context, app: String, sender: String, text: String) =
        onMessage(context, Msg("chat", app, sender, text, System.currentTimeMillis()))

    private fun onMessage(context: Context, m: Msg) {
        if (check(context, m, test = false)) {
            FlushWorker.flushSoon(context)              // the Pi answers: send anything still waiting
        } else {
            Settings.addPending(context, m)
            Settings.addRecent(context, line(m, "WAITING for the Pi"))
            FlushWorker.schedule(context)
        }
    }

    /** The "Send a test scam" button: never kept for later, and the Pi does not log it. */
    fun test(context: Context, sender: String, text: String) {
        check(context, Msg("sms", null, sender, text, System.currentTimeMillis()), test = true)
    }

    /** Sends the waiting messages, oldest first, until the Pi stops answering. */
    fun flush(context: Context) {
        synchronized(flushLock) {
            while (true) {
                val next = Settings.firstPending(context) ?: break
                if (!check(context, next.msg, test = false)) break
                Settings.removePending(context, next.id)
            }
        }
        if (Settings.pendingCount(context) == 0) {
            FlushWorker.stop(context)
            if (Settings.pendingCount(context) > 0) FlushWorker.schedule(context)   // one arrived meanwhile
        }
    }

    /** True when the Pi answered (or refused this message for good); false when it could not be reached. */
    private fun check(context: Context, m: Msg, test: Boolean): Boolean {
        try {
            val client = PiClient.of(context)
            val language = if (DEVANAGARI.containsMatchIn(m.text)) "hi" else "en"
            val res = client.checkSms(
                m.text.take(PiClient.MAX_MESSAGE), m.sender.take(64), language, test,
                channel = m.channel, app = m.app, device = Settings.device(context), study = Settings.study(context)
            )
            val finding = res.getJSONObject("finding")
            val advice = res.getJSONObject("advice")
            val verdict = finding.optString("verdict", "safe")
            val score = finding.optDouble("score", 0.0)
            val label = verdict.uppercase(Locale.US)
            val late = System.currentTimeMillis() - m.received > LATE_MS
            val status = "$label (${"%.2f".format(Locale.US, score)})" + (if (late) ", checked later" else "")
            Settings.addRecent(context, line(m, status))

            if (verdict != "safe") {
                val where = if (m.app != null) "${ChatApps.label(m.app)}: " else ""
                val title = where + advice.optString("headline").ifBlank { label }
                val body = (if (late) "Received ${stamp(m.received)}. " else "") + Notifier.adviceText(advice)
                val id = Notifier.show(context, title, body)
                val explain = res.optJSONObject("explain")
                if (explain != null) ExplainWorker.enqueue(context, explain.getString("id"), id, title)
            }
            return true
        } catch (e: PiClient.Rejected) {
            // The Pi refused the message itself, not the token: sending it again would not help.
            Settings.addRecent(context, line(m, "NOT CHECKED: ${e.message}"))
            return true
        } catch (e: Exception) {
            if (test) Settings.addRecent(context, line(m, "NOT CHECKED: ${e.message}"))
            return false
        }
    }

    private fun stamp(time: Long) = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(time))

    private fun line(m: Msg, status: String): String {
        val from = (if (m.app != null) "[${ChatApps.label(m.app)}] " else "") + m.sender.ifBlank { "unknown sender" }
        return "${stamp(m.received)}  $from  $status\n${m.text.take(80)}"
    }
}
