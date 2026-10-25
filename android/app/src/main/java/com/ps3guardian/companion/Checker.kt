package com.ps3guardian.companion

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Sends SMS to the Pi and shows the answer. Blocking: call it from a background thread. */
object Checker {
    private val DEVANAGARI = Regex("[\\u0900-\\u097F]")
    private const val LATE_MS = 2 * 60 * 1000L          // checked more than 2 minutes after it arrived
    private val flushLock = Any()

    /** A real SMS as it arrives: checked now, or kept on the phone until the Pi can be reached. */
    fun onSms(context: Context, sender: String, text: String) {
        val received = System.currentTimeMillis()
        if (check(context, sender, text, received, test = false)) {
            FlushWorker.flushSoon(context)              // the Pi answers: send anything still waiting
        } else {
            Settings.addPending(context, sender, text, received)
            Settings.addRecent(context, line(received, sender, "WAITING for the Pi", text))
            FlushWorker.schedule(context)
        }
    }

    /** The "Send a test scam" button: never kept for later, and the Pi does not log it. */
    fun test(context: Context, sender: String, text: String) {
        check(context, sender, text, System.currentTimeMillis(), test = true)
    }

    /** Sends the waiting SMS, oldest first, until the Pi stops answering. */
    fun flush(context: Context) {
        synchronized(flushLock) {
            while (true) {
                val next = Settings.firstPending(context) ?: break
                if (!check(context, next.sender, next.text, next.received, test = false)) break
                Settings.removePending(context, next.id)
            }
        }
        if (Settings.pendingCount(context) == 0) {
            FlushWorker.stop(context)
            if (Settings.pendingCount(context) > 0) FlushWorker.schedule(context)   // one arrived meanwhile
        }
    }

    /** True when the Pi answered (or refused this message for good); false when it could not be reached. */
    private fun check(context: Context, sender: String, text: String, received: Long, test: Boolean): Boolean {
        try {
            val client = PiClient(Settings.piUrl(context), Settings.token(context))
            val language = if (DEVANAGARI.containsMatchIn(text)) "hi" else "en"
            val res = client.checkSms(text.take(PiClient.MAX_MESSAGE), sender.take(64), language, test)
            val finding = res.getJSONObject("finding")
            val advice = res.getJSONObject("advice")
            val verdict = finding.optString("verdict", "safe")
            val score = finding.optDouble("score", 0.0)
            val label = verdict.uppercase(Locale.US)
            val late = System.currentTimeMillis() - received > LATE_MS
            val status = "$label (${"%.2f".format(Locale.US, score)})" + (if (late) ", checked later" else "")
            Settings.addRecent(context, line(received, sender, status, text))

            if (verdict != "safe") {
                val title = advice.optString("headline").ifBlank { label }
                val body = (if (late) "Received ${stamp(received)}. " else "") + Notifier.adviceText(advice)
                val id = Notifier.show(context, title, body)
                val explain = res.optJSONObject("explain")
                if (explain != null) ExplainWorker.enqueue(context, explain.getString("id"), id, title)
            }
            return true
        } catch (e: PiClient.Rejected) {
            // The Pi refused the message itself, not the token: sending it again would not help.
            Settings.addRecent(context, line(received, sender, "NOT CHECKED: ${e.message}", text))
            return true
        } catch (e: Exception) {
            if (test) Settings.addRecent(context, line(received, sender, "NOT CHECKED: ${e.message}", text))
            return false
        }
    }

    private fun stamp(time: Long) = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(time))

    private fun line(time: Long, sender: String, status: String, text: String) =
        "${stamp(time)}  ${sender.ifBlank { "unknown sender" }}  $status\n${text.take(80)}"
}
