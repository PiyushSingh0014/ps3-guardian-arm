package com.ps3guardian.app

import android.content.Context
import com.ps3guardian.app.guard.GuardResult
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One message to check: an SMS, or a chat message (RCS, MMS, WhatsApp) read from a notification.
 * phoneVerdict and notifyId: what Phone Guard decided on this phone, and its alert, if it showed one.
 */
class Msg(val channel: String, val app: String?, val sender: String, val text: String, val received: Long,
          var phoneVerdict: String? = null, var notifyId: Int = 0)

/**
 * Checks each message on the phone first (Phone Guard: no network needed), then sends it to the Pi,
 * which adds Llama's explanation and its phishing list when the phone is on its Wi-Fi. When the Pi
 * cannot be reached and Llama is on this phone (update 44), Llama explains the alert here instead.
 * Blocking: call it from a background thread.
 */
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
        val r = onPhone(context, m)
        if (check(context, m, test = false)) {
            FlushWorker.flushSoon(context)              // the Pi answers: send anything still waiting
        } else {
            Settings.addPending(context, m)
            Settings.addRecent(context, line(m, "WAITING for the Pi"))
            FlushWorker.schedule(context)
            explainHere(context, m, r)
        }
    }

    /** The "Send a test scam" button: checked on the phone, then by the Pi; never kept for later, and the Pi does not log it. */
    fun test(context: Context, sender: String, text: String) {
        val m = Msg("sms", null, sender, text, System.currentTimeMillis())
        val r = onPhone(context, m)
        if (!check(context, m, test = true)) explainHere(context, m, r)
    }

    /** "hi" for a message in Devanagari, else "en": the language of the explanation. */
    fun languageOf(text: String) = if (DEVANAGARI.containsMatchIn(text)) "hi" else "en"

    /** Phone Guard: the verdict on this phone, at once, and an alert if the message is not safe. */
    private fun onPhone(context: Context, m: Msg): GuardResult? {
        val r = PhoneGuard.check(context, m.text.take(PiClient.MAX_MESSAGE), m.sender.take(64)) ?: return null
        m.phoneVerdict = r.verdict
        val ms = if (r.millis < 1) "under 1 ms" else "%.0f ms".format(Locale.US, r.millis)
        Settings.addRecent(context, line(m, "${r.verdict.uppercase(Locale.US)} (${"%.2f".format(Locale.US, r.score)}) on this phone, $ms"))
        if (r.verdict != "safe") {
            m.notifyId = Notifier.show(context, title(m, r), r.adviceText() + "\n(Checked on this phone.)")
        }
        return r
    }

    private fun title(m: Msg, r: GuardResult) = (if (m.app != null) "${ChatApps.label(m.app)}: " else "") + r.headline

    /** The Pi cannot be reached: Llama on this phone explains the phone's alert, if Llama is here. */
    private fun explainHere(context: Context, m: Msg, r: GuardResult?) {
        if (r == null || m.notifyId == 0) return
        PhoneExplainWorker.enqueue(context, r, m.notifyId, title(m, r), languageOf(m.text), head(m))
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
            val language = languageOf(m.text)
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
            val status = "Pi: $label (${"%.2f".format(Locale.US, score)})" + (if (late) ", checked later" else "")
            Settings.addRecent(context, line(m, status))

            if (verdict != "safe") {
                val where = if (m.app != null) "${ChatApps.label(m.app)}: " else ""
                val title = where + advice.optString("headline").ifBlank { label }
                val body = (if (late) "Received ${stamp(m.received)}. " else "") + Notifier.adviceText(advice)
                val warned = m.phoneVerdict != null && m.phoneVerdict != "safe"
                val id: Int? = when {
                    // the phone's alert is still on screen: the Pi's advice replaces it, Llama's text follows
                    m.notifyId != 0 && Notifier.isShowing(context, m.notifyId) -> Notifier.show(context, title, body, m.notifyId)
                    warned -> null                         // the phone warned already, and the alert was seen
                    else -> Notifier.show(context, title, body)
                }
                val explain = res.optJSONObject("explain")
                if (id != null && explain != null) ExplainWorker.enqueue(context, explain.getString("id"), id, title)
            }
            return true
        } catch (e: PiClient.Rejected) {
            // The Pi refused the message itself, not the token: sending it again would not help.
            Settings.addRecent(context, line(m, "NOT CHECKED: ${e.message}"))
            return true
        } catch (e: Exception) {
            if (test) Settings.addRecent(context, line(m, "the Pi did not answer: ${e.message}"))
            return false
        }
    }

    private fun stamp(time: Long) = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(time))

    private fun head(m: Msg): String {
        val from = (if (m.app != null) "[${ChatApps.label(m.app)}] " else "") + m.sender.ifBlank { "unknown sender" }
        return "${stamp(m.received)}  $from"
    }

    private fun line(m: Msg, status: String) = "${head(m)}  $status\n${m.text.take(80)}"
}
