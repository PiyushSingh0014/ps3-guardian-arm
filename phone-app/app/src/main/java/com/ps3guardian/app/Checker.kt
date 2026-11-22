package com.ps3guardian.app

import android.content.Context
import com.ps3guardian.app.guard.GuardResult
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One message to check: an SMS, or a chat message (RCS, MMS, WhatsApp) read from a notification.
 * phoneVerdict and notifyId: what Phone Guard decided on this phone, and its alert, if it showed one;
 * historyId: its entry in History (app 3.0), for the alert's screen.
 */
class Msg(val channel: String, val app: String?, val sender: String, val text: String, val received: Long,
          var phoneVerdict: String? = null, var notifyId: Int = 0, var historyId: String = "")

/**
 * Checks each message on the phone first (Phone Guard: no network needed), then sends it to the
 * Home Hub, which adds Llama's explanation and its phishing list when the phone is on the home
 * Wi-Fi. When the Hub cannot be reached and Llama is on this phone (update 44), Llama explains the
 * alert here instead. Every result goes into History for the screens, and into the activity log.
 * Blocking: call it from a background thread.
 */
object Checker {
    private val DEVANAGARI = Regex("[\\u0900-\\u097F]")
    private const val LATE_MS = 2 * 60 * 1000L          // checked more than 2 minutes after it arrived
    private val flushLock = Any()
    const val TEST_SENDER = "9812345678"
    const val TEST_TEXT = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/update"

    /** A real SMS as it arrives: checked now, or kept on the phone until the Hub can be reached. */
    fun onSms(context: Context, sender: String, text: String) =
        onMessage(context, Msg("sms", null, sender, text, System.currentTimeMillis()))

    /** A chat message read by ChatListener: the same, marked as a chat from that app. */
    fun onChat(context: Context, app: String, sender: String, text: String) =
        onMessage(context, Msg("chat", app, sender, text, System.currentTimeMillis()))

    private fun onMessage(context: Context, m: Msg) {
        m.historyId = History.create(context, m.channel, m.app, m.sender, m.received)
        val r = onPhone(context, m)
        if (check(context, m, test = false)) {
            FlushWorker.flushSoon(context)              // the Hub answers: send anything still waiting
        } else {
            Settings.addPending(context, m)
            History.set(context, m.historyId, "hub", "waiting")
            Settings.addRecent(context, line(m, "WAITING for the Home Hub"))
            FlushWorker.schedule(context)
            explainHere(context, m, r)
        }
    }

    /**
     * "Send a test scam": checked on the phone, then by the Hub; never kept for later, and the Hub
     * does not log it. created: called with the History id as soon as the entry exists.
     */
    fun test(context: Context, created: ((String) -> Unit)? = null) {
        val m = Msg("test", null, TEST_SENDER, TEST_TEXT, System.currentTimeMillis())
        m.historyId = History.create(context, "test", null, TEST_SENDER, m.received)
        created?.invoke(m.historyId)
        val r = onPhone(context, m)
        if (!check(context, m, test = true)) {
            History.set(context, m.historyId, "hub", "unreachable")
            explainHere(context, m, r)
        }
    }

    /**
     * A message pasted into "Check a message" or shared to Sajag: no notification, since its own
     * screen is open. Returns at once with the History id; the checks run on a background thread.
     */
    fun shareText(context: Context, text: String): String {
        val c = context.applicationContext
        val m = Msg("share", null, "", text, System.currentTimeMillis())
        m.historyId = History.create(c, "share", null, "", m.received)
        Thread {
            val r = onPhone(c, m, notify = false)
            if (!checkText(c, m)) {
                History.set(c, m.historyId, "hub", "unreachable")
                if (r != null && r.verdict != "safe") PhoneExplainWorker.enqueue(c, r, 0, "", languageOf(text), head(m), m.historyId)
            }
        }.start()
        return m.historyId
    }

    /** "hi" for a message in Devanagari, else "en": the language of the explanation. */
    fun languageOf(text: String) = if (DEVANAGARI.containsMatchIn(text)) "hi" else "en"

    /** Phone Guard: the verdict on this phone, at once, and an alert if the message is not safe. */
    private fun onPhone(context: Context, m: Msg, notify: Boolean = true): GuardResult? {
        val r = PhoneGuard.check(context, m.text.take(PiClient.MAX_MESSAGE), m.sender.take(64).ifBlank { null })
        if (r == null) {
            Settings.addRecent(context, line(m, "not checked on this phone: ${PhoneGuard.error ?: "Phone Guard is not ready"}"))
            return null
        }
        m.phoneVerdict = r.verdict
        History.fromPhone(context, m.historyId, r, m.text)
        val ms = if (r.millis < 1) "under 1 ms" else "%.0f ms".format(Locale.US, r.millis)
        Settings.addRecent(context, line(m, "${r.verdict.uppercase(Locale.US)} (${"%.2f".format(Locale.US, r.score)}) on this phone, $ms"))
        if (notify && r.verdict != "safe") {
            m.notifyId = Notifier.alert(context, m.historyId)
            History.set(context, m.historyId, "notify", m.notifyId)
        }
        return r
    }

    private fun title(m: Msg, r: GuardResult) = (if (m.app != null) "${ChatApps.label(m.app)}: " else "") + r.headline

    /** The Hub cannot be reached: Llama on this phone explains the phone's alert, if Llama is here. */
    private fun explainHere(context: Context, m: Msg, r: GuardResult?) {
        if (r == null || m.notifyId == 0) return
        PhoneExplainWorker.enqueue(context, r, m.notifyId, title(m, r), languageOf(m.text), head(m), m.historyId)
    }

    /** Sends the waiting messages, oldest first, until the Hub stops answering. */
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

    /** True when the Hub answered (or refused this message for good); false when it could not be reached. */
    private fun check(context: Context, m: Msg, test: Boolean): Boolean {
        // A message kept by app 2.x has no History entry yet: it gets one now, for its alert's screen.
        if (m.historyId.isEmpty()) m.historyId = History.create(context, m.channel, m.app, m.sender, m.received)
        try {
            val client = PiClient.of(context)
            val language = languageOf(m.text)
            val res = client.checkSms(
                m.text.take(PiClient.MAX_MESSAGE), m.sender.take(64), language, test,
                channel = if (m.channel == "test") "sms" else m.channel, app = m.app,
                device = Settings.device(context), study = Settings.study(context)
            )
            val finding = res.getJSONObject("finding")
            val verdict = finding.optString("verdict", "safe")
            val score = finding.optDouble("score", 0.0)
            val late = System.currentTimeMillis() - m.received > LATE_MS
            Settings.addRecent(context, line(m, "Home Hub: ${verdict.uppercase(Locale.US)} (${"%.2f".format(Locale.US, score)})" +
                (if (late) ", checked later" else "")))
            History.fromHub(context, m.historyId, res, m.text, late)

            if (verdict != "safe") {
                val warned = m.phoneVerdict != null && m.phoneVerdict != "safe"
                val id: Int? = when {
                    // the phone's alert is still on screen: the Hub's advice replaces it, Llama's text follows
                    m.notifyId != 0 && Notifier.isShowing(context, m.notifyId) -> Notifier.alert(context, m.historyId, m.notifyId)
                    warned -> null                         // the phone warned already, and the alert was seen
                    else -> Notifier.alert(context, m.historyId)
                }
                if (id != null) History.set(context, m.historyId, "notify", id)
                val explain = res.optJSONObject("explain")
                if (explain != null) ExplainWorker.enqueue(context, explain.getString("id"), id ?: 0, m.historyId)
            }
            return true
        } catch (e: PiClient.Rejected) {
            // The Hub refused the message itself, not the code: sending it again would not help.
            Settings.addRecent(context, line(m, "NOT CHECKED by the Home Hub: ${e.message}"))
            History.set(context, m.historyId, "hub", "refused")
            return true
        } catch (e: Exception) {
            if (test) Settings.addRecent(context, line(m, "the Home Hub did not answer: ${e.message}"))
            return false
        }
    }

    /** A shared or pasted text on the Hub: /check, then Llama's explanation in the background. */
    private fun checkText(c: Context, m: Msg): Boolean {
        return try {
            val res = PiClient.of(c).checkText(m.text.take(PiClient.MAX_MESSAGE), languageOf(m.text))
            History.fromHub(c, m.historyId, res, m.text, late = false)
            val explain = res.optJSONObject("explain")
            if (explain != null) ExplainWorker.enqueue(c, explain.getString("id"), 0, m.historyId)
            true
        } catch (e: PiClient.Rejected) {
            History.set(c, m.historyId, "hub", "refused")
            true
        } catch (e: Exception) {
            false
        }
    }

    /** A file shared to Sajag: checked on the Hub only (Phone Guard reads messages, not files). */
    fun shareFile(context: Context, name: String, data: ByteArray): String {
        val c = context.applicationContext
        val id = History.create(c, "file", null, "", System.currentTimeMillis(), name.take(120))
        Thread {
            try {
                val res = PiClient.of(c).checkFile(name, data)
                History.fromHub(c, id, res, null, late = false)
                val explain = res.optJSONObject("explain")
                if (explain != null) ExplainWorker.enqueue(c, explain.getString("id"), 0, id)
            } catch (e: PiClient.Rejected) {
                History.update(c, id) { it.put("verdict", "unknown").put("hub", "refused").put("why", e.message ?: "") }
            } catch (e: Exception) {
                History.update(c, id) { it.put("verdict", "unknown").put("hub", "unreachable") }
            }
        }.start()
        return id
    }

    private fun stamp(time: Long) = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(time))

    private fun head(m: Msg): String {
        val from = (if (m.app != null) "[${ChatApps.label(m.app)}] " else "") + m.sender.ifBlank { m.channel }
        return "${stamp(m.received)}  $from"
    }

    private fun line(m: Msg, status: String) = "${head(m)}  $status\n${m.text.take(80)}"
}
