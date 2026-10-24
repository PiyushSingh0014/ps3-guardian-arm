package com.ps3guardian.companion

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Sends one SMS to the Pi and shows the answer. Call it from a background thread. */
object Checker {
    private val DEVANAGARI = Regex("[\\u0900-\\u097F]")

    fun check(context: Context, sender: String, text: String, test: Boolean = false) {
        val time = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date())
        val from = sender.ifBlank { "unknown sender" }
        try {
            val client = PiClient(Settings.piUrl(context), Settings.token(context))
            val language = if (DEVANAGARI.containsMatchIn(text)) "hi" else "en"
            val res = client.checkSms(text.take(PiClient.MAX_MESSAGE), sender.take(64), language, test)
            val finding = res.getJSONObject("finding")
            val advice = res.getJSONObject("advice")
            val verdict = finding.optString("verdict", "safe")
            val score = finding.optDouble("score", 0.0)
            val label = verdict.uppercase(Locale.US)
            Settings.addRecent(context, "$time  $from  $label (${"%.2f".format(Locale.US, score)})\n${text.take(80)}")

            if (verdict != "safe") {
                val title = advice.optString("headline").ifBlank { label }
                val id = Notifier.show(context, title, Notifier.adviceText(advice))
                val explain = res.optJSONObject("explain")
                if (explain != null) ExplainWorker.enqueue(context, explain.getString("id"), id, title)
            }
        } catch (e: Exception) {
            Settings.addRecent(context, "$time  $from  NOT CHECKED: ${e.message}\n${text.take(80)}")
        }
    }
}
