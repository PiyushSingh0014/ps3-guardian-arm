package com.ps3guardian.app

import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * One alert (app 3.0): the verdict, what is happening (Llama's explanation once it is ready), what
 * to do now, why it was flagged and the message itself, its links broken so they can't be opened.
 * A checked message comes from History (EXTRA_ID); a network alert from the Hub's list (EXTRA_NET).
 * The screen redraws itself when the Hub's verdict or Llama's explanation arrives.
 */
open class AlertActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_ID = "history_id"
        const val EXTRA_NET = "net_id"
    }

    protected var historyId: String? = null
    private var netId: String? = null
    private var waitingText = "Checking…"

    private val refresh = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == History.KEY || key == Settings.KEY_NET_LIST) runOnUiThread { render() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_alert)
        Ui.edgeToEdge(this, findViewById(R.id.alert_root), findViewById(R.id.alert_status_space), null)
        findViewById<View>(R.id.alert_back).setOnClickListener { goBack() }
        findViewById<View>(R.id.btn_call).setOnClickListener { open(Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"))) }
        findViewById<View>(R.id.btn_report).setOnClickListener {
            open(Intent(Intent.ACTION_VIEW, Uri.parse("https://cybercrime.gov.in")))
        }
        historyId = intent.getStringExtra(EXTRA_ID)
        netId = intent.getStringExtra(EXTRA_NET)
    }

    override fun onResume() {
        super.onResume()
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(refresh)
        render()
    }

    override fun onPause() {
        Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(refresh)
        super.onPause()
    }

    /** Opened from a notification, the app's own screens are not under this one: open Home. */
    private fun goBack() {
        if (isTaskRoot) startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun open(i: Intent) {
        try {
            startActivity(i)
        } catch (e: ActivityNotFoundException) {
            // no dialler or browser on this phone: nothing to do
        }
    }

    /** Shown before the entry exists (a shared file being read), or when there is nothing to check. */
    protected fun showWaiting(text: String) {
        waitingText = text
        render()
    }

    private fun <T : View> v(id: Int): T = findViewById(id)

    private fun show(id: Int, on: Boolean) {
        findViewById<View>(id).visibility = if (on) View.VISIBLE else View.GONE
    }

    protected fun render() {
        val net = netId
        if (net != null) return renderNet(NetAlerts.find(this, net))
        val id = historyId ?: return renderEmpty(waitingText, "checking")
        val e = History.get(this, id) ?: return renderEmpty("This alert is no longer kept: Sajag keeps the newest 60.", "unknown")
        renderEntry(e)
    }

    private fun header(verdict: String, title: String, meta: String) {
        val look = Ui.look(this, verdict)
        v<View>(R.id.alert_card).background = Ui.rounded(look.tint, Ui.dp(this, 28).toFloat())
        Ui.verdictIcon(v(R.id.alert_icon_box), v<ImageView>(R.id.alert_icon), look, strong = true)
        val word = v<TextView>(R.id.alert_word)
        word.text = look.word
        word.setTextColor(look.color)
        v<TextView>(R.id.alert_title).text = title
        val m = v<TextView>(R.id.alert_meta)
        m.text = meta
        m.setTextColor(look.soft)
        m.visibility = if (meta.isBlank()) View.GONE else View.VISIBLE
    }

    private fun renderEmpty(title: String, verdict: String) {
        header(verdict, title, "")
        for (id in listOf(R.id.alert_state, R.id.alert_what_card, R.id.alert_steps_head, R.id.alert_steps, R.id.btn_call,
            R.id.btn_report, R.id.alert_reasons_head, R.id.alert_reasons, R.id.alert_msg_head, R.id.alert_msg_card)) show(id, false)
        v<TextView>(R.id.alert_footer).text = ""
    }

    private fun renderEntry(e: History.Entry) {
        val now = System.currentTimeMillis()
        val title = when {
            e.verdict == "checking" -> "Checking…"
            e.verdict == "unknown" -> if (e.channel == "file") "Not checked" else "Not checked yet"
            e.title.isNotBlank() -> e.title
            else -> "Checked"
        }
        val from = when (e.channel) {
            "file" -> e.name ?: ""
            "share", "test" -> ""
            else -> e.sender.ifBlank { if (e.channel == "chat") "a saved contact" else "" }
        }
        header(e.verdict, title, listOf(Ui.channelLabel(e.channel, e.app), from, Ui.whenText(e.time, now))
            .filter { it.isNotBlank() }.joinToString(" · "))

        val state = v<TextView>(R.id.alert_state)
        state.text = when {
            e.verdict == "checking" -> "Checking…"
            e.llama == "writing" && e.explanation == null -> "Llama is writing a plain explanation…"
            e.channel == "file" && e.hub == "unreachable" ->
                "Your Home Hub can't be reached, and files are checked there. Try again on your home Wi-Fi."
            e.hub == "refused" -> "Your Home Hub did not check it" + (if (e.why.isNotBlank()) ": ${e.why}" else ".")
            else -> ""
        }
        state.visibility = if (state.text.isNullOrBlank()) View.GONE else View.VISIBLE

        val explanation = e.explanation
        val what = explanation ?: listOf(e.what, e.why).filter { it.isNotBlank() }.joinToString(" ")
        show(R.id.alert_what_card, what.isNotBlank())
        v<TextView>(R.id.alert_what).text = what
        show(R.id.alert_by_row, explanation != null)
        v<TextView>(R.id.alert_by).text =
            if (e.explainedBy == "phone") "Explained on this phone by Llama 3.2" else "Explained by Llama 3.2 on your Home Hub"

        steps(e.steps)
        show(R.id.btn_call, e.flagged)
        show(R.id.btn_report, e.flagged)
        reasons(if (e.flagged) e.reasons else emptyList(), e.verdict)

        val text = e.text
        show(R.id.alert_msg_head, text != null)
        show(R.id.alert_msg_card, text != null)
        if (text != null) {
            v<TextView>(R.id.alert_from).text = listOf(e.sender, Ui.channelLabel(e.channel, e.app))
                .filter { it.isNotBlank() }.joinToString(" · ")
            v<TextView>(R.id.alert_text).text = Ui.defang(text)
        }
        v<TextView>(R.id.alert_footer).text = footer(e)
    }

    private fun footer(e: History.Entry): String {
        val lines = mutableListOf<String>()
        val ms = e.checkMs
        val phone = if (ms < 0) "" else if (ms < 1) "under 1 ms" else "%.0f ms".format(Locale.US, ms)
        when {
            e.by == "hub" && phone.isNotEmpty() -> lines += "Checked on this phone in $phone, then by your Home Hub" +
                (if (e.hub == "later" && e.hubAt > 0) " at ${Ui.clock(e.hubAt)}, when it could be reached." else ".")
            e.by == "hub" -> lines += "Checked by your Home Hub."
            phone.isNotEmpty() -> lines += "Checked on this phone in $phone."
        }
        when (e.hub) {
            "waiting" -> lines += "Your Home Hub was out of reach. It checks this message again when you're home."
            "unreachable" -> if (e.channel != "file") lines += "Your Home Hub could not be reached, so this verdict is the phone's alone."
        }
        if (e.explainNote.isNotBlank()) lines += "Llama on this phone explained it in ${e.explainNote}."
        if (e.channel == "test") lines += "A test: your Home Hub does not log it."
        return lines.joinToString("\n")
    }

    private fun renderNet(a: JSONObject?) {
        if (a == null) return renderEmpty("This alert is no longer in your Home Hub's list.", "unknown")
        val now = System.currentTimeMillis()
        val t = a.optLong("time_ms", 0L)
        val time = if (t > 0L) Ui.whenText(t, now) else a.optString("time")
        header(a.optString("verdict"), a.optString("title"),
            listOf(a.optString("device"), time).filter { it.isNotBlank() }.joinToString(" · "))
        show(R.id.alert_state, false)
        val what = listOf(a.optString("what"), a.optString("why")).filter { it.isNotBlank() }.joinToString(" ")
        show(R.id.alert_what_card, what.isNotBlank())
        v<TextView>(R.id.alert_what).text = what
        show(R.id.alert_by_row, a.optBoolean("explained"))
        v<TextView>(R.id.alert_by).text = "Explained by Llama 3.2 on your Home Hub"
        steps(strings(a.optJSONArray("steps")))
        show(R.id.btn_call, false)
        show(R.id.btn_report, false)
        reasons(strings(a.optJSONArray("reasons")), a.optString("verdict"))
        show(R.id.alert_msg_head, false)
        show(R.id.alert_msg_card, false)
        v<TextView>(R.id.alert_footer).text = "Found by your Home Hub, which watches the devices on your home Wi-Fi."
    }

    private fun strings(a: JSONArray?): List<String> = if (a == null) emptyList() else List(a.length()) { a.optString(it) }

    private fun steps(items: List<String>) {
        show(R.id.alert_steps_head, items.isNotEmpty())
        show(R.id.alert_steps, items.isNotEmpty())
        val list = v<LinearLayout>(R.id.alert_steps)
        list.removeAllViews()
        items.forEachIndexed { i, s ->
            val row = layoutInflater.inflate(R.layout.row_step, list, false)
            row.findViewById<TextView>(R.id.step_n).text = (i + 1).toString()
            row.findViewById<TextView>(R.id.step_text).text = s
            row.findViewById<View>(R.id.step_divider).visibility = if (i < items.size - 1) View.VISIBLE else View.GONE
            list.addView(row)
        }
    }

    private fun reasons(items: List<String>, verdict: String) {
        show(R.id.alert_reasons_head, items.isNotEmpty())
        show(R.id.alert_reasons, items.isNotEmpty())
        val list = v<LinearLayout>(R.id.alert_reasons)
        list.removeAllViews()
        val look = Ui.look(this, verdict)
        items.forEachIndexed { i, s ->
            val row = layoutInflater.inflate(R.layout.row_reason, list, false)
            row.findViewById<View>(R.id.reason_icon_box).background = Ui.circle(look.tint)
            val icon = row.findViewById<ImageView>(R.id.reason_icon)
            icon.setImageResource(reasonIcon(s))
            Ui.tint(icon, look.color)
            row.findViewById<TextView>(R.id.reason_text).text = Ui.defang(s.replaceFirstChar { it.uppercaseChar() })
            row.findViewById<View>(R.id.reason_divider).visibility = if (i < items.size - 1) View.VISIBLE else View.GONE
            list.addView(row)
        }
    }

    /** A picture for a warning sign, from its words. */
    private fun reasonIcon(s: String): Int {
        val t = s.lowercase(Locale.US)
        return when {
            listOf("link", "website", "url", "domain", "site").any { it in t } -> R.drawable.ic_link
            listOf("prize", "lottery", "reward", "refund", "cashback", "won").any { it in t } -> R.drawable.ic_gift
            listOf("otp", "pin", "password", "cvv", "secret").any { it in t } -> R.drawable.ic_lock
            listOf("urgent", "today", "immediately", "deadline", "block", "suspend", "hours").any { it in t } -> R.drawable.ic_clock
            listOf("number", "sender", "mobile", "header").any { it in t } -> R.drawable.ic_phone
            listOf("app", "apk", "file", "program").any { it in t } -> R.drawable.ic_download
            else -> R.drawable.ic_warn
        }
    }
}
