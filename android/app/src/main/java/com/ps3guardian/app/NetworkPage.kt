package com.ps3guardian.app

import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/**
 * Home network: what the Home Hub finds on the home Wi-Fi. A summary card (red, yellow or green),
 * the devices riskiest first, then the Hub's network alerts, newest first.
 */
class NetworkPage(private val a: MainActivity, private val root: View) {
    private var summaryClick: (() -> Unit)? = null
    private var shown = ""

    init {
        root.findViewById<View>(R.id.btn_net_on).setOnClickListener {
            Settings.setSwitch(a, Settings.NET_ON, true)
            NetWorker.start(a)
            refresh()
        }
        root.findViewById<View>(R.id.net_summary).setOnClickListener { summaryClick?.invoke() }
    }

    private fun name(d: JSONObject): String = d.optString("name").take(32).ifBlank { d.optString("ip") }

    private fun summary(verdict: String, title: String, text: String, click: (() -> Unit)?) {
        val look = Ui.look(a, verdict)
        val card = root.findViewById<View>(R.id.net_summary)
        card.visibility = View.VISIBLE
        card.background = Ui.rounded(look.tint, Ui.dp(a, 24).toFloat())
        val box = root.findViewById<View>(R.id.net_summary_icon_box)
        val icon = root.findViewById<ImageView>(R.id.net_summary_icon)
        box.background = Ui.circle(look.color)
        icon.setImageResource(when (verdict) {
            "dangerous", "suspicious" -> look.icon
            "safe" -> R.drawable.ic_shield_check
            else -> R.drawable.ic_hub
        })
        Ui.tint(icon, look.ink)
        root.findViewById<TextView>(R.id.net_summary_title).text = title
        val t = root.findViewById<TextView>(R.id.net_summary_text)
        t.text = text
        t.setTextColor(look.soft)
        root.findViewById<View>(R.id.net_summary_chevron).visibility = if (click != null) View.VISIBLE else View.GONE
        summaryClick = click
    }

    fun refresh() {
        val on = Settings.netOn(a)
        root.findViewById<View>(R.id.net_off).visibility = if (on) View.GONE else View.VISIBLE
        val devices = Settings.devList(a)
        val alerts = Settings.netList(a)
        val checked = Settings.netCheckedAt(a)
        val failed = Settings.netFailedAt(a)
        val paired = Settings.pin(a).isNotBlank()
        val atRisk = devices.filter { it.optString("risk") == "at_risk" }
        val check = devices.filter { it.optString("risk") == "check" }

        when {
            !on -> {
                root.findViewById<View>(R.id.net_summary).visibility = View.GONE
                summaryClick = null
            }
            !paired -> summary("checking", "Pair your Home Hub",
                "Network checks come from your Home Hub. Pair it in Settings, on your home Wi-Fi.") {
                a.select(MainActivity.TAB_SETTINGS)
            }
            devices.isEmpty() && (checked == 0L || failed > checked) -> summary("checking", "Can't reach your Home Hub",
                "Network checks work while this phone is on your home Wi-Fi.", null)
            atRisk.isNotEmpty() || check.isNotEmpty() -> {
                val worst = if (atRisk.isNotEmpty()) atRisk else check
                val d = worst.first()
                val latest = d.optJSONArray("latest")?.optJSONObject(0)?.optString("headline") ?: ""
                val n = worst.size
                val title = if (atRisk.isNotEmpty()) (if (n == 1) "1 device at risk" else "$n devices at risk")
                else (if (n == 1) "1 device needs a look" else "$n devices need a look")
                val newest = alerts.firstOrNull { it.optString("ip") == d.optString("ip") }
                summary(if (atRisk.isNotEmpty()) "dangerous" else "suspicious", title,
                    "${name(d)}: ${History.cleanTitle(latest).ifBlank { "see its alerts" }}.",
                    newest?.let { o -> { a.openNetAlert(o.optString("id")) } })
            }
            else -> summary("safe", "All devices look normal",
                (if (devices.size == 1) "1 device" else "${devices.size} devices") +
                    " on your Wi-Fi this week, none with an alert in the last 24 hours.", null)
        }

        // The lists are drawn again only when the Hub's answer changed (it is asked every 10 s).
        val sig = "$on|" + devices.joinToString { it.toString() } + "|" + alerts.joinToString { it.toString() }
        if (sig != shown) {
            shown = sig
            lists(devices, alerts, on)
        }

        root.findViewById<TextView>(R.id.net_status).text = when {
            !on -> ""
            checked == 0L && failed == 0L -> "Not checked yet."
            failed > checked -> "Can't reach your Home Hub" +
                (if (checked > 0L) " (last reached at ${Ui.clock(checked)})." else ".")
            else -> "Checked at ${Ui.clock(checked)}. New alerts come as notifications."
        }
    }

    private fun lists(devices: List<JSONObject>, alerts: List<JSONObject>, on: Boolean) {
        val devList = root.findViewById<LinearLayout>(R.id.dev_list)
        devList.removeAllViews()
        devices.forEachIndexed { i, d -> devList.addView(Rows.device(a, devList, d, last = i == devices.size - 1)) }
        devList.visibility = if (devices.isEmpty()) View.GONE else View.VISIBLE
        val devEmpty = root.findViewById<TextView>(R.id.dev_empty)
        devEmpty.text = "No devices seen yet."
        devEmpty.visibility = if (devices.isEmpty() && on) View.VISIBLE else View.GONE

        val netList = root.findViewById<LinearLayout>(R.id.net_list)
        netList.removeAllViews()
        alerts.forEachIndexed { i, o -> netList.addView(Rows.netAlert(a, netList, o, last = i == alerts.size - 1)) }
        netList.visibility = if (alerts.isEmpty()) View.GONE else View.VISIBLE
        val netEmpty = root.findViewById<TextView>(R.id.net_empty)
        netEmpty.text = "No network alerts."
        netEmpty.visibility = if (alerts.isEmpty() && on) View.VISIBLE else View.GONE
    }
}
