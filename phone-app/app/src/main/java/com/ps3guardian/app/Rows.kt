package com.ps3guardian.app

import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import org.json.JSONObject
import java.util.Locale

/** The rows of the lists: checked messages, network alerts and devices (app 3.0). */
object Rows {
    private fun text(o: JSONObject, key: String): String = if (o.isNull(key)) "" else o.optString(key)

    /** A checked message: its verdict's icon, title, verdict and channel, time. note: the text's start. */
    fun entry(a: MainActivity, parent: ViewGroup, e: History.Entry, last: Boolean, note: Boolean = false): View {
        val v = a.layoutInflater.inflate(R.layout.row_alert, parent, false)
        val look = Ui.look(a, e.verdict)
        Ui.verdictIcon(v.findViewById(R.id.row_icon_box), v.findViewById<ImageView>(R.id.row_icon), look, strong = false)
        v.findViewById<TextView>(R.id.row_title).text = when {
            e.verdict == "checking" -> "Checking…"
            e.verdict == "unknown" -> "Not checked" + (e.name?.let { ": $it" } ?: "")
            e.title.isNotBlank() -> e.title
            else -> "Checked"
        }
        v.findViewById<TextView>(R.id.row_sub).text = Ui.verdictLine(look.word, look.color, Ui.channelLabel(e.channel, e.app))
        val t = e.text
        if (note && t != null) {
            val n = v.findViewById<TextView>(R.id.row_note)
            n.text = Ui.defang(t.replace('\n', ' ').take(120))
            n.visibility = View.VISIBLE
        }
        v.findViewById<TextView>(R.id.row_time).text = Ui.shortTime(e.time, System.currentTimeMillis())
        v.findViewById<View>(R.id.row_divider).visibility = if (last) View.GONE else View.VISIBLE
        v.findViewById<View>(R.id.row).setOnClickListener { a.openAlert(e.id) }
        return v
    }

    /** A network alert from the Home Hub (NetAlerts.toJson). */
    fun netAlert(a: MainActivity, parent: ViewGroup, o: JSONObject, last: Boolean): View {
        val v = a.layoutInflater.inflate(R.layout.row_alert, parent, false)
        val look = Ui.look(a, text(o, "verdict"))
        Ui.verdictIcon(v.findViewById(R.id.row_icon_box), v.findViewById<ImageView>(R.id.row_icon), look, strong = false)
        v.findViewById<TextView>(R.id.row_title).text = text(o, "title")
        v.findViewById<TextView>(R.id.row_sub).text = Ui.verdictLine(look.word, look.color, text(o, "device"))
        val t = o.optLong("time_ms", 0L)
        v.findViewById<TextView>(R.id.row_time).text =
            if (t > 0L) Ui.shortTime(t, System.currentTimeMillis()) else text(o, "time").drop(11).take(5)
        v.findViewById<View>(R.id.row_divider).visibility = if (last) View.GONE else View.VISIBLE
        v.findViewById<View>(R.id.row).setOnClickListener { a.openNetAlert(text(o, "id")) }
        return v
    }

    /** A device on the home Wi-Fi (GET /devices): icon, name, what is known, risk. */
    fun device(a: MainActivity, parent: ViewGroup, d: JSONObject, last: Boolean): View {
        val v = a.layoutInflater.inflate(R.layout.row_device, parent, false)
        val risk = text(d, "risk")
        val look = Ui.look(a, when (risk) {
            "at_risk" -> "dangerous"
            "check" -> "suspicious"
            else -> "safe"
        })
        val name = text(d, "name").take(32)                      // chosen by the device: shown as text only
        val ip = text(d, "ip")
        v.findViewById<TextView>(R.id.dev_name).text = name.ifBlank { "Unnamed device" }
        val latest = d.optJSONArray("latest")?.optJSONObject(0)
        val about = when {
            risk != "ok" && latest != null -> History.cleanTitle(text(latest, "headline"))
            text(d, "learning_until").isNotBlank() -> "Learning its normal until ${text(d, "learning_until")}"
            text(d, "last_active").isNotBlank() -> "Active ${text(d, "last_active")}"
            else -> ""
        }
        val sub = v.findViewById<TextView>(R.id.dev_sub)
        sub.text = listOf(if (name.isBlank()) ip else "", about).filter { it.isNotBlank() }.joinToString(" · ")
        sub.setTextColor(if (risk != "ok") look.color else a.getColor(R.color.text_3))
        val box = v.findViewById<View>(R.id.dev_icon_box)
        val icon = v.findViewById<ImageView>(R.id.dev_icon)
        icon.setImageResource(deviceIcon(name, d.optBoolean("lab_device")))
        if (risk != "ok") {
            box.background = Ui.circle(look.tint)
            Ui.tint(icon, look.color)
        } else {
            box.background = Ui.circle(a.getColor(R.color.raised))
            Ui.tint(icon, a.getColor(R.color.text_2))
        }
        val chip = v.findViewById<TextView>(R.id.dev_chip)
        chip.text = when (risk) {
            "at_risk" -> "At risk"
            "check" -> "Check"
            else -> "OK"
        }
        chip.background = Ui.rounded(look.tint, Ui.dp(a, 14).toFloat())
        chip.setTextColor(look.color)
        v.findViewById<View>(R.id.dev_divider).visibility = if (last) View.GONE else View.VISIBLE
        v.findViewById<View>(R.id.dev_row).setOnClickListener { deviceDetails(a, d) }
        return v
    }

    /** What the Hub knows about a device; its newest alert opens from here when there is one. */
    private fun deviceDetails(a: MainActivity, d: JSONObject) {
        val ip = text(d, "ip")
        val newest = Settings.netList(a).firstOrNull { it.optString("ip") == ip }
        if (text(d, "risk") != "ok" && newest != null) {
            a.openNetAlert(newest.optString("id"))
            return
        }
        val lines = listOfNotNull(
            text(d, "summary").ifBlank { null },
            ip.ifBlank { null }?.let { "Address on your Wi-Fi: $it" },
            text(d, "first_seen").ifBlank { null }?.let { "First seen: $it" },
            text(d, "last_active").ifBlank { null }?.let { "Last active: $it" },
            text(d, "learning_until").ifBlank { null }?.let { "Your Home Hub is learning its normal until $it." },
        )
        Dialogs.info(a, text(d, "name").take(32).ifBlank { "Unnamed device" }, lines.joinToString("\n\n"))
    }

    /** A picture for a device, from its name. */
    private fun deviceIcon(name: String, lab: Boolean): Int {
        val n = name.lowercase(Locale.US)
        return when {
            listOf("cam", "doorbell").any { it in n } -> R.drawable.ic_camera
            listOf("tv", "chromecast", "firestick", "roku").any { it in n } -> R.drawable.ic_tv
            listOf("laptop", "desktop", "pc", "macbook", "windows", "loq", "thinkpad").any { it in n } -> R.drawable.ic_laptop
            listOf("phone", "android", "iphone", "galaxy", "pixel", "redmi", "oppo", "vivo", "realme", "oneplus", "moto", "-s2")
                .any { it in n } -> R.drawable.ic_phone
            listOf("plug", "socket", "bulb", "light").any { it in n } -> R.drawable.ic_plug
            lab || listOf("esp", "sensor", "iot", "arduino").any { it in n } -> R.drawable.ic_chip
            else -> R.drawable.ic_wifi
        }
    }
}
