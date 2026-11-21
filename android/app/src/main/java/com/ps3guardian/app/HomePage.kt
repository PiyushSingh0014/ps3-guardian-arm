package com.ps3guardian.app

import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Home: whether this phone is protected (green), or what it needs (yellow); the Home Hub and
 * offline explanations at a glance; "Check a message" and "Check a link"; the newest results.
 */
class HomePage(private val a: MainActivity, private val root: View) {
    private val card: View = root.findViewById(R.id.status_card)
    private val title: TextView = root.findViewById(R.id.status_title)
    private val text: TextView = root.findViewById(R.id.status_text)
    private val action: TextView = root.findViewById(R.id.status_action)
    private val recent: LinearLayout = root.findViewById(R.id.recent_list)
    private var onAction: (() -> Unit)? = null

    init {
        root.findViewById<View>(R.id.btn_help).setOnClickListener { help() }
        root.findViewById<View>(R.id.btn_check_message).setOnClickListener { a.checkDialog(link = false) }
        root.findViewById<View>(R.id.btn_check_link).setOnClickListener { a.checkDialog(link = true) }
        root.findViewById<View>(R.id.see_all).setOnClickListener { a.select(MainActivity.TAB_ALERTS) }
        root.findViewById<View>(R.id.tile_hub_box).setOnClickListener { a.select(MainActivity.TAB_SETTINGS) }
        root.findViewById<View>(R.id.tile_explain_box).setOnClickListener { a.select(MainActivity.TAB_SETTINGS) }
        action.setOnClickListener { onAction?.invoke() }
    }

    private fun help() = Dialogs.info(
        a, "How Sajag works",
        "Every SMS, and chats from numbers you don't know if you allow them, is checked right here on this " +
            "phone, in a few milliseconds. Nothing is sent to the cloud.\n\n" +
            "At home, your Home Hub checks it too, with its list of phishing websites, and watches the devices " +
            "on your Wi-Fi.\n\n" +
            "If something looks wrong, you get an alert: what is happening, why, and what to do now. Llama writes " +
            "a short, plain explanation, on your Home Hub or on this phone."
    )

    fun refresh() {
        val c = a
        val hub = Settings.hub(c)
        val paired = Settings.pin(c).isNotBlank()
        val away = paired && hub.state != "ok"
        val allowed = Perms.sms(c) && Perms.notifications(c)

        // The card: green when protected, yellow when something needs the owner.
        val ok: Boolean
        onAction = null
        when {
            !allowed -> {
                ok = false
                title.text = "Allow Sajag to check messages"
                text.text = "Sajag needs to read incoming SMS and to show alerts. It never sends, changes or deletes a message."
                action.text = "Allow"
                onAction = { a.askPermissions.launch(Perms.wanted()) }
            }
            !Settings.smsOn(c) -> {
                ok = false
                title.text = "SMS checks are off"
                text.text = "Turn them on to be warned about scam messages."
                action.text = "Turn on"
                onAction = { Settings.setSwitch(c, Settings.SMS_ON, true) }
            }
            PhoneGuard.error != null && !PhoneGuard.loaded() -> {
                ok = false
                title.text = "Checks on this phone could not start"
                text.text = "Messages wait for your Home Hub instead. (${PhoneGuard.error})"
            }
            else -> {
                ok = true
                title.text = "You're protected"
                text.text = when {
                    !paired -> "Messages and links are checked on this phone. Pair your Home Hub to add its checks."
                    away -> "Away from your Home Hub. Messages and links are still checked here."
                    else -> "Your messages, links and home Wi-Fi are being checked."
                }
            }
        }
        action.visibility = if (onAction != null) View.VISIBLE else View.GONE
        val look = Ui.look(c, if (ok) "safe" else "suspicious")
        card.background = Ui.rounded(look.tint, Ui.dp(c, 28).toFloat())
        val iconBox = root.findViewById<View>(R.id.status_icon_box)
        val icon = root.findViewById<ImageView>(R.id.status_icon)
        iconBox.background = Ui.circle(look.color)
        icon.setImageResource(if (ok) R.drawable.ic_shield_check else R.drawable.ic_warn)
        Ui.tint(icon, look.ink)
        text.setTextColor(look.soft)

        // The three tiles.
        val phoneOn = allowed && Settings.smsOn(c)
        tile(R.id.tile_phone, R.id.tile_phone_label, if (phoneOn) "On" else "Off", look, warn = !phoneOn)
        val hubText = when {
            !paired -> "Not paired"
            hub.state == "ok" -> "Connected"
            hub.state == "refused" -> "Check code"
            hub.state == "" -> "Checking…"
            else -> "Away"
        }
        tile(R.id.tile_hub, R.id.tile_hub_label, hubText, look, warn = paired && hub.state != "ok" && hub.state != "")
        val pct = LlamaCopy.percent()
        val explain = when {
            pct != null -> "$pct%"
            PhoneLlama.ready(c) -> "Ready"
            else -> "Not added"
        }
        tile(R.id.tile_explain, R.id.tile_explain_label, explain, look, warn = false)

        // Messages waiting for the Hub.
        val waiting = Settings.pendingCount(c)
        root.findViewById<View>(R.id.waiting).visibility = if (waiting > 0) View.VISIBLE else View.GONE
        root.findViewById<TextView>(R.id.waiting_text).text = if (waiting == 1)
            "1 message waits for your Home Hub. It is sent as soon as the Hub can be reached."
        else "$waiting messages wait for your Home Hub. They are sent as soon as the Hub can be reached."

        // The newest three results.
        val entries = History.entries(c).take(3)
        recent.removeAllViews()
        entries.forEachIndexed { i, e -> recent.addView(Rows.entry(a, recent, e, last = i == entries.size - 1)) }
        recent.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
        root.findViewById<View>(R.id.recent_empty).visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun tile(valueId: Int, labelId: Int, value: String, look: Ui.Look, warn: Boolean) {
        val v = root.findViewById<TextView>(valueId)
        v.text = value
        v.setTextColor(if (warn) a.getColor(R.color.warn) else a.getColor(R.color.ivory))
        root.findViewById<TextView>(labelId).setTextColor(look.soft)
    }
}
