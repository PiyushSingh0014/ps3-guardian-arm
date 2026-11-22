package com.ps3guardian.app

import android.content.Intent
import android.text.InputType
import android.view.View
import android.widget.CompoundButton
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AlertDialog

/**
 * Settings: what to check, the Home Hub, offline explanations, privacy and the testing tools.
 * Switches save at once; refresh() shows the saved state without saving again.
 */
class SettingsPage(private val a: MainActivity, private val root: View) {
    private var binding = false
    private val switches = mutableListOf<Triple<Int, String, Boolean>>()     // switch id, key, default

    init {
        switch(R.id.row_sms, R.id.sw_sms, Settings.SMS_ON, true)
        switch(R.id.row_whatsapp, R.id.sw_whatsapp, Settings.chatKey(ChatApps.WHATSAPP), false) { on -> if (on) askChatAccess() }
        switch(R.id.row_rcs, R.id.sw_rcs, Settings.chatKey(ChatApps.MESSAGES), false) { on -> if (on) askChatAccess() }
        switch(R.id.row_net, R.id.sw_net, Settings.NET_ON, true) { on -> if (on) NetWorker.start(a) else NetWorker.stop(a) }
        switch(R.id.row_study, R.id.sw_study, Settings.STUDY, false)
        switch(R.id.row_contacts, R.id.sw_contacts, Settings.CHAT_CONTACTS, false)

        click(R.id.row_permissions) { a.askPermissions.launch(Perms.wanted()) }
        click(R.id.row_notif_access) { Perms.openNotificationAccess(a) }
        click(R.id.row_test) { Pairing.test(a, { note(R.id.hub_note, it) }) { } }
        click(R.id.row_pair) { a.startActivity(Intent(a, SetupActivity::class.java).putExtra(SetupActivity.EXTRA_STEP, 2)) }
        click(R.id.row_llama_get) { LlamaCopy.ask(a) { a.watchLlama() } }
        click(R.id.row_test_scam) {
            note(R.id.adv_note, "Sending a test scam…")
            val app = a.applicationContext
            Thread { Checker.test(app) { id -> a.runOnUiThread { a.openAlert(id) } } }.start()
        }
        click(R.id.row_phone_name) {
            Dialogs.input(a, "Phone name", "Marks this phone's messages in your Home Hub's log.", "For example: Riya's phone",
                Settings.device(a), InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS, 1, "Save") {
                Settings.saveDevice(a, it)
            }
        }
        click(R.id.row_hub_address) {
            Dialogs.input(a, "Home Hub address", "Usually https://10.42.0.1:8443 on the Home Hub's own Wi-Fi.", Settings.DEFAULT_URL,
                Settings.piUrl(a), InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI, 1, "Save") {
                Settings.saveUrl(a, it)
            }
        }
        click(R.id.row_token) {
            Dialogs.input(a, "Pairing code", "On the Home Hub, run: cat ~/.ps3_guardian_token", "The code your Home Hub shows",
                "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD, 1, "Save") {
                if (it.isNotBlank()) Settings.saveToken(a, it)
            }
        }
        click(R.id.row_log) {
            val lines = Settings.recent(a)
            AlertDialog.Builder(a)
                .setTitle("Activity log")
                .setMessage(if (lines.isEmpty()) "Nothing yet." else lines.joinToString("\n\n"))
                .setPositiveButton("Close", null)
                .show()
        }
        click(R.id.row_setup) { a.startActivity(Intent(a, SetupActivity::class.java)) }
        root.findViewById<TextView>(R.id.about_version).text = "Sajag ${Ui.VERSION}"
    }

    private fun click(id: Int, f: () -> Unit) = root.findViewById<View>(id).setOnClickListener { f() }

    private fun switch(rowId: Int, swId: Int, key: String, default: Boolean, changed: ((Boolean) -> Unit)? = null) {
        val sw = root.findViewById<CompoundButton>(swId)
        switches += Triple(swId, key, default)
        sw.setOnCheckedChangeListener { _, on ->
            if (!binding) {
                Settings.setSwitch(a, key, on)
                changed?.invoke(on)
            }
        }
        root.findViewById<View>(rowId).setOnClickListener { sw.toggle() }
    }

    /** Chats are read from notifications: Android asks the owner once, on its own settings page. */
    private fun askChatAccess() {
        if (Perms.chats(a)) return
        AlertDialog.Builder(a)
            .setTitle("Allow notification access")
            .setMessage("Sajag reads chats from the notifications of WhatsApp and Messages, only from numbers that " +
                "are not in your contacts. Android asks you to allow this on its own page.")
            .setPositiveButton("Open") { _, _ -> Perms.openNotificationAccess(a) }
            .setNegativeButton("Not now", null)
            .show()
    }

    private fun note(id: Int, text: String) {
        val t = root.findViewById<TextView>(id)
        t.text = text
        t.visibility = if (text.isBlank()) View.GONE else View.VISIBLE
    }

    private fun value(id: Int, text: String, color: Int) {
        val t = root.findViewById<TextView>(id)
        t.text = text
        t.setTextColor(a.getColor(color))
    }

    private fun host(url: String) = url.substringAfter("://").substringBefore("/")

    fun refresh() {
        binding = true
        val prefs = Settings.prefs(a)
        for ((id, key, default) in switches) root.findViewById<CompoundButton>(id).isChecked = prefs.getBoolean(key, default)
        binding = false

        val allowed = Perms.sms(a) && Perms.notifications(a)
        value(R.id.perm_value, if (allowed) "Allowed" else "Not allowed", if (allowed) R.color.safe else R.color.warn)
        val chats = Perms.chats(a)
        value(R.id.notif_value, if (chats) "Allowed" else "Off", if (chats) R.color.safe else R.color.text_3)

        val paired = Settings.pin(a).isNotBlank()
        val hub = Settings.hub(a)
        root.findViewById<TextView>(R.id.hub_sub).text = host(Settings.piUrl(a)) + if (paired) " · paired" else " · not paired"
        when {
            !paired -> value(R.id.hub_value, "Not paired", R.color.text_3)
            hub.state == "ok" -> value(R.id.hub_value, "Connected", R.color.safe)
            hub.state == "refused" -> value(R.id.hub_value, "Code not accepted", R.color.warn)
            hub.state == "" -> value(R.id.hub_value, "Not checked", R.color.text_3)
            else -> value(R.id.hub_value, "Away", R.color.warn)
        }

        val ready = PhoneLlama.ready(a)
        val pct = LlamaCopy.percent()
        root.findViewById<TextView>(R.id.llama_sub).text =
            if (ready) "Llama 3.2 1B · ${PhoneLlama.megabytes(PhoneLlama.size(a))}" else "Not on this phone yet"
        when {
            pct != null -> value(R.id.llama_value, "$pct%", R.color.ivory)
            ready -> value(R.id.llama_value, "Ready", R.color.safe)
            else -> value(R.id.llama_value, "Not added", R.color.text_3)
        }
        val bar = root.findViewById<ProgressBar>(R.id.llama_progress)
        bar.visibility = if (pct != null) View.VISIBLE else View.GONE
        bar.progress = pct ?: 0
        root.findViewById<TextView>(R.id.row_llama_get_title).text =
            if (ready) "Update from your Home Hub" else "Add from your Home Hub"
        note(R.id.llama_note, when {
            pct != null -> "Copying ${PhoneLlama.megabytes(PhoneLlama.copied)} of ${PhoneLlama.megabytes(PhoneLlama.toCopy)}. " +
                "Keep this screen open and stay on your home Wi-Fi."
            else -> PhoneLlama.copyResult ?: ""
        })

        value(R.id.phone_name_value, Settings.device(a).ifBlank { "Not set" }, R.color.text_2)
        value(R.id.hub_address_value, host(Settings.piUrl(a)), R.color.text_2)
        value(R.id.token_value, if (Settings.token(a).isBlank()) "Not set" else "••••••", R.color.text_2)
    }
}
