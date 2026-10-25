package com.example.ps3guardian

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat

/** One screen: Pi address, token and phone name, permissions, chats, two tests, and the last results. */
class MainActivity : AppCompatActivity() {

    private lateinit var url: EditText
    private lateinit var token: EditText
    private lateinit var device: EditText
    private lateinit var status: TextView
    private lateinit var chatStatus: TextView
    private lateinit var recent: TextView

    private val askPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
            val denied = result.filterValues { granted -> !granted }.keys.map { it.substringAfterLast('.') }
            status.text = if (denied.isEmpty()) {
                "Permissions allowed. Incoming SMS will now be checked."
            } else {
                "Not allowed: ${denied.joinToString()}. If SMS cannot be allowed, open App info, " +
                    "tap ⋮ and choose 'Allow restricted settings' (see the guide)."
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        url = findViewById(R.id.pi_url)
        token = findViewById(R.id.token)
        device = findViewById(R.id.device)
        status = findViewById(R.id.status)
        chatStatus = findViewById(R.id.chat_status)
        recent = findViewById(R.id.recent)
        url.setText(Settings.piUrl(this))
        token.setText(Settings.token(this))
        device.setText(Settings.device(this))
        Notifier.ensureChannel(this)

        findViewById<Button>(R.id.save).setOnClickListener {
            save()
            status.text = "Saved."
        }
        findViewById<Button>(R.id.permissions).setOnClickListener {
            val wanted = mutableListOf(Manifest.permission.RECEIVE_SMS)
            if (Build.VERSION.SDK_INT >= 33) wanted += Manifest.permission.POST_NOTIFICATIONS
            askPermissions.launch(wanted.toTypedArray())
        }
        findViewById<Button>(R.id.test_connection).setOnClickListener { testConnection() }
        findViewById<Button>(R.id.test_message).setOnClickListener { testMessage() }

        bindSwitch(R.id.chat_messages, Settings.chatKey(ChatApps.MESSAGES))
        bindSwitch(R.id.chat_whatsapp, Settings.chatKey(ChatApps.WHATSAPP))
        bindSwitch(R.id.chat_contacts, Settings.CHAT_CONTACTS)
        findViewById<Button>(R.id.notification_access).setOnClickListener { openNotificationAccess() }
    }

    // While the screen is open, show new results as soon as they are saved.
    private val refresh = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == Settings.KEY_RECENT || key == Settings.KEY_PENDING) runOnUiThread { showRecent() }
    }

    override fun onResume() {
        super.onResume()
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(refresh)
        showRecent()
        showChatStatus()                     // notification access may have just been allowed
        FlushWorker.flushSoon(this)          // send messages that waited for the Pi, if it can be reached now
    }

    override fun onPause() {
        Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(refresh)
        super.onPause()
    }

    private fun save() = Settings.save(this, url.text.toString(), token.text.toString(), device.text.toString())

    private fun bindSwitch(id: Int, key: String) {
        val box = findViewById<CheckBox>(id)
        box.isChecked = Settings.prefs(this).getBoolean(key, false)
        box.setOnCheckedChangeListener { _, on ->
            Settings.setSwitch(this, key, on)
            showChatStatus()
        }
    }

    /** Android's settings page where the user allows the app to read notifications. */
    private fun openNotificationAccess() {
        val list = Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        val intent = if (Build.VERSION.SDK_INT >= 30) {
            Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS).putExtra(
                android.provider.Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
                ComponentName(this, ChatListener::class.java).flattenToString()
            )
        } else {
            list
        }
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            startActivity(list)
        }
    }

    private fun showChatStatus() {
        val allowed = NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)
        val on = listOf(ChatApps.MESSAGES, ChatApps.WHATSAPP).filter { Settings.chatOn(this, it) }
            .map { ChatApps.label(it) }
        chatStatus.text = when {
            on.isEmpty() -> "Chats are not checked."
            !allowed -> "Tap 'Allow notification access' so that chats in ${on.joinToString(" and ")} can be checked."
            else -> "Checking chats in ${on.joinToString(" and ")} from numbers that are not in your contacts" +
                (if (Settings.chatContacts(this)) ", and from your contacts (testing)." else ".")
        }
    }

    private fun testConnection() {
        save()
        status.text = "Connecting..."
        Thread {
            val message = try {
                val health = PiClient(Settings.piUrl(this), Settings.token(this)).health()
                "Connected. Advisor: ${health.optString("backend")}."
            } catch (e: Exception) {
                "Cannot reach the Pi: ${e.message}"
            }
            runOnUiThread { status.text = message }
        }.start()
    }

    /** A fake scam from a phone number: checks the token too. The Pi does not log tests. */
    private fun testMessage() {
        save()
        status.text = "Sending a test scam..."
        Thread {
            Checker.test(
                applicationContext, "9812345678",
                "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/update"
            )
            runOnUiThread {
                status.text = "Test done: see the alert and the list below."
                showRecent()
            }
        }.start()
    }

    private fun showRecent() {
        val lines = Settings.recent(this)
        val waiting = Settings.pendingCount(this)
        val head = when (waiting) {
            0 -> ""
            1 -> "1 message is waiting for the Pi. It is sent as soon as the Pi can be reached.\n\n"
            else -> "$waiting messages are waiting for the Pi. They are sent as soon as the Pi can be reached.\n\n"
        }
        recent.text = head + if (lines.isEmpty()) "No messages checked yet." else lines.joinToString("\n\n")
    }
}
