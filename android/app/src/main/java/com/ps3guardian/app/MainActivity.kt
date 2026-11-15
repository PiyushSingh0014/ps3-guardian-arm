package com.ps3guardian.app

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One screen: Pi address, token and phone name, pairing with the Pi's certificate, the study switch,
 * permissions, chats, two tests, the network alerts from the Pi's lab Wi-Fi, and the last results.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var url: EditText
    private lateinit var token: EditText
    private lateinit var device: EditText
    private lateinit var status: TextView
    private lateinit var chatStatus: TextView
    private lateinit var netStatus: TextView
    private lateinit var devList: TextView
    private lateinit var netAlerts: TextView
    private lateinit var recent: TextView
    private val handler = Handler(Looper.getMainLooper())

    // While the screen is open, ask the Pi for network alerts and its device list every 10 s.
    private val netLoop = object : Runnable {
        override fun run() {
            if (Settings.netOn(this@MainActivity)) {
                val app = applicationContext
                Thread {
                    if (NetAlerts.check(app)) Devices.check(app)
                    runOnUiThread { showNet() }
                }.start()
            }
            handler.postDelayed(this, 10_000L)
        }
    }

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
        netStatus = findViewById(R.id.net_status)
        devList = findViewById(R.id.dev_list)
        netAlerts = findViewById(R.id.net_alerts)
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
        findViewById<Button>(R.id.pair).setOnClickListener { pair() }
        findViewById<Button>(R.id.test_connection).setOnClickListener { testConnection() }
        findViewById<Button>(R.id.test_message).setOnClickListener { testMessage() }

        val studyBox = findViewById<CheckBox>(R.id.study)
        studyBox.isChecked = Settings.study(this)
        studyBox.setOnCheckedChangeListener { _, on -> Settings.setSwitch(this, Settings.STUDY, on) }

        bindSwitch(R.id.chat_messages, Settings.chatKey(ChatApps.MESSAGES))
        bindSwitch(R.id.chat_whatsapp, Settings.chatKey(ChatApps.WHATSAPP))
        bindSwitch(R.id.chat_contacts, Settings.CHAT_CONTACTS)
        findViewById<Button>(R.id.notification_access).setOnClickListener { openNotificationAccess() }

        val netBox = findViewById<CheckBox>(R.id.net_on)
        netBox.isChecked = Settings.netOn(this)
        netBox.setOnCheckedChangeListener { _, on ->
            Settings.setSwitch(this, Settings.NET_ON, on)
            if (on) NetWorker.start(this) else NetWorker.stop(this)
            showNet()
        }
        NetWorker.start(this)
    }

    // While the screen is open, show new results as soon as they are saved.
    private val refresh = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == Settings.KEY_RECENT || key == Settings.KEY_PENDING) runOnUiThread { showRecent() }
        if (key == Settings.KEY_NET_LIST || key == Settings.KEY_DEV_LIST) runOnUiThread { showNet() }
    }

    override fun onResume() {
        super.onResume()
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(refresh)
        showRecent()
        showNet()
        showChatStatus()                     // notification access may have just been allowed
        FlushWorker.flushSoon(this)          // send messages that waited for the Pi, if it can be reached now
        handler.post(netLoop)
    }

    override fun onPause() {
        handler.removeCallbacks(netLoop)
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

    /** Asks the Pi for its certificate and shows the fingerprint, to compare with the Pi's own (update 39). */
    private fun pair() {
        save()
        val address = Settings.piUrl(this)
        if (!address.startsWith("https://")) {
            status.text = HTTPS_ONLY
            return
        }
        status.text = "Asking the Pi for its certificate..."
        Thread {
            val seen = try {
                Tls.seen(address)
            } catch (e: Exception) {
                runOnUiThread { status.text = "Cannot reach the Pi: ${e.message}" }
                null
            }
            if (seen != null) runOnUiThread { confirmPin(address, seen) }
        }.start()
    }

    private fun confirmPin(address: String, seen: String) {
        AlertDialog.Builder(this)
            .setTitle("Is this your Pi?")
            .setMessage(
                "The Pi at $address shows this certificate fingerprint:\n\n$seen\n\n" +
                    "On the Pi, run:  cat ~/.ps3_tls_fingerprint\n\n" +
                    "Tap Trust only if the two are the same. The app then talks to no other certificate."
            )
            .setPositiveButton("Trust") { _, _ ->
                Settings.setPin(this, seen)
                status.text = "Paired with the Pi."
                testConnection()
            }
            .setNegativeButton("Cancel") { _, _ ->
                status.text = "Not paired: the fingerprints must be the same."
            }
            .show()
    }

    private fun testConnection() {
        save()
        val address = Settings.piUrl(this)
        if (!address.startsWith("https://")) {
            status.text = HTTPS_ONLY
            return
        }
        if (Settings.pin(this).isBlank()) {
            status.text = "Tap 'Pair with the Pi' first: the app checks the Pi's certificate before it sends anything."
            return
        }
        status.text = "Connecting..."
        Thread {
            val message = try {
                val health = PiClient.of(this).health()
                "Connected over HTTPS to the paired Pi. Advisor: ${health.optString("backend")}."
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

    private fun clock(ms: Long): String = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ms))

    private fun showNet() {
        if (!Settings.netOn(this)) {
            netStatus.text = "Off: this phone does not ask the Pi for network alerts."
            devList.text = ""
            netAlerts.text = ""
            return
        }
        val checked = Settings.netCheckedAt(this)
        val failed = Settings.netFailedAt(this)
        netStatus.text = when {
            checked == 0L && failed == 0L -> "Not checked yet."
            failed > checked -> "Cannot reach the Pi" +
                (if (checked > 0L) " (last reached at ${clock(checked)})" else "") +
                ". Network alerts come while this phone is on the Pi's Wi-Fi, PS3-Guardian-Lab."
            else -> "Checked at ${clock(checked)}. New alerts come as notifications."
        }
        val devices = Settings.devList(this)
        devList.text = if (devices.isEmpty()) "No device seen yet." else devices.joinToString("\n\n")
        val lines = Settings.netList(this)
        netAlerts.text = if (lines.isEmpty()) "No network alerts." else lines.joinToString("\n\n")
    }

    companion object {
        private const val HTTPS_ONLY = "The app talks to the Pi only over HTTPS: use the address https://10.42.0.1:8443."
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
