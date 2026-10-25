package com.example.ps3guardian

import android.Manifest
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

/** One screen: Pi address and token, permissions, two tests, and the last results. */
class MainActivity : AppCompatActivity() {

    private lateinit var url: EditText
    private lateinit var token: EditText
    private lateinit var status: TextView
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
        status = findViewById(R.id.status)
        recent = findViewById(R.id.recent)
        url.setText(Settings.piUrl(this))
        token.setText(Settings.token(this))
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
    }

    // While the screen is open, show new results as soon as they are saved.
    private val refresh = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == Settings.KEY_RECENT || key == Settings.KEY_PENDING) runOnUiThread { showRecent() }
    }

    override fun onResume() {
        super.onResume()
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(refresh)
        showRecent()
        FlushWorker.flushSoon(this)          // send SMS that waited for the Pi, if it can be reached now
    }

    override fun onPause() {
        Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(refresh)
        super.onPause()
    }

    private fun save() = Settings.save(this, url.text.toString(), token.text.toString())

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
