package com.ps3guardian.companion

import android.Manifest
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

    override fun onResume() {
        super.onResume()
        showRecent()
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
            Checker.check(
                applicationContext, "9812345678",
                "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/update",
                test = true
            )
            runOnUiThread {
                status.text = "Test done: see the alert and the list below."
                showRecent()
            }
        }.start()
    }

    private fun showRecent() {
        val lines = Settings.recent(this)
        recent.text = if (lines.isEmpty()) "No messages checked yet." else lines.joinToString("\n\n")
    }
}
