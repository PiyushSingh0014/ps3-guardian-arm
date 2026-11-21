package com.ps3guardian.app

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

/**
 * Set-up (app 3.0), three steps: 1 allow SMS, alerts and, if wanted, chats; 2 pair with the Home
 * Hub (address, pairing code, phone name, then its certificate's fingerprint); 3 copy Llama for
 * offline explanations. Each step can be skipped; Settings opens any step again.
 */
class SetupActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_STEP = "step"
    }

    private val handler = Handler(Looper.getMainLooper())
    private var step = 1
    private lateinit var address: EditText
    private lateinit var token: EditText
    private lateinit var device: EditText

    private val askPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { refresh() }

    private val copyLoop = object : Runnable {
        override fun run() {
            refresh()
            if (PhoneLlama.copying) handler.postDelayed(this, 1_000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        Ui.edgeToEdge(this, findViewById(R.id.setup_root), findViewById(R.id.setup_status_space), findViewById(R.id.setup_buttons))
        address = findViewById(R.id.setup_address)
        token = findViewById(R.id.setup_token)
        device = findViewById(R.id.setup_device)
        address.setText(Settings.piUrl(this))
        token.setText(Settings.token(this))
        device.setText(Settings.device(this))

        findViewById<View>(R.id.setup_perm_btn).setOnClickListener { askPermissions.launch(Perms.wanted()) }
        findViewById<View>(R.id.setup_chat_btn).setOnClickListener { Perms.openNotificationAccess(this) }
        findViewById<View>(R.id.setup_pair).setOnClickListener {
            saveFields()
            Pairing.start(this, { hubStatus(it) }) { refresh() }
        }
        findViewById<View>(R.id.setup_secondary).setOnClickListener {
            when (step) {
                1, 2 -> show(step + 1)
                else -> finishSetup()
            }
        }
        findViewById<View>(R.id.setup_primary).setOnClickListener {
            when {
                step < 3 -> show(step + 1)
                PhoneLlama.ready(this) || Settings.pin(this).isBlank() -> finishSetup()
                PhoneLlama.copying -> {}
                else -> LlamaCopy.ask(this) { handler.post(copyLoop) }
            }
        }
        show(savedInstanceState?.getInt(EXTRA_STEP) ?: intent.getIntExtra(EXTRA_STEP, 1))
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(EXTRA_STEP, step)
    }

    override fun onResume() {
        super.onResume()
        refresh()                                  // notification access may have just been allowed
        if (PhoneLlama.copying) handler.post(copyLoop)
    }

    override fun onPause() {
        handler.removeCallbacks(copyLoop)
        saveFields()
        super.onPause()
    }

    private fun saveFields() {
        Settings.saveUrl(this, address.text.toString())
        if (token.text.toString().isNotBlank()) Settings.saveToken(this, token.text.toString())
        Settings.saveDevice(this, device.text.toString())
    }

    private fun hubStatus(text: String) {
        val t = findViewById<TextView>(R.id.setup_hub_status)
        t.text = text
        t.visibility = View.VISIBLE
    }

    private fun finishSetup() {
        saveFields()
        Settings.setSetupDone(this)
        if (isTaskRoot) startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun show(n: Int) {
        step = n.coerceIn(1, 3)
        findViewById<View>(R.id.step_checks).visibility = if (step == 1) View.VISIBLE else View.GONE
        findViewById<View>(R.id.step_hub).visibility = if (step == 2) View.VISIBLE else View.GONE
        findViewById<View>(R.id.step_llama).visibility = if (step == 3) View.VISIBLE else View.GONE
        findViewById<TextView>(R.id.setup_step_label).text = "STEP $step OF 3"
        listOf(R.id.setup_seg1, R.id.setup_seg2, R.id.setup_seg3).forEachIndexed { i, id ->
            findViewById<View>(id).setBackgroundResource(if (i < step) R.drawable.bg_step_on else R.drawable.bg_step_off)
        }
        refresh()
    }

    private fun refresh() {
        val allowed = Perms.sms(this) && Perms.notifications(this)
        findViewById<TextView>(R.id.setup_perm_sub).text =
            if (allowed) "Allowed" else "Needed to check SMS and to warn you"
        val permBtn = findViewById<TextView>(R.id.setup_perm_btn)
        permBtn.text = if (allowed) "Allowed" else "Allow"
        permBtn.setBackgroundResource(if (allowed) R.drawable.bg_button_tonal else R.drawable.bg_button_primary)
        permBtn.setTextColor(getColor(if (allowed) R.color.safe else R.color.ink))
        val chats = Perms.chats(this)
        findViewById<TextView>(R.id.setup_chat_sub).text =
            if (chats) "Allowed" else "Optional: lets Sajag check chats from numbers you don't know"
        val chatBtn = findViewById<TextView>(R.id.setup_chat_btn)
        chatBtn.text = if (chats) "Allowed" else "Allow"
        chatBtn.setTextColor(getColor(if (chats) R.color.safe else R.color.ivory))

        val paired = Settings.pin(this).isNotBlank()
        findViewById<TextView>(R.id.setup_pair).text = if (paired) "Paired · pair again" else "Pair with this Home Hub"

        // Step 3: the copy.
        val ready = PhoneLlama.ready(this)
        val pct = LlamaCopy.percent()
        val copying = pct != null
        if (copying) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        findViewById<TextView>(R.id.setup_copy_title).text = when {
            ready -> "Ready on this phone"
            copying -> "Copying from your Home Hub"
            paired -> "Not copied yet"
            else -> "Pair your Home Hub first"
        }
        findViewById<TextView>(R.id.setup_copy_pct).text = when {
            ready -> "100%"
            copying -> "$pct%"
            else -> ""
        }
        findViewById<ProgressBar>(R.id.setup_copy_bar).progress = if (ready) 100 else pct ?: 0
        findViewById<TextView>(R.id.setup_copy_note).text = when {
            copying -> "About 1 GB. Keep this screen open on your home Wi-Fi."
            ready -> PhoneLlama.copyResult ?: "Checked against your Home Hub's copy."
            !paired -> "The model comes only from your paired Home Hub (step 2)."
            else -> PhoneLlama.copyResult ?: "About 1 GB, copied once over your home Wi-Fi."
        }

        val primary = findViewById<TextView>(R.id.setup_primary)
        val secondary = findViewById<TextView>(R.id.setup_secondary)
        when (step) {
            1, 2 -> {
                primary.text = "Next"
                secondary.text = "Skip for now"
            }
            else -> {
                primary.text = when {
                    ready || !paired -> "Done"
                    copying -> "Copying…"
                    else -> "Copy now"
                }
                secondary.text = "Later"
            }
        }
    }
}
