package com.ps3guardian.app

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

/**
 * Sajag (app 3.0): Home, Alerts, Network and Settings, switched by the bar at the bottom. Each page
 * is its own class; this screen keeps them fresh: when a result is saved, every 10 s for the
 * Home Hub's network alerts while it is open, and every second while Llama is being copied.
 */
class MainActivity : AppCompatActivity() {
    companion object {
        const val TAB_HOME = 0
        const val TAB_ALERTS = 1
        const val TAB_NETWORK = 2
        const val TAB_SETTINGS = 3
        const val EXTRA_TAB = "tab"
        private const val KEY_TAB = "tab"
    }

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var home: HomePage
    private lateinit var alerts: AlertsPage
    private lateinit var network: NetworkPage
    private lateinit var settings: SettingsPage
    private lateinit var pages: List<View>
    private var tab = TAB_HOME
    private var ticks = 0

    val askPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { refreshAll() }

    // While Llama is being copied from the Home Hub, show how far it got every second.
    private val llamaLoop = object : Runnable {
        override fun run() {
            val copying = PhoneLlama.copying
            if (copying) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            home.refresh()
            settings.refresh()
            if (copying) handler.postDelayed(this, 1_000L)
        }
    }

    // While the app is open: the Hub's network alerts and devices every 10 s, or, with network
    // alerts off, a look at whether the Hub can be reached every 30 s.
    private val netLoop = object : Runnable {
        override fun run() {
            val app = applicationContext
            val net = Settings.netOn(app)
            val ping = !net && ticks % 3 == 0 && Settings.pin(app).isNotBlank()
            ticks++
            if (net || ping) {
                Thread {
                    if (net) {
                        if (NetAlerts.check(app)) Devices.check(app)
                    } else {
                        try {
                            PiClient.of(app).health()
                        } catch (e: Exception) {
                            // recorded by PiClient: the Home page shows "Away"
                        }
                    }
                }.start()
            }
            handler.postDelayed(this, 10_000L)
        }
    }

    // While the screen is open, show new results as soon as they are saved.
    private val refresh = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        runOnUiThread {
            when (key) {
                History.KEY -> {
                    home.refresh()
                    alerts.refresh()
                    updateBadge()
                }
                Settings.KEY_PENDING -> home.refresh()
                Settings.KEY_NET_LIST, Settings.KEY_DEV_LIST -> network.refresh()
                Settings.KEY_HUB -> {
                    home.refresh()
                    network.refresh()
                    settings.refresh()
                }
                Settings.KEY_RECENT -> {}
                else -> settings.refresh()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Ui.edgeToEdge(this, findViewById(R.id.root), findViewById(R.id.status_space), findViewById(R.id.nav))
        Notifier.ensureChannel(this)
        home = HomePage(this, findViewById(R.id.page_home))
        alerts = AlertsPage(this, findViewById(R.id.page_alerts))
        network = NetworkPage(this, findViewById(R.id.page_network))
        settings = SettingsPage(this, findViewById(R.id.page_settings))
        pages = listOf(R.id.page_home, R.id.page_alerts, R.id.page_network, R.id.page_settings).map { findViewById<View>(it) }
        listOf(R.id.tab_home, R.id.tab_alerts, R.id.tab_network, R.id.tab_settings).forEachIndexed { i, id ->
            findViewById<View>(id).setOnClickListener { select(i) }
        }
        PhoneGuard.warm(this) { runOnUiThread { home.refresh() } }
        NetWorker.start(this)
        select(savedInstanceState?.getInt(KEY_TAB) ?: intent.getIntExtra(EXTRA_TAB, TAB_HOME))
        if (savedInstanceState == null && !Settings.setupDone(this)) startActivity(Intent(this, SetupActivity::class.java))
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_TAB, tab)
    }

    override fun onResume() {
        super.onResume()
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(refresh)
        refreshAll()
        FlushWorker.flushSoon(this)          // send messages that waited for the Hub, if it can be reached now
        handler.post(netLoop)
        handler.post(llamaLoop)
    }

    override fun onPause() {
        handler.removeCallbacks(netLoop)
        handler.removeCallbacks(llamaLoop)
        Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(refresh)
        super.onPause()
    }

    /** Shows the copy's progress every second until it ends (Llama was just asked for). */
    fun watchLlama() {
        handler.removeCallbacks(llamaLoop)
        handler.post(llamaLoop)
    }

    fun refreshAll() {
        home.refresh()
        alerts.refresh()
        network.refresh()
        settings.refresh()
        updateBadge()
    }

    /** Shows one of the four pages and marks its tab. */
    fun select(i: Int) {
        tab = i.coerceIn(TAB_HOME, TAB_SETTINGS)
        pages.forEachIndexed { n, p -> p.visibility = if (n == tab) View.VISIBLE else View.GONE }
        val on = getColor(R.color.ivory)
        val off = getColor(R.color.text_3)
        val parts = listOf(
            Triple(R.id.tab_home_pill, R.id.tab_home_icon, R.id.tab_home_label),
            Triple(R.id.tab_alerts_pill, R.id.tab_alerts_icon, R.id.tab_alerts_label),
            Triple(R.id.tab_network_pill, R.id.tab_network_icon, R.id.tab_network_label),
            Triple(R.id.tab_settings_pill, R.id.tab_settings_icon, R.id.tab_settings_label),
        )
        parts.forEachIndexed { n, (pill, icon, label) ->
            val selected = n == tab
            findViewById<View>(pill).setBackgroundResource(if (selected) R.drawable.bg_nav_pill else 0)
            Ui.tint(findViewById<ImageView>(icon), if (selected) on else off)
            val text = findViewById<TextView>(label)
            text.setTextColor(if (selected) on else off)
            text.typeface = resources.getFont(if (selected) R.font.figtree_bold else R.font.figtree_semibold)
        }
        if (tab == TAB_ALERTS) Settings.setAlertsSeen(this)
        updateBadge()
    }

    /** The number on the Alerts tab: flagged messages since the Alerts page was last opened. */
    private fun updateBadge() {
        val seen = Settings.alertsSeen(this)
        val n = History.entries(this).count { it.flagged && it.time > seen }
        val badge = findViewById<TextView>(R.id.tab_alerts_badge)
        badge.text = if (n > 9) "9+" else n.toString()
        badge.visibility = if (n > 0 && tab != TAB_ALERTS) View.VISIBLE else View.GONE
    }

    fun openAlert(id: String) =
        startActivity(Intent(this, AlertActivity::class.java).putExtra(AlertActivity.EXTRA_ID, id))

    fun openNetAlert(id: String) =
        startActivity(Intent(this, AlertActivity::class.java).putExtra(AlertActivity.EXTRA_NET, id))

    /** "Check a message" and "Check a link": pasted here, then checked like a shared message. */
    fun checkDialog(link: Boolean) {
        val type = if (link) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        Dialogs.input(
            this, if (link) "Check a link" else "Check a message",
            if (link) "Paste the link. Sajag checks it on this phone and, at home, on your Home Hub. It is never opened."
            else "Paste the message. Sajag checks it on this phone and, at home, on your Home Hub.",
            if (link) "https://…" else "Paste the message here", "", type, if (link) 1 else 4, "Check"
        ) { text ->
            if (text.isNotBlank()) openAlert(Checker.shareText(this, text.trim()))
        }
    }
}
