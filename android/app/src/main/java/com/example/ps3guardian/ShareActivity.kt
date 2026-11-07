package com.example.ps3guardian

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.Locale
import java.util.concurrent.Executors

/**
 * "Share to PS3 Guardian": a file, or a message's text, shared from WhatsApp, Messages or the
 * Files app is checked on the Pi, and the answer is shown here. Android lets this app read only
 * the one shared file, and only now; the Pi checks it in memory and keeps no copy.
 */
class ShareActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var head: TextView
    private lateinit var body: TextView
    private lateinit var llm: TextView
    @Volatile private var open = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        head = TextView(this)
        head.textSize = 20f
        head.setPadding(0, 0, 0, pad / 2)
        body = TextView(this)
        body.textSize = 16f
        llm = TextView(this)
        llm.textSize = 15f
        llm.setPadding(0, pad, 0, pad)
        val close = Button(this)
        close.text = "Close"
        close.setOnClickListener { finish() }
        val column = LinearLayout(this)
        column.orientation = LinearLayout.VERTICAL
        column.setPadding(pad, pad, pad, pad)
        column.addView(head)
        column.addView(body)
        column.addView(llm)
        column.addView(close)
        val scroll = ScrollView(this)
        scroll.addView(column)
        setContentView(scroll)

        head.text = "Checking on the Pi..."
        val uri = sharedUri(intent)
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)
        when {
            uri != null -> worker.execute { checkFile(uri) }
            !text.isNullOrBlank() -> worker.execute { checkText(text) }
            else -> head.text = "Nothing to check. Share a file or a message to PS3 Guardian."
        }
    }

    override fun onDestroy() {
        open = false
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun sharedUri(i: Intent): Uri? {
        if (i.action != Intent.ACTION_SEND) return null
        return if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        else @Suppress("DEPRECATION") i.getParcelableExtra(Intent.EXTRA_STREAM)
    }

    /** The file's name as the sharing app gives it ("Wedding_Invitation.apk"): its ending matters. */
    private fun nameOf(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (i >= 0) return c.getString(i) ?: ""
            }
        }
        return uri.lastPathSegment ?: ""
    }

    private fun readUpTo(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (out.size() < limit) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun checkFile(uri: Uri) {
        try {
            val name = nameOf(uri)
            val data = contentResolver.openInputStream(uri)?.use { readUpTo(it, PiClient.MAX_FILE + 1) }
            if (data == null) return show("Could not read the file", "The app it came from did not hand it over.")
            if (data.size > PiClient.MAX_FILE) return show("Too big to check", "The Pi checks files up to 25 MB.")
            val client = PiClient(Settings.piUrl(this), Settings.token(this))
            answer(client.checkFile(name, data), client)
        } catch (e: PiClient.Rejected) {
            show("Not checked", e.message ?: "")
        } catch (e: InterruptedException) {
            // the screen was closed
        } catch (e: Exception) {
            show("Could not reach the Pi", "Is this phone on the Pi's Wi-Fi, with the Pi address set in the app? "
                + (e.message ?: ""))
        }
    }

    private fun checkText(text: String) {
        try {
            val client = PiClient(Settings.piUrl(this), Settings.token(this))
            answer(client.checkText(text.take(PiClient.MAX_MESSAGE), "en"), client)
        } catch (e: PiClient.Rejected) {
            show("Not checked", e.message ?: "")
        } catch (e: InterruptedException) {
            // the screen was closed
        } catch (e: Exception) {
            show("Could not reach the Pi", e.message ?: "")
        }
    }

    /** The Pi's answer now, then Llama's explanation when it is ready (20-30 s). */
    private fun answer(res: JSONObject, client: PiClient) {
        val finding = res.getJSONObject("finding")
        val advice = res.getJSONObject("advice")
        val title = advice.optString("headline").ifBlank { finding.optString("verdict").uppercase(Locale.US) }
        show(title, Notifier.adviceText(advice))
        val explain = res.optJSONObject("explain") ?: return
        val id = explain.optString("id")
        if (id.isBlank()) return
        ui { llm.text = "Llama is writing a plain-language explanation on the Pi..." }
        repeat(60) {                                         // at most 2 minutes
            if (!open) return
            Thread.sleep(2_000)
            val reply = client.explain(id)
            when (reply.optString("status")) {
                "pending" -> {}
                "done" -> {
                    val a = reply.optJSONObject("advice") ?: return
                    show(title, Notifier.adviceText(a))
                    ui { llm.text = "Explained by Llama 3.2 on the Pi." }
                    return
                }
                else -> {                                    // fallback or failed: the first advice stays
                    ui { llm.text = "" }
                    return
                }
            }
        }
    }

    private fun show(title: String, text: String) = ui {
        head.text = title
        body.text = text
    }

    private fun ui(f: () -> Unit) {
        if (open) runOnUiThread { if (open) f() }
    }
}
