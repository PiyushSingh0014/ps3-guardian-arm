package com.ps3guardian.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream
import java.io.InputStream

/**
 * "Check with Sajag": a file, or a message's text, shared from WhatsApp, Messages or the Files
 * app. A text is checked on this phone at once and then by the Home Hub; a file by the Home Hub
 * only. The result shows on the alert's own screen (AlertActivity), which fills in as the Hub's
 * verdict and Llama's explanation arrive. Android lets this app read only the one shared file,
 * and only now; the Hub checks it in memory and keeps no copy.
 */
class ShareActivity : AlertActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {                // turned: the same entry as before
            historyId = savedInstanceState.getString(KEY_ID)
            return
        }
        val uri = sharedUri(intent)
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)
        when {
            uri != null -> readFile(uri)
            !text.isNullOrBlank() -> historyId = Checker.shareText(this, text)
            else -> showWaiting("Nothing to check. Share a message or a file to Sajag.")
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_ID, historyId)
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

    /** Reads the file here, while Android allows it, then hands it to the Hub in the background. */
    private fun readFile(uri: Uri) {
        showWaiting("Reading the file…")
        Thread {
            val result: String? = try {
                val name = nameOf(uri)
                val data = contentResolver.openInputStream(uri)?.use { readUpTo(it, PiClient.MAX_FILE + 1) }
                when {
                    data == null -> "Could not read the file: the app it came from did not hand it over."
                    data.size > PiClient.MAX_FILE -> "Too big to check: your Home Hub checks files up to 25 MB."
                    else -> {
                        val id = Checker.shareFile(this, name, data)
                        runOnUiThread {
                            historyId = id
                            render()
                        }
                        null
                    }
                }
            } catch (e: Exception) {
                "Could not read the file: ${e.message}"
            }
            if (result != null) runOnUiThread { showWaiting(result) }
        }.start()
    }

    private companion object {
        const val KEY_ID = "history_id"
    }
}
