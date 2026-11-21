package com.ps3guardian.app

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/** Dialogs shared by the screens (app 3.0). */
object Dialogs {
    /** A dialog with one text box; ok gets what was typed. */
    fun input(a: AppCompatActivity, title: String, note: String?, hint: String, initial: String, inputType: Int,
              lines: Int, okLabel: String, ok: (String) -> Unit) {
        val v = a.layoutInflater.inflate(R.layout.dialog_input, null)
        val noteView = v.findViewById<TextView>(R.id.input_note)
        val box = v.findViewById<EditText>(R.id.input_text)
        if (note != null) {
            noteView.text = note
            noteView.visibility = View.VISIBLE
        }
        box.hint = hint
        box.inputType = inputType
        if (lines > 1) {
            box.minLines = lines
            box.maxLines = 10
        } else {
            box.maxLines = 1
        }
        box.setText(initial)
        AlertDialog.Builder(a)
            .setTitle(title)
            .setView(v)
            .setPositiveButton(okLabel) { _, _ -> ok(box.text.toString()) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    fun info(a: AppCompatActivity, title: String, message: String) {
        AlertDialog.Builder(a).setTitle(title).setMessage(message).setPositiveButton("OK", null).show()
    }
}

/** What the app is allowed to do. */
object Perms {
    private fun granted(c: Context, p: String) = ContextCompat.checkSelfPermission(c, p) == PackageManager.PERMISSION_GRANTED

    fun sms(c: Context) = granted(c, Manifest.permission.RECEIVE_SMS)

    fun notifications(c: Context) = Build.VERSION.SDK_INT < 33 || granted(c, Manifest.permission.POST_NOTIFICATIONS)

    /** SMS, and on Android 13+ notifications: asked together. */
    fun wanted(): Array<String> {
        val w = mutableListOf(Manifest.permission.RECEIVE_SMS)
        if (Build.VERSION.SDK_INT >= 33) w += Manifest.permission.POST_NOTIFICATIONS
        return w.toTypedArray()
    }

    /** Notification access, for chats from WhatsApp and Messages. */
    fun chats(c: Context) = NotificationManagerCompat.getEnabledListenerPackages(c).contains(c.packageName)

    /** Android's page where the owner allows the app to read notifications. */
    fun openNotificationAccess(a: Activity) {
        val list = Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        val intent = if (Build.VERSION.SDK_INT >= 30) {
            Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS).putExtra(
                android.provider.Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
                ComponentName(a, ChatListener::class.java).flattenToString()
            )
        } else {
            list
        }
        try {
            a.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            a.startActivity(list)
        }
    }
}

/** Pairing with the Home Hub's certificate (update 39), and the connection test. */
object Pairing {
    const val HTTPS_ONLY = "Sajag talks to the Home Hub only over HTTPS: use an address like https://10.42.0.1:8443."

    /** Asks the Hub for its certificate, then the owner to compare its fingerprint with the Hub's own. */
    fun start(a: AppCompatActivity, status: (String) -> Unit, done: (Boolean) -> Unit) {
        val address = Settings.piUrl(a)
        if (!address.startsWith("https://")) {
            status(HTTPS_ONLY)
            done(false)
            return
        }
        status("Asking your Home Hub for its certificate…")
        Thread {
            val seen = try {
                Tls.seen(address)
            } catch (e: Exception) {
                a.runOnUiThread {
                    status("Can't reach your Home Hub: ${e.message}. Is this phone on your home Wi-Fi?")
                    done(false)
                }
                null
            }
            if (seen != null) a.runOnUiThread { confirm(a, address, seen, status, done) }
        }.start()
    }

    private fun confirm(a: AppCompatActivity, address: String, seen: String, status: (String) -> Unit, done: (Boolean) -> Unit) {
        AlertDialog.Builder(a)
            .setTitle("Is this your Home Hub?")
            .setMessage(
                "Your Home Hub at $address shows this certificate fingerprint:\n\n$seen\n\n" +
                    "On the Home Hub, run:  cat ~/.ps3_tls_fingerprint\n\n" +
                    "Tap Trust only if the two are the same. Sajag then talks to no other certificate."
            )
            .setPositiveButton("Trust") { _, _ ->
                Settings.setPin(a, seen)
                test(a, status, done)
            }
            .setNegativeButton("Cancel") { _, _ ->
                status("Not paired: the two fingerprints must be the same.")
                done(false)
            }
            .show()
    }

    /** Asks the paired Hub for /health. */
    fun test(a: Activity, status: (String) -> Unit, done: (Boolean) -> Unit) {
        if (!Settings.piUrl(a).startsWith("https://")) {
            status(HTTPS_ONLY)
            done(false)
            return
        }
        if (Settings.pin(a).isBlank()) {
            status("Pair with your Home Hub first: Sajag checks its certificate before it sends anything.")
            done(false)
            return
        }
        status("Connecting…")
        val app = a.applicationContext
        Thread {
            var ok = false
            val message = try {
                val health = PiClient.of(app).health()
                ok = true
                "Connected to your Home Hub over HTTPS. Explanations by: ${health.optString("backend")}."
            } catch (e: Exception) {
                "Can't reach your Home Hub: ${e.message}"
            }
            a.runOnUiThread {
                status(message)
                done(ok)
            }
        }.start()
    }
}

/** Copying Llama from the Home Hub (update 44), after asking: it is about 1 GB. */
object LlamaCopy {
    fun ask(a: AppCompatActivity, started: () -> Unit) {
        if (PhoneLlama.copying) {
            started()
            return
        }
        if (!Settings.piUrl(a).startsWith("https://") || Settings.pin(a).isBlank()) {
            Dialogs.info(a, "Pair first", "Pair with your Home Hub first, on your home Wi-Fi: the model comes from your paired Home Hub only.")
            return
        }
        AlertDialog.Builder(a)
            .setTitle("Copy Llama from your Home Hub?")
            .setMessage(
                "Llama 3.2 1B (about 1 GB) is copied from your Home Hub to this phone, over your home Wi-Fi, in a few " +
                    "minutes. Keep this screen open until it is done.\n\nThen, when your Home Hub can't be reached, " +
                    "Llama explains alerts on this phone. If the copy stops, tap again: it goes on from where it stopped."
            )
            .setPositiveButton("Copy") { _, _ ->
                PhoneLlama.startCopy(a)
                started()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** "40%" while copying, else null. */
    fun percent(): Int? {
        if (!PhoneLlama.copying) return null
        val total = PhoneLlama.toCopy
        return if (total <= 0L) 0 else (PhoneLlama.copied * 100 / total).toInt().coerceIn(0, 100)
    }
}
