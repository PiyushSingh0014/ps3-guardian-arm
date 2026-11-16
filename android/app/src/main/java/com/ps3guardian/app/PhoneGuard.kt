package com.ps3guardian.app

import android.content.Context
import com.ps3guardian.app.guard.Guard
import com.ps3guardian.app.guard.GuardFiles
import com.ps3guardian.app.guard.GuardResult

/**
 * Phone Guard (update 43): the Pi's checks for messages and links, run on this phone from the
 * app's assets (assets/guard/), so a verdict needs no network at all. Loaded once, on first use.
 */
object PhoneGuard {
    @Volatile
    private var guard: Guard? = null

    /** Why it could not be loaded, if it could not. */
    @Volatile
    var error: String? = null
        private set

    fun get(c: Context): Guard? {
        guard?.let { return it }
        synchronized(this) {
            guard?.let { return it }
            return try {
                val assets = c.applicationContext.assets
                Guard(GuardFiles { name -> assets.open("guard/$name").use { it.readBytes() } }).also {
                    guard = it
                    error = null
                }
            } catch (e: Exception) {
                error = e.message ?: e.javaClass.simpleName
                null
            }
        }
    }

    /** Loads it in the background, so that the first message does not wait for it. */
    fun warm(c: Context, then: (() -> Unit)? = null) {
        val app = c.applicationContext
        Thread {
            get(app)
            then?.invoke()
        }.start()
    }

    /** The phone's verdict on a message, or null if the guard could not be loaded. */
    fun check(c: Context, text: String, sender: String?): GuardResult? =
        try {
            get(c)?.check(text, sender)
        } catch (e: Exception) {
            error = e.message ?: e.javaClass.simpleName
            null
        }
}
