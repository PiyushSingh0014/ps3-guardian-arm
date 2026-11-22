package com.ps3guardian.app

import android.content.Context
import org.json.JSONArray

/**
 * The devices on the home Wi-Fi (GET /devices), riskiest first. Each has a risk level from its
 * network alerts of the last 24 hours: at risk (a dangerous one), check (a suspicious one) or OK.
 * Only for the Network page: fetched while the app is open, never in the background.
 */
object Devices {
    /** Asks the Hub once and keeps the list as it came. False if the Hub could not be reached. */
    fun check(c: Context): Boolean {
        val reply = try {
            PiClient.of(c).devices()
        } catch (e: Exception) {
            return false
        }
        val arr = reply.optJSONArray("devices") ?: JSONArray()
        Settings.saveDevList(c, (0 until arr.length()).mapNotNull { arr.optJSONObject(it) })
        return true
    }
}
