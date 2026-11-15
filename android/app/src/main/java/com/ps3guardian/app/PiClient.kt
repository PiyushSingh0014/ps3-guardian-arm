package com.ps3guardian.app

import android.content.Context
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * The calls the app makes to the Pi (app/server.py). Blocking: use a background thread.
 * Over https:// (the Pi's port 8443) the connection trusts only the certificate this phone paired
 * with ([pin], see Tls.kt), and the pairing token is sent only over such a connection.
 */
class PiClient(private val baseUrl: String, private val token: String, private val pin: String = "") {

    /** The Pi refused the request itself (bad or too long a message), not the connection or the token. */
    class Rejected(message: String) : IOException(message)

    fun health(): JSONObject = request("GET", "/health", null)

    /** channel "sms", or "chat" with the app it came from; device is this phone's name for the log. */
    fun checkSms(
        message: String, sender: String, language: String, test: Boolean = false,
        channel: String = "sms", app: String? = null, device: String = "", study: Boolean = false
    ): JSONObject {
        val body = JSONObject()
            .put("message", message)
            .put("language", language)
            .put("test", test)
            .put("channel", channel)
            .put("study", study)                 // the "Share message texts with the study" switch
        if (sender.isNotBlank()) body.put("sender", sender)
        if (app != null) body.put("app", app)
        if (device.isNotBlank()) body.put("device", device.take(32))
        return request("POST", "/sms", body)
    }

    fun explain(jobId: String): JSONObject = request("GET", "/explain/$jobId", null)

    /** A file shared to the app, as the raw body (POST /file). The Pi checks it in memory and keeps no copy. */
    fun checkFile(name: String, data: ByteArray, language: String = "en"): JSONObject {
        val path = "/file?channel=share&language=$language&name=" + URLEncoder.encode(name.take(200), "UTF-8")
        return request("POST", path, null, raw = data, readMs = 60_000)
    }

    /** A message's text shared to the app: checked like on the Pi's page (POST /check), not logged. */
    fun checkText(message: String, language: String): JSONObject =
        request("POST", "/check", JSONObject().put("message", message).put("language", language))

    /** The newest network alerts from the Pi's lab Wi-Fi, newest first: the list the Pi's page shows. */
    fun alerts(limit: Int): JSONObject = request("GET", "/alerts?limit=$limit", null)

    /** The devices on the Pi's lab Wi-Fi with a risk level each, riskiest first. */
    fun devices(): JSONObject = request("GET", "/devices", null)

    private fun request(method: String, path: String, body: JSONObject?, raw: ByteArray? = null,
                        readMs: Int = 6_000): JSONObject {
        val conn = URI(baseUrl + path).toURL().openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) Tls.pin(conn, Tls.PinTrust(pin), pin)
        try {
            conn.requestMethod = method
            // Android gives an SMS receiver about 10 s; the Pi answers in well under 1 s.
            conn.connectTimeout = 3_000
            conn.readTimeout = readMs
            if (token.isNotEmpty()) conn.setRequestProperty("X-Guardian-Token", token)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            } else if (raw != null) {
                conn.doOutput = true
                conn.setFixedLengthStreamingMode(raw.size)
                conn.setRequestProperty("Content-Type", "application/octet-stream")
                conn.outputStream.use { it.write(raw) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code in REFUSED) throw Rejected("HTTP $code ${text.take(120)}")
            if (code !in 200..299) throw IOException("HTTP $code ${text.take(120)}")
            return JSONObject(text)
        } catch (e: SSLException) {
            // Still an IOException: a message waits on the phone until the Pi can be reached.
            if (!Tls.notPinned(e)) throw e
            throw IOException(if (pin.isBlank()) "not paired with the Pi yet: tap 'Pair with the Pi'"
                              else "the Pi's certificate is not the one this phone paired with: tap 'Pair with the Pi'")
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        /** A client with this phone's settings: the Pi address, the pairing token and the pinned certificate. */
        fun of(c: Context) = PiClient(Settings.piUrl(c), Settings.token(c), Settings.pin(c))

        const val MAX_MESSAGE = 2000        // the Pi accepts up to 2000 characters
        const val MAX_FILE = 25 * 1024 * 1024   // and files up to 25 MB
        // Bad request, too large, invalid fields. A wrong token (401) or a stopped app is
        // worth trying again later, so those stay ordinary IOExceptions.
        private val REFUSED = setOf(400, 413, 422)
    }
}
