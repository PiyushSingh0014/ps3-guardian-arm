package com.ps3guardian.app

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
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
class PiClient(private val baseUrl: String, private val token: String, private val pin: String = "",
               private val ctx: Context? = null) {

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

    /** The Llama files the Pi gives a paired phone (GET /llama): names, sizes and SHA-256. The Pi
     *  works out a 1 GB file's SHA-256 the first time it is asked, so this may take a while. */
    fun llamaFiles(): JSONObject = request("GET", "/llama", null, readMs = 120_000)

    /**
     * Copies one of the Pi's Llama files into [part], going on from where an earlier copy stopped
     * if the Pi can (HTTP 206), else from the start. progress gets the bytes in [part] so far.
     */
    fun download(path: String, part: File, expected: Long, progress: (Long) -> Unit) {
        var have = part.length()
        val conn = open("GET", path, 30_000)
        try {
            if (have > 0) conn.setRequestProperty("Range", "bytes=$have-")
            val code = conn.responseCode
            val resumed = code == 206 && (conn.getHeaderField("Content-Range") ?: "").startsWith("bytes $have-")
            if (code != 200 && !resumed) throw IOException("HTTP $code from the Pi")
            if (!resumed) have = 0L
            FileOutputStream(part, resumed).use { out ->
                conn.inputStream.use { input ->
                    val buf = ByteArray(256 * 1024)
                    var shown = have
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        have += n
                        if (have - shown >= 4_000_000) {
                            progress(have)
                            shown = have
                        }
                    }
                }
            }
            progress(have)
            if (have != expected) throw IOException("the copy stopped at ${have / 1_000_000} of ${expected / 1_000_000} MB")
        } catch (e: SSLException) {
            throw pinError(e)
        } finally {
            conn.disconnect()
        }
    }

    /** A connection to the Pi that trusts only the paired certificate, with the pairing token. */
    private fun open(method: String, path: String, readMs: Int): HttpURLConnection {
        val conn = URI(baseUrl + path).toURL().openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) Tls.pin(conn, Tls.PinTrust(pin), pin)
        conn.requestMethod = method
        // Android gives an SMS receiver about 10 s; the Pi answers in well under 1 s.
        conn.connectTimeout = 3_000
        conn.readTimeout = readMs
        if (token.isNotEmpty()) conn.setRequestProperty("X-Guardian-Token", token)
        return conn
    }

    /** Still an IOException: a message waits on the phone until the Pi can be reached. */
    private fun pinError(e: SSLException): IOException {
        if (!Tls.notPinned(e)) return e
        return IOException(if (pin.isBlank()) "not paired with the Home Hub yet: Settings, Pair again"
                           else "the Home Hub's certificate is not the one this phone paired with: Settings, Pair again")
    }

    private fun request(method: String, path: String, body: JSONObject?, raw: ByteArray? = null,
                        readMs: Int = 6_000): JSONObject {
        val conn = open(method, path, readMs)
        var reached = false
        try {
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
            reached = true
            if (code == 401) mark("refused", "the Home Hub did not accept the pairing code") else mark("ok")
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code in REFUSED) throw Rejected("HTTP $code ${text.take(120)}")
            if (code !in 200..299) throw IOException("HTTP $code ${text.take(120)}")
            return JSONObject(text)
        } catch (e: SSLException) {
            val err = pinError(e)
            mark("away", err.message ?: "")
            throw err
        } catch (e: IOException) {
            if (!reached) mark("away", e.message ?: "")
            throw e
        } finally {
            conn.disconnect()
        }
    }

    /** Whether the Home Hub answered, for the Home and Settings screens (app 3.0). */
    private fun mark(state: String, error: String = "") {
        val c = ctx ?: return
        Settings.hubSeen(c, state, error)
    }

    companion object {
        /** A client with this phone's settings: the Pi address, the pairing token and the pinned certificate. */
        fun of(c: Context) = PiClient(Settings.piUrl(c), Settings.token(c), Settings.pin(c), c.applicationContext)

        const val MAX_MESSAGE = 2000        // the Pi accepts up to 2000 characters
        const val MAX_FILE = 25 * 1024 * 1024   // and files up to 25 MB
        // Bad request, too large, invalid fields. A wrong token (401) or a stopped app is
        // worth trying again later, so those stay ordinary IOExceptions.
        private val REFUSED = setOf(400, 413, 422)
    }
}
