package com.example.ps3guardian

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI

/** The three calls the app makes to the Pi (app/server.py). Blocking: use a background thread. */
class PiClient(private val baseUrl: String, private val token: String) {

    /** The Pi refused the request itself (bad or too long a message), not the connection or the token. */
    class Rejected(message: String) : IOException(message)

    fun health(): JSONObject = request("GET", "/health", null)

    /** channel "sms", or "chat" with the app it came from; device is this phone's name for the log. */
    fun checkSms(
        message: String, sender: String, language: String, test: Boolean = false,
        channel: String = "sms", app: String? = null, device: String = ""
    ): JSONObject {
        val body = JSONObject()
            .put("message", message)
            .put("language", language)
            .put("test", test)
            .put("channel", channel)
        if (sender.isNotBlank()) body.put("sender", sender)
        if (app != null) body.put("app", app)
        if (device.isNotBlank()) body.put("device", device.take(32))
        return request("POST", "/sms", body)
    }

    fun explain(jobId: String): JSONObject = request("GET", "/explain/$jobId", null)

    private fun request(method: String, path: String, body: JSONObject?): JSONObject {
        val conn = URI(baseUrl + path).toURL().openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            // Android gives an SMS receiver about 10 s; the Pi answers in well under 1 s.
            conn.connectTimeout = 3_000
            conn.readTimeout = 6_000
            if (token.isNotEmpty()) conn.setRequestProperty("X-Guardian-Token", token)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code in REFUSED) throw Rejected("HTTP $code ${text.take(120)}")
            if (code !in 200..299) throw IOException("HTTP $code ${text.take(120)}")
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        const val MAX_MESSAGE = 2000        // the Pi accepts up to 2000 characters
        // Bad request, too large, invalid fields. A wrong token (401) or a stopped app is
        // worth trying again later, so those stay ordinary IOExceptions.
        private val REFUSED = setOf(400, 413, 422)
    }
}
