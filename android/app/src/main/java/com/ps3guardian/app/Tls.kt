package com.ps3guardian.app

import java.io.IOException
import java.net.URI
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * HTTPS to the Pi (update 39). The Pi makes its own certificate, so no certificate authority vouches
 * for it. The app trusts exactly one certificate instead: the one its owner confirmed when pairing,
 * by comparing its fingerprint with the one the Pi prints. Any other certificate is refused, even a
 * valid one for another website, so someone else on the Wi-Fi cannot pose as the Pi.
 */
object Tls {
    const val NOT_PINNED = "not the certificate this phone paired with"

    /** SHA-256 of the certificate (DER), as 16 groups of 4 hex digits: the same text the Pi prints. */
    fun fingerprint(cert: Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString("") { "%02X".format(it.toInt() and 0xff) }.chunked(4).joinToString(" ")

    /** Spaces and case do not matter; an empty pin matches nothing. */
    fun same(a: String, b: String): Boolean =
        a.isNotBlank() && a.replace(" ", "").equals(b.replace(" ", ""), ignoreCase = true)

    /** Trusts only the certificate whose fingerprint is [pin], and remembers the one it was shown. */
    class PinTrust(private val pin: String) : X509TrustManager {
        @Volatile
        var seen: String? = null

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw CertificateException("the Pi sent no certificate")
            val fp = fingerprint(leaf)
            seen = fp
            if (!same(fp, pin)) throw CertificateException(NOT_PINNED)
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("the app takes no connections")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    /** This connection trusts the pinned certificate and nothing else. */
    fun pin(conn: HttpsURLConnection, trust: PinTrust, pin: String) {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trust), null)
        conn.sslSocketFactory = ctx.socketFactory
        // The certificate cannot name every address the Pi may get; the pin is what identifies it.
        conn.hostnameVerifier = HostnameVerifier { _, session ->
            val leaf = session.peerCertificates.firstOrNull()
            leaf != null && same(fingerprint(leaf), pin)
        }
    }

    /** The fingerprint of the certificate the Pi at [baseUrl] shows, for its owner to compare when pairing. */
    fun seen(baseUrl: String): String {
        val conn = URI("$baseUrl/health").toURL().openConnection() as? HttpsURLConnection
            ?: throw IOException("the Pi address must start with https://")
        val trust = PinTrust("")
        pin(conn, trust, "")
        conn.connectTimeout = 3_000
        conn.readTimeout = 3_000
        try {
            conn.connect()                      // refused on purpose once the certificate is seen
        } catch (e: IOException) {
            if (trust.seen == null) throw e     // the Pi was not reached
        } finally {
            conn.disconnect()
        }
        return trust.seen ?: throw IOException("the Pi sent no certificate")
    }

    /** True if [e] came from a certificate that is not the paired one. */
    fun notPinned(e: Throwable): Boolean {
        var cause: Throwable? = e
        while (cause != null) {
            if (cause is CertificateException && cause.message == NOT_PINNED) return true
            cause = cause.cause
        }
        return false
    }
}
