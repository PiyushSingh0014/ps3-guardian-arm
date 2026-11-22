package com.ps3guardian.app

import android.content.Context
import android.os.SystemClock
import com.ps3guardian.app.guard.LlamaPrompt
import org.json.JSONObject
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmModule
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Llama 3.2 1B on this phone (update 44): the Pi's own model, copied from the Pi once ("Get Llama
 * from the Pi", GET /llama), run by ExecuTorch 1.5.1's LLM runner, the runtime the Pi's model was
 * exported for. Phone Guard asks it for an alert's explanation only when the Pi cannot be reached;
 * the prompt and the checks on its answer are the Pi's (guard/Llama.kt), so a sentence that says
 * more than the evidence never reaches the user. The model is never in the app or the repo.
 */
object PhoneLlama {
    const val PTE = "llama3_2.pte"
    const val TOKENIZER = "tokenizer.model"
    private val NAMES = listOf(PTE, TOKENIZER)
    private const val OK_FILE = "ok.json"        // each file's size and SHA-256, written once they were checked
    private const val SEQ_LEN = 2048             // the export's context; the answer itself stops at maxNewTokens
    private const val IDLE_MS = 3 * 60 * 1000L   // the model leaves memory after 3 minutes without an alert

    fun dir(c: Context) = File(c.applicationContext.filesDir, "llama")

    private fun readOk(c: Context): JSONObject =
        try {
            JSONObject(File(dir(c), OK_FILE).readText())
        } catch (e: Exception) {
            JSONObject()
        }

    private fun writeOk(c: Context, ok: JSONObject) {
        val tmp = File(dir(c), "$OK_FILE.tmp")
        tmp.writeText(ok.toString())
        if (!tmp.renameTo(File(dir(c), OK_FILE))) throw IOException("could not save $OK_FILE")
    }

    /** Both files are here, each as big as when its SHA-256 was checked against the Pi's. */
    fun ready(c: Context): Boolean {
        val ok = readOk(c)
        return NAMES.all { name ->
            val f = File(dir(c), name)
            val want = ok.optJSONObject(name)
            want != null && f.isFile && f.length() == want.optLong("bytes", -1)
        }
    }

    fun megabytes(bytes: Long) = "%,d MB".format(Locale.US, bytes / 1_000_000)

    fun size(c: Context): Long = NAMES.sumOf { File(dir(c), it).length() }

    // --- running Llama -----------------------------------------------------------------------

    /**
     * Llama's raw answer, how long it took (with loading the model, if it was loaded for it), how many
     * pieces of text it wrote, and the runner's own numbers (JSON: tokens read and written, times).
     */
    class Answer(val text: String, val seconds: Double, val pieces: Int, val loadSeconds: Double, val stats: String?)

    /** "9.3 s, 2.8 s of it loading the model; read 712 tokens in 3.1 s, wrote 61 in 3.2 s", for the list. */
    fun describe(a: Answer): String {
        val sb = StringBuilder("%.1f s".format(Locale.US, a.seconds))
        if (a.loadSeconds > 0) sb.append(", %.1f s of it loading the model".format(Locale.US, a.loadSeconds))
        try {
            val s = JSONObject(a.stats ?: return sb.toString())
            val start = s.getLong("inference_start_ms")
            val read = s.getLong("prompt_eval_end_ms")
            val end = s.getLong("inference_end_ms")
            sb.append("; read ${s.getLong("prompt_tokens")} tokens in %.1f s, wrote ${s.getLong("generated_tokens")} in %.1f s"
                .format(Locale.US, (read - start) / 1000.0, (end - read) / 1000.0))
        } catch (e: Exception) {
            // the runner's numbers are a bonus: without them the time above stands
        }
        return sb.toString()
    }

    /** Why the last answer could not be had, if it could not. */
    @Volatile
    var error: String? = null
        private set

    private val lock = Any()
    private var module: LlmModule? = null
    private var closing: ScheduledFuture<*>? = null
    private val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "llama-idle").apply { isDaemon = true } }

    /**
     * Llama's answer to this prompt, greedy as on the Pi (temperature 0), or null when the model is
     * not here or failed ([error] says why). Blocking, one alert at a time: call it from a worker.
     */
    fun answer(c: Context, p: LlamaPrompt): Answer? {
        if (!ready(c)) {
            error = "Llama is not on this phone"
            return null
        }
        synchronized(lock) {
            closing?.cancel(false)
            try {
                val t0 = SystemClock.elapsedRealtime()
                var loadSeconds = 0.0
                val m = module ?: LlmModule(File(dir(c), PTE).path, File(dir(c), TOKENIZER).path, 0.0f).also {
                    it.load()                                  // a few seconds: the program and the weights
                    module = it
                    loadSeconds = (SystemClock.elapsedRealtime() - t0) / 1000.0
                }
                m.resetContext()           // each alert on its own: the runner would go on from the last one
                val out = StringBuilder()
                var pieces = 0
                var failed: String? = null
                var statsOf: String? = null
                // The runner hands over text piece by piece (a token, or a few for a Devanagari letter);
                // after maxNewTokens pieces it is stopped, as the Pi stops at maxNewTokens tokens.
                m.generate(p.text, SEQ_LEN, object : LlmCallback {
                    override fun onResult(result: String) {
                        if (pieces < p.maxNewTokens) out.append(result)
                        pieces++
                        if (pieces >= p.maxNewTokens) m.stop()
                    }

                    override fun onStats(stats: String) {
                        statsOf = stats
                    }

                    override fun onError(errorCode: Int, message: String) {
                        failed = "ExecuTorch error $errorCode: $message"
                    }
                }, false, 0.0f, 0, 0)
                failed?.let {
                    error = it
                    return null
                }
                error = null
                return Answer(out.toString(), (SystemClock.elapsedRealtime() - t0) / 1000.0, pieces, loadSeconds, statsOf)
            } catch (e: Throwable) {
                // The native library or the model can fail in ways Java cannot name (a missing
                // library, too little memory): the alert keeps the playbook's text.
                error = e.message ?: e.javaClass.simpleName
                release()
                return null
            } finally {
                closing = timer.schedule(Runnable { synchronized(lock) { release() } }, IDLE_MS, TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun release() {
        try {
            module?.close()
        } catch (e: Exception) {
            // it is being dropped anyway
        }
        module = null
    }

    // --- copying it from the Pi ------------------------------------------------------------------

    @Volatile
    var copying = false
        private set
    @Volatile
    var copied = 0L
        private set
    @Volatile
    var toCopy = 0L
        private set
    /** How the last copy ended, for the app's screen. */
    @Volatile
    var copyResult: String? = null
        private set
    private val copyLock = Any()

    /** Starts copying the model from the Pi in the background; false if a copy is already running. */
    fun startCopy(c: Context): Boolean {
        synchronized(copyLock) {
            if (copying) return false
            copying = true
            copied = 0L
            toCopy = 0L
        }
        val app = c.applicationContext
        Thread {
            copyResult = try {
                copy(app)
            } catch (e: Exception) {
                val why = e.message ?: e.javaClass.simpleName
                when {
                    "no Llama files" in why -> "Your Home Hub has no Llama files to give: on the Home Hub, check that " +
                        "~/executorch-deployment/llama3_2.pte and tokenizer.model are there, then restart it."
                    "HTTP 404" in why -> "Your Home Hub has no Llama files to give: it runs an older version. Update it " +
                        "(update 44) and restart it."
                    else -> "The copy stopped: $why. Tap Add again: it goes on from where it stopped."
                }
            } finally {
                copying = false
            }
        }.start()
        return true
    }

    /** Copies the files the Pi lists (GET /llama) that this phone does not have yet, and checks each. */
    private fun copy(c: Context): String {
        val client = PiClient.of(c)
        val files = client.llamaFiles().getJSONArray("files")
        val d = dir(c).apply { mkdirs() }
        val ok = readOk(c)
        val list = (0 until files.length()).map { files.getJSONObject(it) }
        val names = list.map { it.getString("name") }
        if (names.sorted() != NAMES.sorted()) throw IOException("the Home Hub listed other files: $names")
        val need = list.filter { f -> !same(c, ok, f) }
        toCopy = list.sumOf { it.getLong("bytes") }
        copied = toCopy - need.sumOf { it.getLong("bytes") }
        if (need.isEmpty()) return "Llama on this phone is the same as the Home Hub's (${megabytes(toCopy)})."
        val missing = need.sumOf { it.getLong("bytes") - File(d, it.getString("name") + ".part").length().coerceAtLeast(0) }
        if (d.usableSpace < missing + 200_000_000L) {
            throw IOException("not enough free space on the phone: ${megabytes(missing)} more are needed")
        }
        synchronized(lock) { release() }                      // its files are about to change
        for (f in need) {
            val name = f.getString("name")
            val bytes = f.getLong("bytes")
            val sha = f.getString("sha256").lowercase(Locale.US)
            val part = File(d, "$name.part")
            if (part.length() > bytes) part.delete()
            val before = copied
            if (part.length() < bytes) client.download("/llama/$name", part, bytes) { n -> copied = before + n }
            copied = before + bytes
            if (sha256(part) != sha) {
                part.delete()
                throw IOException("the copy of $name does not match the Home Hub's (SHA-256), so it was deleted")
            }
            ok.remove(name)
            writeOk(c, ok)                                    // not ready while the file is swapped
            val dest = File(d, name)
            if (dest.exists() && !dest.delete()) throw IOException("could not replace $name")
            if (!part.renameTo(dest)) throw IOException("could not save $name")
            ok.put(name, JSONObject().put("bytes", bytes).put("sha256", sha))
            writeOk(c, ok)
        }
        return "Llama 3.2 1B is now on this phone (${megabytes(toCopy)}), checked against the Home Hub's."
    }

    private fun same(c: Context, ok: JSONObject, f: JSONObject): Boolean {
        val name = f.getString("name")
        val have = ok.optJSONObject(name) ?: return false
        return File(dir(c), name).length() == f.getLong("bytes") && have.optLong("bytes") == f.getLong("bytes") &&
            have.optString("sha256") == f.getString("sha256").lowercase(Locale.US)
    }

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { input ->
            val buf = ByteArray(1 shl 20)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
