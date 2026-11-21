/*
 * Runs Phone Guard (the app's guard/ folder) on a computer, for scripts/check_phone_guard.py:
 *
 *   kotlinc ../app/src/main/java/com/ps3guardian/app/guard/*.kt GuardCli.kt -include-runtime -d guard-check.jar
 *   java -jar guard-check.jar ../app/src/main/assets/guard in.jsonl phone.jsonl
 *
 * Not part of the app: Android Studio does not build this folder.
 */
import com.ps3guardian.app.guard.Guard
import com.ps3guardian.app.guard.GuardFiles
import java.io.File

private fun q(s: String): String {
    val sb = StringBuilder("\"")
    for (c in s) when {
        c == '"' -> sb.append("\\\"")
        c == '\\' -> sb.append("\\\\")
        c == '\n' -> sb.append("\\n")
        c == '\r' -> sb.append("\\r")
        c == '\t' -> sb.append("\\t")
        c.code < 0x20 -> sb.append(String.format("\\u%04x", c.code))
        else -> sb.append(c)
    }
    return sb.append('"').toString()
}

/** args: assets folder, input JSONL ({"text", "sender"}), output JSONL. */
fun main(args: Array<String>) {
    val dir = File(args[0])
    val t0 = System.nanoTime()
    val guard = Guard(GuardFiles { name -> File(dir, name).readBytes() })
    System.err.println("loaded in %.0f ms".format((System.nanoTime() - t0) / 1e6))
    File(args[2]).bufferedWriter().use { out ->
        var total = 0.0; var n = 0
        File(args[1]).forEachLine { line ->
            @Suppress("UNCHECKED_CAST")
            val m = com.ps3guardian.app.guard.JsonForTests.parse(line) as Map<String, Any?>
            val r = guard.check(m["text"] as String, m["sender"] as String?)
            total += r.millis; n++
            val links = r.links.joinToString(",") { v ->
                "{\"host\":${q(v.host)},\"verdict\":${q(v.verdict)},\"score\":${v.score},\"kind\":${q(v.kind)},\"decisive\":${v.decisive},\"reasons\":[${v.reasons.joinToString(",") { q(it) }}]}"
            }
            out.write("{\"score\":${r.score},\"verdict\":${q(r.verdict)},\"category\":${q(r.category)},\"reasons\":[${r.reasons.joinToString(",") { q(it) }}],\"headline\":${q(r.headline)},\"steps\":[${r.steps.joinToString(",") { q(it) }}],\"clean\":${q(guard.clean(m["text"] as String))},\"links\":[$links]}\n")
        }
        System.err.println("checked $n messages, %.2f ms each on average".format(total / maxOf(n, 1)))
    }
}
