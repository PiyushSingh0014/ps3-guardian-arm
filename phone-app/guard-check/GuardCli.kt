// (Line comments: Kotlin would read the "/*" of a path as the start of a nested comment.)
// Runs Phone Guard (the app's guard/ folder) on a computer, for scripts/check_phone_guard.py:
//
//   kotlinc ../app/src/main/java/com/ps3guardian/app/guard/*.kt GuardCli.kt -include-runtime -d guard-check.jar
//   java -jar guard-check.jar ../app/src/main/assets/guard in.jsonl phone.jsonl
//   java -jar guard-check.jar --answers ../app/src/main/assets/guard answers.jsonl checked.jsonl
//
// The first checks messages ({"text", "sender"}): the verdict and everything the app shows, who the
// message claims to be, and the case and prompt Llama would get (update 44). The second runs the
// Llama answer checker on answers ({"raw", "verdict", "language", "evidence"}).
// Not part of the app: Android Studio does not build this folder.
import com.ps3guardian.app.guard.Guard
import com.ps3guardian.app.guard.GuardFiles
import java.io.File
import java.security.MessageDigest

private fun q(s: String?): String {
    if (s == null) return "null"
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

private fun sha256(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

@Suppress("UNCHECKED_CAST")
private fun parse(line: String) = com.ps3guardian.app.guard.JsonForTests.parse(line) as Map<String, Any?>

/** args: assets folder, input JSONL, output JSONL (with --answers first: the answer checker). */
fun main(args: Array<String>) {
    val answers = args[0] == "--answers"
    val a = if (answers) args.drop(1) else args.toList()
    val dir = File(a[0])
    val t0 = System.nanoTime()
    val guard = Guard(GuardFiles { name -> File(dir, name).readBytes() })
    System.err.println("loaded in %.0f ms".format((System.nanoTime() - t0) / 1e6))
    File(a[2]).bufferedWriter().use { out ->
        if (answers) {
            var n = 0
            File(a[1]).forEachLine { line ->
                val m = parse(line)
                val c = guard.llama.check(m["raw"] as String, m["verdict"] as String, m["language"] as String,
                    m["evidence"] as String?)
                out.write("{\"what\":${q(c.what)},\"why\":${q(c.why)},\"ok\":${c.ok},\"flags\":[${c.flags.joinToString(",") { q(it) }}]}\n")
                n++
            }
            System.err.println("checked $n answers")
            return
        }
        var total = 0.0; var n = 0
        File(a[1]).forEachLine { line ->
            val m = parse(line)
            val r = guard.check(m["text"] as String, m["sender"] as String?)
            total += r.millis; n++
            val links = r.links.joinToString(",") { v ->
                "{\"host\":${q(v.host)},\"verdict\":${q(v.verdict)},\"score\":${v.score},\"kind\":${q(v.kind)},\"decisive\":${v.decisive},\"reasons\":[${v.reasons.joinToString(",") { q(it) }}]}"
            }
            val en = guard.llama.prompt(r, "en")
            val hi = guard.llama.prompt(r, "hi")
            val llama = if (en == null || hi == null) "null" else
                "{\"case\":${q(en.evidence)},\"prompt_en\":${q(sha256(en.text))},\"prompt_hi\":${q(sha256(hi.text))},\"max_new_en\":${en.maxNewTokens},\"max_new_hi\":${hi.maxNewTokens}}"
            out.write("{\"score\":${r.score},\"verdict\":${q(r.verdict)},\"category\":${q(r.category)},\"reasons\":[${r.reasons.joinToString(",") { q(it) }}],\"headline\":${q(r.headline)},\"steps\":[${r.steps.joinToString(",") { q(it) }}],\"clean\":${q(guard.clean(m["text"] as String))},\"links\":[$links],\"claims_to_be\":${q(r.claimsToBe)},\"claims_kind\":${q(r.claimsKind)},\"llama\":$llama}\n")
        }
        System.err.println("checked $n messages, %.2f ms each on average".format(total / maxOf(n, 1)))
    }
}
