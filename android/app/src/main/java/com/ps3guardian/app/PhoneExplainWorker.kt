package com.ps3guardian.app

import android.content.Context
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.ps3guardian.app.guard.GuardResult
import org.json.JSONArray
import java.util.Locale

/**
 * Llama on this phone (update 44), for an alert the Pi could not explain because it could not be
 * reached. It gets the same evidence-only prompt as on the Pi (the scam type, the warning signs and
 * who the message claims to be: never the message text), its answer passes the Pi's checks, and
 * the alert's text is replaced while it is still on screen, as ExplainWorker does with the Pi's.
 * One alert at a time: the jobs queue one after another.
 */
class PhoneExplainWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val c = applicationContext
        val d = inputData
        val id = d.getInt(KEY_NOTIFICATION, 0)
        val historyId = d.getString(KEY_HISTORY) ?: ""
        if (!firstTime(id, (d.getString(KEY_LINE) ?: "") + historyId)) return Result.success()     // explained already
        val verdict = d.getString(KEY_VERDICT) ?: return Result.success()
        val language = d.getString(KEY_LANGUAGE) ?: "en"
        val guard = PhoneGuard.get(c) ?: return Result.success()
        val prompt = guard.llama.prompt(verdict, d.getString(KEY_CATEGORY) ?: "", strings(d.getString(KEY_REASONS)),
            d.getString(KEY_CLAIMS)?.ifEmpty { null }, d.getString(KEY_KIND)?.ifEmpty { null }, language)
            ?: return Result.success()
        History.set(c, historyId, "llama", "writing")
        val answer = PhoneLlama.answer(c, prompt)
        val label = d.getString(KEY_LINE) ?: ""
        if (answer == null) {
            Settings.addRecent(c, "$label  Llama on this phone could not answer: ${PhoneLlama.error}")
            History.set(c, historyId, "llama", "failed")
            return Result.success()
        }
        val checked = guard.llama.check(answer.text, verdict, language, prompt.evidence)
        val took = "%.1f s".format(Locale.US, answer.seconds)
        if (!checked.ok) {                                 // the playbook's text stays, as on the Hub
            Settings.addRecent(c, "$label  Llama on this phone ($took): answer not used, ${checked.flags.firstOrNull() ?: ""}")
            History.set(c, historyId, "llama", "failed")
            return Result.success()
        }
        val what = checked.what.ifEmpty { d.getString(KEY_WHAT) ?: "" }
        val why = checked.why.ifEmpty { d.getString(KEY_WHY) ?: "" }
        val timings = PhoneLlama.describe(answer)
        History.explained(c, historyId, what, why, "phone", timings)
        if (id != 0 && Notifier.isShowing(c, id)) Notifier.alert(c, historyId, id)
        Settings.addRecent(c, "$label  Llama on this phone explained it in $timings")
        return Result.success()
    }

    companion object {
        private const val KEY_NOTIFICATION = "notification"
        private const val KEY_TITLE = "title"
        private const val KEY_VERDICT = "verdict"
        private const val KEY_CATEGORY = "category"
        private const val KEY_REASONS = "reasons"
        private const val KEY_CLAIMS = "claims_to_be"
        private const val KEY_KIND = "claims_kind"
        private const val KEY_LANGUAGE = "language"
        private const val KEY_WHAT = "what"
        private const val KEY_WHY = "why"
        private const val KEY_STEPS = "steps"
        private const val KEY_LINE = "line"
        private const val KEY_HISTORY = "history"

        /**
         * Asks Llama on this phone to explain the alert with this id (0: none on screen) and its History
         * entry, if the model is here and the verdict is one the Hub would explain. line: the start of
         * the activity log's line ("21 Nov 10:02  sender").
         */
        fun enqueue(context: Context, r: GuardResult, notificationId: Int, title: String, language: String, line: String,
                    historyId: String = "") {
            if ((notificationId == 0 && historyId.isEmpty()) || r.verdict == "safe" || !PhoneLlama.ready(context)) return
            // Only the evidence Llama is shown and the alert's own text: never the message itself.
            val data = workDataOf(
                KEY_NOTIFICATION to notificationId, KEY_TITLE to title, KEY_VERDICT to r.verdict,
                KEY_CATEGORY to r.category, KEY_REASONS to JSONArray(r.reasons.take(8)).toString(),   // the prompt uses 4
                KEY_CLAIMS to (r.claimsToBe ?: ""), KEY_KIND to (r.claimsKind ?: ""), KEY_LANGUAGE to language,
                KEY_WHAT to r.what, KEY_WHY to r.why, KEY_STEPS to JSONArray(r.steps).toString(), KEY_LINE to line,
                KEY_HISTORY to historyId,
            )
            val request = OneTimeWorkRequestBuilder<PhoneExplainWorker>().setInputData(data).build()
            WorkManager.getInstance(context).enqueueUniqueWork(QUEUE, ExistingWorkPolicy.APPEND_OR_REPLACE, request)
        }

        private const val QUEUE = "phone-llama"

        // The alerts explained since the app started. WorkManager can run a job a second time (one
        // test on the S25 was explained twice); the second run then costs nothing and adds no line.
        private val explained = LinkedHashSet<String>()

        @Synchronized
        private fun firstTime(id: Int, line: String): Boolean {
            if (!explained.add("$id $line")) return false
            if (explained.size > 200) explained.remove(explained.first())
            return true
        }

        private fun strings(json: String?): List<String> {
            val a = JSONArray(json ?: "[]")
            return List(a.length()) { a.getString(it) }
        }
    }
}
