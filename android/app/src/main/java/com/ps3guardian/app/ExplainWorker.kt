package com.ps3guardian.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf

/**
 * Llama on the Home Hub needs 20-30 s to write its explanation. This background job asks the Hub
 * for it every 5 seconds and, when it is ready, puts it into the message's History entry and, if
 * the alert is still on screen, into the alert.
 */
class ExplainWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val c = applicationContext
        val job = inputData.getString(KEY_JOB) ?: return Result.success()
        val notificationId = inputData.getInt(KEY_NOTIFICATION, 0)
        val historyId = inputData.getString(KEY_HISTORY) ?: ""
        val client = PiClient.of(c)
        repeat(36) {                                         // at most 3 minutes
            val reply = try {
                client.explain(job)
            } catch (e: Exception) {
                if (runAttemptCount < 3) return Result.retry()
                History.set(c, historyId, "llama", "failed")
                return Result.success()
            }
            when (reply.optString("status")) {
                "pending" -> Thread.sleep(5_000)
                "done" -> {
                    val advice = reply.optJSONObject("advice") ?: return Result.success()
                    History.explained(c, historyId, advice.optString("what"), advice.optString("why"), "hub")
                    if (notificationId != 0 && Notifier.isShowing(c, notificationId)) Notifier.alert(c, historyId, notificationId)
                    return Result.success()
                }
                else -> {                                    // fallback or failed: the first advice stays
                    History.set(c, historyId, "llama", "failed")
                    return Result.success()
                }
            }
        }
        History.set(c, historyId, "llama", "failed")
        return Result.success()
    }

    companion object {
        private const val KEY_JOB = "job"
        private const val KEY_NOTIFICATION = "notification"
        private const val KEY_HISTORY = "history"

        /** notificationId 0: no alert to update (a message checked on its own screen). */
        fun enqueue(context: Context, job: String, notificationId: Int, historyId: String) {
            val request = OneTimeWorkRequestBuilder<ExplainWorker>()
                .setInputData(workDataOf(KEY_JOB to job, KEY_NOTIFICATION to notificationId, KEY_HISTORY to historyId))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueue(request)
        }
    }
}
