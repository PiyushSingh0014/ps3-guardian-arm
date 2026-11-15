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
 * Llama on the Pi needs 20-30 s to write its explanation. This background job asks
 * the Pi for it every 5 seconds and, when it is ready, replaces the alert's text.
 */
class ExplainWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val job = inputData.getString(KEY_JOB) ?: return Result.success()
        val notificationId = inputData.getInt(KEY_NOTIFICATION, 0)
        val client = PiClient.of(applicationContext)
        repeat(36) {                                         // at most 3 minutes
            val reply = try {
                client.explain(job)
            } catch (e: Exception) {
                return if (runAttemptCount < 3) Result.retry() else Result.success()
            }
            when (reply.optString("status")) {
                "pending" -> Thread.sleep(5_000)
                "done" -> {
                    val advice = reply.optJSONObject("advice") ?: return Result.success()
                    val title = inputData.getString(KEY_TITLE) ?: advice.optString("headline")
                    Notifier.show(applicationContext, title, Notifier.adviceText(advice), notificationId)
                    return Result.success()
                }
                else -> return Result.success()              // fallback or failed: the first advice stays
            }
        }
        return Result.success()
    }

    companion object {
        private const val KEY_JOB = "job"
        private const val KEY_NOTIFICATION = "notification"
        private const val KEY_TITLE = "title"

        fun enqueue(context: Context, job: String, notificationId: Int, title: String) {
            val request = OneTimeWorkRequestBuilder<ExplainWorker>()
                .setInputData(workDataOf(KEY_JOB to job, KEY_NOTIFICATION to notificationId, KEY_TITLE to title))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueue(request)
        }
    }
}
