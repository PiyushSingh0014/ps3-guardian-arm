package com.example.ps3guardian

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Sends the SMS that arrived while the Pi could not be reached. It runs every 15 minutes while
 * messages are waiting, when the app is opened, and after any SMS the Pi answered.
 */
class FlushWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        Checker.flush(applicationContext)
        return Result.success()
    }

    companion object {
        private const val EVERY_15_MIN = "flush-periodic"
        private const val NOW = "flush-now"

        private fun network() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        /** Try every 15 minutes (the shortest repeat Android allows) until nothing is waiting. */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<FlushWorker>(15, TimeUnit.MINUTES)
                .setConstraints(network())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(EVERY_15_MIN, ExistingPeriodicWorkPolicy.KEEP, request)
        }

        /** Try once now, if anything is waiting. */
        fun flushSoon(context: Context) {
            if (Settings.pendingCount(context) == 0) return
            val request = OneTimeWorkRequestBuilder<FlushWorker>().setConstraints(network()).build()
            WorkManager.getInstance(context).enqueueUniqueWork(NOW, ExistingWorkPolicy.KEEP, request)
        }

        fun stop(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(EVERY_15_MIN)
        }
    }
}
