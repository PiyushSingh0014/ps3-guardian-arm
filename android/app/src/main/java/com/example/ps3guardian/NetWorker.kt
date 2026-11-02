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
import androidx.work.workDataOf
import java.util.concurrent.TimeUnit

/**
 * Asks the Pi for new network alerts about once a minute while it answers, and every
 * 15 minutes while it does not (the phone is away from the lab Wi-Fi). Each check queues the
 * next one. A 15-minute repeat, the shortest Android allows, restarts that chain if it ever
 * stops. While the phone sleeps, Android delays both.
 */
class NetWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val c = applicationContext
        if (!Settings.netOn(c)) return Result.success()
        val reached = NetAlerts.check(c)
        val delay = if (reached) EVERY_S else AWAY_S
        if (inputData.getBoolean(KEY_CHAIN, false)) {
            queue(c, delay, ExistingWorkPolicy.APPEND_OR_REPLACE)    // the next link, after this one
        } else {
            queue(c, delay, ExistingWorkPolicy.KEEP)                 // the 15-minute repeat: only if the chain stopped
        }
        return Result.success()
    }

    companion object {
        private const val CHAIN = "net-alerts"
        private const val REPEAT = "net-alerts-15min"
        private const val KEY_CHAIN = "chain"
        private const val EVERY_S = 60L
        private const val AWAY_S = 15 * 60L

        private fun network() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        private fun queue(context: Context, delaySeconds: Long, policy: ExistingWorkPolicy) {
            val request = OneTimeWorkRequestBuilder<NetWorker>()
                .setInitialDelay(delaySeconds, TimeUnit.SECONDS)
                .setInputData(workDataOf(KEY_CHAIN to true))
                .setConstraints(network())
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(CHAIN, policy, request)
        }

        /** Starts the checks (app opened, switch turned on). Safe to call again: a running chain continues. */
        fun start(context: Context) {
            if (!Settings.netOn(context)) return
            val repeat = PeriodicWorkRequestBuilder<NetWorker>(15, TimeUnit.MINUTES)
                .setConstraints(network())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(REPEAT, ExistingPeriodicWorkPolicy.KEEP, repeat)
            queue(context, 0L, ExistingWorkPolicy.KEEP)
        }

        fun stop(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(CHAIN)
            WorkManager.getInstance(context).cancelUniqueWork(REPEAT)
        }
    }
}
