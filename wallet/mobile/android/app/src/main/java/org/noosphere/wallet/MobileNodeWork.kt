package org.noosphere.wallet

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.noosphere.wallet.core.MobileNodeSyncOutcome
import org.noosphere.wallet.core.MobileNodeSynchronizer
import java.io.IOException
import java.util.concurrent.TimeUnit

internal object MobileNodeCoordinator {
    private val synchronizationLock = Mutex()

    suspend fun synchronize(context: Context, network: MindChainNetwork): MobileNodeSyncOutcome =
        withContext(Dispatchers.IO) {
            synchronizationLock.withLock {
                val enabled = network.requireEnabled()
                MobileNodeSynchronizer(
                    context = context.applicationContext,
                    chainId = enabled.chainId,
                    genesisHash = enabled.genesisHash,
                    maximumFreshnessMs = enabled.maximumFreshnessMs,
                    minimumControlClusterQuorum = enabled.minimumControlClusterQuorum,
                    endpoints = enabled.endpoints,
                ).use(MobileNodeSynchronizer::synchronize)
            }
        }
}

internal class MobileNodeWorker(
    appContext: Context,
    workerParameters: WorkerParameters,
) : CoroutineWorker(appContext, workerParameters) {
    override suspend fun doWork(): Result {
        val network = try {
            MindChainNetwork.load(applicationContext)
        } catch (_: RuntimeException) {
            return Result.failure()
        }
        return try {
            MobileNodeCoordinator.synchronize(applicationContext, network)
            Result.success()
        } catch (_: NetworkDisabledException) {
            // A disabled signed-in build is deliberate. Do not create a retry loop
            // until a valid public indexer quorum is configured.
            Result.success()
        } catch (_: IOException) {
            Result.retry()
        } catch (_: RuntimeException) {
            Result.failure()
        }
    }

    companion object {
        private const val UNIQUE_WORK = "mindchain-mobile-node-periodic-v1"

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<MobileNodeWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
                UNIQUE_WORK,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
        }
    }
}
