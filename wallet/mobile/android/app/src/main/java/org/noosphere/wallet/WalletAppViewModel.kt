package org.noosphere.wallet

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.noosphere.wallet.core.DerivedAuthority
import org.noosphere.wallet.core.MobileNodeSnapshot
import org.noosphere.wallet.core.MobileWalletCore
import org.noosphere.wallet.core.SubmissionResult
import org.noosphere.wallet.core.TransferReview
import org.noosphere.wallet.core.WalletApiTransport
import org.noosphere.wallet.core.WalletSdkException
import org.noosphere.wallet.core.WalletTransferBundle
import org.noosphere.wallet.security.StrongBoxSeedVault
import java.io.IOException

internal enum class BiometricAction { DERIVE_AUTHORITY, SIGN_TRANSFER }

internal data class WalletAppState(
    val networkEnabled: Boolean,
    val networkReason: String?,
    val chainId: String,
    val genesisHash: String,
    val walletId: String = "primary",
    val account: String = "0",
    val index: String = "0",
    val seedHex: String = "",
    val allowHardwareFallback: Boolean = false,
    val trustTier: StrongBoxSeedVault.TrustTier? = null,
    val nodeSnapshot: MobileNodeSnapshot? = null,
    val nodeQuorumEndpoints: UInt? = null,
    val nodeQuorumClusters: UInt? = null,
    val derivedAuthority: DerivedAuthority? = null,
    val transactionSpec: String = "",
    val transferReview: TransferReview? = null,
    val submissionResult: SubmissionResult? = null,
    val busyLabel: String? = null,
    val notice: String? = null,
    val errorCode: String? = null,
)

internal class WalletAppViewModel(application: Application) : AndroidViewModel(application) {
    private val network = MindChainNetwork.load(application)
    private val vault = StrongBoxSeedVault(application, network.chainIdBytes())
    private val walletCore = MobileWalletCore(
        chainId = network.chainId,
        genesisHash = network.genesisHash,
        apiVersion = "v1",
        maximumFreshnessMs = network.maximumFreshnessMs,
    )
    private val transport = if (network.enabled) {
        WalletApiTransport(
            chainId = network.chainId,
            genesisHash = network.genesisHash,
            minimumControlClusterQuorum = network.minimumControlClusterQuorum,
            endpoints = network.endpoints,
        )
    } else {
        null
    }

    private val mutableState = MutableStateFlow(
        WalletAppState(
            networkEnabled = network.enabled,
            networkReason = network.disabledReason,
            chainId = network.chainId,
            genesisHash = network.genesisHash,
        ),
    )
    val state: StateFlow<WalletAppState> = mutableState.asStateFlow()

    private var pendingTransfer: PendingTransfer? = null
    private var preparedTransfer: PreparedTransfer? = null

    init {
        refreshWalletState()
        if (network.enabled) synchronizeNode()
    }

    fun setWalletId(value: String) = mutateInput { copy(walletId = value.lowercase(), derivedAuthority = null) }
    fun setAccount(value: String) = mutateInput { copy(account = value, derivedAuthority = null) }
    fun setIndex(value: String) = mutateInput { copy(index = value, derivedAuthority = null) }
    fun setSeedHex(value: String) = mutateInput { copy(seedHex = value.filterNot(Char::isWhitespace)) }
    fun setHardwareFallback(value: Boolean) = mutateInput { copy(allowHardwareFallback = value) }
    fun setTransactionSpec(value: String) = mutateInput {
        pendingTransfer = null
        preparedTransfer = null
        copy(transactionSpec = value, transferReview = null, submissionResult = null)
    }

    fun dismissMessage() {
        mutableState.update { it.copy(notice = null, errorCode = null) }
    }

    fun synchronizeNode() {
        if (mutableState.value.busyLabel != null) return
        launchOperation("Synchronizing finalized checkpoint") {
            val outcome = MobileNodeCoordinator.synchronize(getApplication(), network)
            mutableState.update {
                it.copy(
                    nodeSnapshot = outcome.snapshot,
                    nodeQuorumEndpoints = outcome.quorumEndpoints,
                    nodeQuorumClusters = outcome.quorumControlClusters,
                    notice = if (outcome.advanced) "Finalized checkpoint advanced" else "Finalized checkpoint verified",
                )
            }
        }
    }

    fun importSeed() {
        if (mutableState.value.busyLabel != null) return
        val snapshot = mutableState.value
        mutableState.update { it.copy(seedHex = "") }
        launchOperation("Sealing seed in device hardware") {
            val seed = decodeSeed(snapshot.seedHex)
            val tier = try {
                vault.importSeed(
                    walletId = snapshot.walletId,
                    seed = seed,
                    allowHardwareFallback = snapshot.allowHardwareFallback,
                )
            } finally {
                seed.fill(0)
            }
            pendingTransfer = null
            preparedTransfer = null
            mutableState.update {
                it.copy(
                    trustTier = tier,
                    derivedAuthority = null,
                    transferReview = null,
                    submissionResult = null,
                    notice = when (tier) {
                        StrongBoxSeedVault.TrustTier.STRONGBOX -> "Seed sealed by StrongBox"
                        StrongBoxSeedVault.TrustTier.HARDWARE_KEYSTORE -> "Seed sealed by hardware-backed Keystore"
                    },
                )
            }
        }
    }

    fun deleteWallet() {
        if (mutableState.value.busyLabel != null) return
        val walletId = mutableState.value.walletId
        launchOperation("Deleting device-bound wallet") {
            vault.delete(walletId)
            pendingTransfer = null
            preparedTransfer = null
            mutableState.update {
                it.copy(
                    trustTier = null,
                    seedHex = "",
                    derivedAuthority = null,
                    transferReview = null,
                    submissionResult = null,
                    notice = "Device-bound wallet deleted",
                )
            }
        }
    }

    fun reviewTransfer() {
        if (mutableState.value.busyLabel != null) return
        val transactionSpec = mutableState.value.transactionSpec
        launchOperation("Building quorum-verified review") {
            val outcome = MobileNodeCoordinator.synchronize(getApplication(), network)
            val bundle = requireTransport().fetchTransferBundle(transactionSpec, outcome.snapshot)
            val review = walletCore.reviewTransfer(
                transactionSpecJson = transactionSpec,
                statusJson = bundle.statusJson,
                notesJson = bundle.notesJson,
            )
            pendingTransfer = PendingTransfer(transactionSpec, bundle, review)
            preparedTransfer = null
            mutableState.update {
                it.copy(
                    nodeSnapshot = outcome.snapshot,
                    nodeQuorumEndpoints = outcome.quorumEndpoints,
                    nodeQuorumClusters = outcome.quorumControlClusters,
                    transferReview = review,
                    submissionResult = null,
                    notice = "Review locked to ${shortHash(review.reviewId)}",
                )
            }
        }
    }

    suspend fun prepareSeedAccess(action: BiometricAction): StrongBoxSeedVault.SeedAccessSession {
        val current = mutableState.value
        if (current.busyLabel != null) throw IllegalStateException("operation_in_progress")
        val account = parseUInt(current.account, "invalid_account")
        val index = parseUInt(current.index, "invalid_index")
        if (action == BiometricAction.SIGN_TRANSFER) {
            mutableState.update { it.copy(busyLabel = "Revalidating exact transfer review", errorCode = null) }
            try {
                val prior = pendingTransfer ?: throw IllegalStateException("transfer_review_required")
                val outcome = MobileNodeCoordinator.synchronize(getApplication(), network)
                val bundle = requireTransport().fetchTransferBundle(prior.transactionSpec, outcome.snapshot)
                val refreshed = walletCore.reviewTransfer(
                    transactionSpecJson = prior.transactionSpec,
                    statusJson = bundle.statusJson,
                    notesJson = bundle.notesJson,
                )
                if (refreshed.reviewId != prior.review.reviewId) {
                    pendingTransfer = PendingTransfer(prior.transactionSpec, bundle, refreshed)
                    preparedTransfer = null
                    mutableState.update {
                        it.copy(
                            transferReview = refreshed,
                            nodeSnapshot = outcome.snapshot,
                            nodeQuorumEndpoints = outcome.quorumEndpoints,
                            nodeQuorumClusters = outcome.quorumControlClusters,
                        )
                    }
                    throw IllegalStateException("review_changed_reconfirm")
                }
                preparedTransfer = PreparedTransfer(
                    pending = PendingTransfer(prior.transactionSpec, bundle, refreshed),
                    snapshot = outcome.snapshot,
                    account = account,
                    index = index,
                )
                mutableState.update {
                    it.copy(
                        nodeSnapshot = outcome.snapshot,
                        nodeQuorumEndpoints = outcome.quorumEndpoints,
                        nodeQuorumClusters = outcome.quorumControlClusters,
                    )
                }
            } catch (error: Throwable) {
                mutableState.update { it.copy(errorCode = errorCode(error)) }
                throw error
            } finally {
                mutableState.update { it.copy(busyLabel = null) }
            }
        }
        return withContext(Dispatchers.IO) { vault.beginSeedAccess(current.walletId) }
    }

    fun completeBiometric(action: BiometricAction, session: StrongBoxSeedVault.SeedAccessSession) {
        if (mutableState.value.busyLabel != null) {
            session.discard()
            return
        }
        when (action) {
            BiometricAction.DERIVE_AUTHORITY -> deriveAuthority(session)
            BiometricAction.SIGN_TRANSFER -> signAndSubmit(session)
        }
    }

    fun biometricFailed(session: StrongBoxSeedVault.SeedAccessSession, code: String) {
        session.discard()
        mutableState.update { it.copy(errorCode = sanitizeCode(code), busyLabel = null) }
    }

    private fun deriveAuthority(session: StrongBoxSeedVault.SeedAccessSession) {
        val current = mutableState.value
        val account = try {
            parseUInt(current.account, "invalid_account")
        } catch (error: RuntimeException) {
            session.discard()
            mutableState.update { it.copy(errorCode = errorCode(error)) }
            return
        }
        val index = try {
            parseUInt(current.index, "invalid_index")
        } catch (error: RuntimeException) {
            session.discard()
            mutableState.update { it.copy(errorCode = errorCode(error)) }
            return
        }
        launchOperation("Deriving purpose-separated authority") {
            val authority = session.complete { seed ->
                walletCore.deriveAuthority(
                    seed = seed,
                    purpose = "sign",
                    suite = null,
                    account = account,
                    index = index,
                )
            }
            mutableState.update {
                it.copy(derivedAuthority = authority, notice = "Public authority derived")
            }
        }
    }

    private fun signAndSubmit(session: StrongBoxSeedVault.SeedAccessSession) {
        val prepared = preparedTransfer
        if (prepared == null) {
            session.discard()
            mutableState.update { it.copy(errorCode = "transfer_review_required") }
            return
        }
        launchOperation("Signing in hardware and submitting") {
            val signed = session.complete { seed ->
                walletCore.signReviewedTransfer(
                    seed = seed,
                    account = prepared.account,
                    index = prepared.index,
                    signerScope = 0U,
                    transactionSpecJson = prepared.pending.transactionSpec,
                    statusJson = prepared.pending.bundle.statusJson,
                    notesJson = prepared.pending.bundle.notesJson,
                    expectedReviewId = prepared.pending.review.reviewId,
                )
            }
            val response = requireTransport().submit(signed.submissionJson, prepared.snapshot)
            val result = walletCore.validateSubmissionResponse(signed.txid, response)
            preparedTransfer = null
            pendingTransfer = null
            mutableState.update {
                it.copy(
                    transferReview = null,
                    submissionResult = result,
                    notice = "Transaction accepted into ${result.state}",
                )
            }
        }
    }

    private fun refreshWalletState() {
        viewModelScope.launch(Dispatchers.IO) {
            val walletId = mutableState.value.walletId
            val tier = runCatching { vault.trustTier(walletId) }.getOrNull()
            mutableState.update { it.copy(trustTier = tier) }
        }
    }

    private fun launchOperation(label: String, operation: suspend () -> Unit) {
        mutableState.update { it.copy(busyLabel = label, errorCode = null, notice = null) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                operation()
            } catch (error: Throwable) {
                mutableState.update { it.copy(errorCode = errorCode(error)) }
            } finally {
                mutableState.update { it.copy(busyLabel = null) }
            }
        }
    }

    private fun mutateInput(transform: WalletAppState.() -> WalletAppState) {
        if (mutableState.value.busyLabel == null) mutableState.update(transform)
    }

    private fun requireTransport(): WalletApiTransport =
        transport ?: throw NetworkDisabledException(network.disabledReason!!)

    override fun onCleared() {
        walletCore.close()
        super.onCleared()
    }

    private data class PendingTransfer(
        val transactionSpec: String,
        val bundle: WalletTransferBundle,
        val review: TransferReview,
    )

    private data class PreparedTransfer(
        val pending: PendingTransfer,
        val snapshot: MobileNodeSnapshot,
        val account: UInt,
        val index: UInt,
    )

    companion object {
        private val SAFE_CODE = Regex("^[a-z0-9_]{1,96}$")
        private val HEX = Regex("^[0-9a-fA-F]+$")

        private fun decodeSeed(raw: String): ByteArray {
            if (raw.length !in 32..256 || raw.length % 2 != 0 || !HEX.matches(raw)) {
                throw IllegalArgumentException("invalid_seed_hex")
            }
            return ByteArray(raw.length / 2) { offset ->
                raw.substring(offset * 2, offset * 2 + 2).toInt(16).toByte()
            }
        }

        private fun parseUInt(value: String, code: String): UInt =
            value.toUIntOrNull() ?: throw IllegalArgumentException(code)

        private fun shortHash(value: String): String = value.take(8) + "…" + value.takeLast(8)

        private fun sanitizeCode(value: String): String =
            value.lowercase().replace('-', '_').takeIf(SAFE_CODE::matches) ?: "operation_failed"

        private fun errorCode(error: Throwable): String = when (error) {
            is StrongBoxSeedVault.VaultException -> sanitizeCode(error.code)
            is NetworkDisabledException -> sanitizeCode(error.reason)
            is WalletSdkException.InvalidProfile -> "invalid_profile"
            is WalletSdkException.InvalidRequest -> "invalid_request"
            is WalletSdkException.MalformedStatus -> "malformed_status"
            is WalletSdkException.StaleStatus -> "stale_status"
            is WalletSdkException.IndexerUnavailable -> "indexer_unavailable"
            is WalletSdkException.WrongProtocolIdentity -> "wrong_protocol_identity"
            is WalletSdkException.InvalidTransaction -> "invalid_transaction"
            is WalletSdkException.InsufficientFunds -> "insufficient_funds"
            is WalletSdkException.NonceBoundary -> "nonce_boundary"
            is WalletSdkException.FeeBoundary -> "fee_boundary"
            is WalletSdkException.ReviewMismatch -> "review_mismatch"
            is WalletSdkException.SubmissionRejected -> "submission_rejected"
            is WalletSdkException.MalformedSubmitResponse -> "malformed_submit_response"
            is WalletSdkException.TxidMismatch -> "txid_mismatch"
            is WalletSdkException.InvalidObservation -> "invalid_observation"
            is WalletSdkException.InsufficientQuorum -> "insufficient_quorum"
            is WalletSdkException.CheckpointRegression -> "checkpoint_regression"
            is WalletSdkException.CheckpointConflict -> "checkpoint_conflict"
            is WalletSdkException.InvalidPersistedState -> "invalid_persisted_state"
            is IOException, is IllegalArgumentException, is IllegalStateException ->
                sanitizeCode(error.message.orEmpty())
            else -> "operation_failed"
        }
    }
}
