package org.noosphere.wallet

import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.noosphere.wallet.security.StrongBoxSeedVault

class MainActivity : FragmentActivity() {
    private var activeSession: StrongBoxSeedVault.SeedAccessSession? = null
    private var activeAction: BiometricAction? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
        )
        MobileNodeWorker.schedule(this)

        setContent {
            MindChainTheme {
                val model: WalletAppViewModel = viewModel()
                val state by model.state.collectAsStateWithLifecycle()
                WalletScreen(
                    state = state,
                    onWalletId = model::setWalletId,
                    onAccount = model::setAccount,
                    onIndex = model::setIndex,
                    onSeedHex = model::setSeedHex,
                    onHardwareFallback = model::setHardwareFallback,
                    onImportSeed = model::importSeed,
                    onDeleteWallet = model::deleteWallet,
                    onDeriveAuthority = { authenticate(model, BiometricAction.DERIVE_AUTHORITY) },
                    onSynchronize = model::synchronizeNode,
                    onTransactionSpec = model::setTransactionSpec,
                    onReviewTransfer = model::reviewTransfer,
                    onSignTransfer = { authenticate(model, BiometricAction.SIGN_TRANSFER) },
                    onDismissMessage = model::dismissMessage,
                )
            }
        }
    }

    private fun authenticate(model: WalletAppViewModel, action: BiometricAction) {
        if (activeSession != null) return
        lifecycleScope.launch {
            val session = try {
                model.prepareSeedAccess(action)
            } catch (_: Throwable) {
                return@launch
            }
            activeSession = session
            activeAction = action

            val executor = ContextCompat.getMainExecutor(this@MainActivity)
            val prompt = BiometricPrompt(
                this@MainActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authenticatedSession = activeSession ?: return
                        val authenticatedAction = activeAction ?: return
                        clearActiveAuthentication()
                        model.completeBiometric(authenticatedAction, authenticatedSession)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        val failedSession = activeSession ?: return
                        clearActiveAuthentication()
                        model.biometricFailed(failedSession, "biometric_error_$errorCode")
                    }
                },
            )
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(
                    if (action == BiometricAction.SIGN_TRANSFER) {
                        "Authorize exact transfer"
                    } else {
                        "Unlock public authority"
                    },
                )
                .setSubtitle("MindChain device-bound wallet")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .setConfirmationRequired(action == BiometricAction.SIGN_TRANSFER)
                .build()
            try {
                prompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(session.cryptoOperation()),
                )
            } catch (error: RuntimeException) {
                clearActiveAuthentication()
                model.biometricFailed(session, "biometric_prompt_unavailable")
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            activeSession?.discard()
            clearActiveAuthentication()
        }
    }

    private fun clearActiveAuthentication() {
        activeSession = null
        activeAction = null
    }
}
