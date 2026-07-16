package org.noosphere.wallet.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * StrongBox-backed wrapping of the Ed25519 seed consumed by the shared Rust
 * wallet core. Plaintext exists only inside [SeedAccessSession.complete] and
 * is zeroized immediately after the synchronous signing operation.
 */
@RequiresApi(Build.VERSION_CODES.S)
class StrongBoxSeedVault(
    context: Context,
    chainId: ByteArray,
) {
    enum class TrustTier { STRONGBOX, HARDWARE_KEYSTORE }

    class VaultException(val code: String, cause: Throwable? = null) : Exception(code, cause)

    private data class Envelope(
        val keyAlias: String,
        val tier: TrustTier,
        val wrappedContentKey: ByteArray,
        val nonce: ByteArray,
        val ciphertextAndTag: ByteArray,
    )

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val chainId = chainId.copyOf()

    init {
        if (this.chainId.size != 32) throw VaultException("invalid_chain_id")
    }

    /**
     * Atomically changes the active envelope: the old envelope and wrapping key
     * remain usable until the new key exists, its protection is attested, and
     * SharedPreferences durably commits the new envelope.
     */
    fun importSeed(
        walletId: String,
        seed: ByteArray,
        allowHardwareFallback: Boolean = false,
    ): TrustTier {
        validateWalletId(walletId)
        if (seed.size !in 16..128) throw VaultException("invalid_seed")
        val keyStore = keyStore()
        val newAlias = newAlias(walletId)
        try {
            val tier = try {
                generateWrappingKey(newAlias, strongBox = true)
                TrustTier.STRONGBOX
            } catch (error: StrongBoxUnavailableException) {
                runCatching { keyStore.deleteEntry(newAlias) }
                if (!allowHardwareFallback) throw VaultException("strongbox_unavailable", error)
                generateWrappingKey(newAlias, strongBox = false)
                TrustTier.HARDWARE_KEYSTORE
            }
            attestKeyProtection(newAlias, requireStrongBox = tier == TrustTier.STRONGBOX)

            val wrappingPublic = keyStore.getCertificate(newAlias)?.publicKey
                ?: throw VaultException("keystore_unavailable")
            val aad = associatedData(walletId)
            val contentKey = ByteArray(32).also(SecureRandom()::nextBytes)
            val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
            val (ciphertext, wrappedContentKey) = try {
                val encryptedSeed = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.ENCRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, nonce))
                    updateAAD(aad)
                    doFinal(seed)
                }
                val encryptedKey = rsaOaepCipher().run {
                    init(Cipher.ENCRYPT_MODE, wrappingPublic, OAEP_PARAMETERS)
                    doFinal(contentKey)
                }
                encryptedSeed to encryptedKey
            } finally {
                contentKey.fill(0)
            }
            val envelope = JSONObject()
                .put("version", ENVELOPE_VERSION)
                .put("key_alias", newAlias)
                .put("tier", tier.name)
                .put("wrapped_content_key", encode(wrappedContentKey))
                .put("nonce", encode(nonce))
                .put("ciphertext_and_tag", encode(ciphertext))
                .toString()
            if (!prefs.edit().putString(walletId, envelope).commit()) {
                throw VaultException("storage_failure")
            }

            // The durable envelope now references only newAlias. Retired keys
            // can no longer decrypt anything even if cleanup is interrupted.
            runCatching { deleteWalletAliases(keyStore, walletId, keep = newAlias) }
            return tier
        } catch (error: VaultException) {
            runCatching { keyStore.deleteEntry(newAlias) }
            throw error
        } catch (error: Exception) {
            runCatching { keyStore.deleteEntry(newAlias) }
            throw VaultException("vault_operation_failed", error)
        }
    }

    class SeedAccessSession internal constructor(
        private val unwrapCipher: Cipher,
        private val wrappedContentKey: ByteArray,
        private val aad: ByteArray,
        private val nonce: ByteArray,
        private val ciphertextAndTag: ByteArray,
    ) {
        private val consumed = AtomicBoolean(false)

        /**
         * The caller must wrap this exact operation in
         * BiometricPrompt.CryptoObject. Cipher-backed crypto objects work on
         * every supported API level.
         */
        fun cryptoOperation(): Cipher {
            if (consumed.get()) throw VaultException("seed_access_consumed")
            return unwrapCipher
        }

        fun discard() {
            consumed.set(true)
        }

        fun <T> complete(operation: (ByteArray) -> T): T {
            if (!consumed.compareAndSet(false, true)) {
                throw VaultException("seed_access_consumed")
            }
            val contentKey = try {
                unwrapCipher.doFinal(wrappedContentKey)
            } catch (error: Exception) {
                throw VaultException("authentication_required", error)
            }
            if (contentKey.size != 32) {
                contentKey.fill(0)
                throw VaultException("malformed_envelope")
            }
            val seed = try {
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(
                        Cipher.DECRYPT_MODE,
                        SecretKeySpec(contentKey, "AES"),
                        GCMParameterSpec(128, nonce),
                    )
                    updateAAD(aad)
                    doFinal(ciphertextAndTag)
                }
            } catch (error: AEADBadTagException) {
                throw VaultException("vault_authentication_failed", error)
            } finally {
                contentKey.fill(0)
            }
            if (seed.size !in 16..128) {
                seed.fill(0)
                throw VaultException("invalid_seed")
            }
            return try {
                operation(seed)
            } finally {
                seed.fill(0)
            }
        }
    }

    fun beginSeedAccess(walletId: String): SeedAccessSession {
        validateWalletId(walletId)
        val envelope = readEnvelope(walletId)
        val keyStore = keyStore()
        val wrappingPrivate = keyStore.getKey(envelope.keyAlias, null) as? PrivateKey
            ?: throw VaultException("wallet_not_found")
        val unwrapCipher = try {
            rsaOaepCipher().apply {
                init(Cipher.DECRYPT_MODE, wrappingPrivate, OAEP_PARAMETERS)
            }
        } catch (error: Exception) {
            throw VaultException("authentication_required", error)
        }
        runCatching { deleteWalletAliases(keyStore, walletId, keep = envelope.keyAlias) }
        return SeedAccessSession(
            unwrapCipher = unwrapCipher,
            wrappedContentKey = envelope.wrappedContentKey,
            aad = associatedData(walletId),
            nonce = envelope.nonce,
            ciphertextAndTag = envelope.ciphertextAndTag,
        )
    }

    /**
     * Removes the durable envelope first, then every wallet-scoped key alias.
     * After the commit succeeds, an interrupted cleanup cannot recover a seed
     * because no ciphertext remains.
     */
    fun delete(walletId: String) {
        validateWalletId(walletId)
        if (!prefs.edit().remove(walletId).commit()) throw VaultException("storage_failure")
        try {
            deleteWalletAliases(keyStore(), walletId, keep = null)
        } catch (error: Exception) {
            throw VaultException("key_cleanup_failure", error)
        }
    }

    fun trustTier(walletId: String): TrustTier {
        validateWalletId(walletId)
        val envelope = readEnvelope(walletId)
        runCatching { deleteWalletAliases(keyStore(), walletId, keep = envelope.keyAlias) }
        return envelope.tier
    }

    private fun readEnvelope(walletId: String): Envelope {
        val encoded = prefs.getString(walletId, null) ?: throw VaultException("wallet_not_found")
        return try {
            val value = JSONObject(encoded)
            if (value.length() != 6 || value.getInt("version") != ENVELOPE_VERSION) {
                throw VaultException("malformed_envelope")
            }
            val keyAlias = value.getString("key_alias")
            if (!validAlias(walletId, keyAlias)) throw VaultException("malformed_envelope")
            val wrappedContentKey = decode(value.getString("wrapped_content_key"))
            val nonce = decode(value.getString("nonce"))
            val ciphertextAndTag = decode(value.getString("ciphertext_and_tag"))
            if (wrappedContentKey.size != RSA_WRAPPED_KEY_BYTES ||
                nonce.size != 12 || ciphertextAndTag.size !in 32..144
            ) {
                throw VaultException("malformed_envelope")
            }
            Envelope(
                keyAlias = keyAlias,
                tier = TrustTier.valueOf(value.getString("tier")),
                wrappedContentKey = wrappedContentKey,
                nonce = nonce,
                ciphertextAndTag = ciphertextAndTag,
            )
        } catch (error: VaultException) {
            throw error
        } catch (error: Exception) {
            throw VaultException("malformed_envelope", error)
        }
    }

    private fun generateWrappingKey(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(RSA_KEY_BITS)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun attestKeyProtection(alias: String, requireStrongBox: Boolean) {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw VaultException("keystore_unavailable")
        val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            .getKeySpec(privateKey, KeyInfo::class.java)
        if (info.securityLevel == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
            throw VaultException("hardware_keystore_unavailable")
        }
        if (requireStrongBox && info.securityLevel != KeyProperties.SECURITY_LEVEL_STRONGBOX) {
            throw VaultException("strongbox_unavailable")
        }
    }

    private fun associatedData(walletId: String): ByteArray =
        DOMAIN + chainId + walletId.toByteArray(Charsets.UTF_8)

    private fun validateWalletId(walletId: String) {
        if (!WALLET_ID.matches(walletId)) throw VaultException("invalid_wallet_id")
    }

    private fun newAlias(walletId: String): String {
        val generation = ByteArray(16).also(SecureRandom()::nextBytes)
        return walletAliasPrefix(walletId) +
            Base64.encodeToString(generation, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    private fun validAlias(walletId: String, value: String): Boolean {
        val prefix = walletAliasPrefix(walletId)
        return value.startsWith(prefix) &&
            ALIAS_GENERATION.matches(value.substring(prefix.length))
    }

    private fun walletAliasPrefix(walletId: String) = "$ALIAS_ROOT$walletId."

    private fun deleteWalletAliases(keyStore: KeyStore, walletId: String, keep: String?) {
        val prefix = walletAliasPrefix(walletId)
        val legacy = "$ALIAS_ROOT$walletId"
        val aliases = mutableListOf<String>()
        val names = keyStore.aliases()
        while (names.hasMoreElements()) {
            val candidate = names.nextElement()
            if ((candidate == legacy || candidate.startsWith(prefix)) && candidate != keep) {
                aliases += candidate
            }
        }
        aliases.forEach(keyStore::deleteEntry)
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }


    companion object {
        private const val ENVELOPE_VERSION = 3
        private const val RSA_KEY_BITS = 2048
        private const val RSA_WRAPPED_KEY_BYTES = RSA_KEY_BITS / 8
        private const val PREFERENCES = "mindchain_device_bound_seed_v1"
        private const val ALIAS_ROOT = "org.noosphere.wallet.seed.v1."
        private val WALLET_ID = Regex("^[a-z0-9_-]{3,64}$")
        private val ALIAS_GENERATION = Regex("^[A-Za-z0-9_-]{22}$")
        private val DOMAIN = "NOOS/ANDROID/SEED/ENVELOPE/V3".toByteArray(Charsets.UTF_8)
        private val OAEP_PARAMETERS = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )

        fun isStrongBoxAvailable(context: Context): Boolean =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        private fun rsaOaepCipher(): Cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
        private fun decode(value: String) = Base64.decode(value, Base64.NO_WRAP)
    }
}
