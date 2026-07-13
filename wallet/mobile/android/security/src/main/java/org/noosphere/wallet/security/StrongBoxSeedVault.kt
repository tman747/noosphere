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
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * StrongBox-backed wrapping of the Ed25519 seed consumed by the shared Rust
 * wallet core. Plaintext is returned only to [withSeed], whose caller must
 * zeroize the supplied byte array after its synchronous signing operation.
 */
@RequiresApi(Build.VERSION_CODES.S)
class StrongBoxSeedVault(
    context: Context,
    chainId: ByteArray,
) {
    enum class TrustTier { STRONGBOX, HARDWARE_KEYSTORE }

    class VaultException(val code: String, cause: Throwable? = null) : Exception(code, cause)

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val chainId = chainId.copyOf()

    init {
        if (this.chainId.size != 32) throw VaultException("invalid_chain_id")
    }

    fun importSeed(
        walletId: String,
        seed: ByteArray,
        allowHardwareFallback: Boolean = false,
    ): TrustTier {
        validateWalletId(walletId)
        if (seed.size !in 16..128) throw VaultException("invalid_seed")
        val alias = alias(walletId)
        val keyStore = keyStore()
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

        val tier = try {
            generateWrappingKey(alias, strongBox = true)
            TrustTier.STRONGBOX
        } catch (error: StrongBoxUnavailableException) {
            if (!allowHardwareFallback) throw VaultException("strongbox_unavailable", error)
            generateWrappingKey(alias, strongBox = false)
            TrustTier.HARDWARE_KEYSTORE
        }
        attestKeyProtection(alias, requireStrongBox = tier == TrustTier.STRONGBOX)

        val wrappingPublic = keyStore.getCertificate(alias)?.publicKey
            ?: throw VaultException("keystore_unavailable")
        val ephemeral = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).apply {
            initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        }.generateKeyPair()
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(wrappingPublic, true)
            generateSecret()
        }
        val aad = associatedData(walletId)
        val key = hkdfSha256(shared, SALT, aad, 32)
        shared.fill(0)
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
        val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(seed)
        }
        key.fill(0)

        val envelope = JSONObject()
            .put("version", 1)
            .put("tier", tier.name)
            .put("ephemeral_public_key", encode(ephemeral.public.encoded))
            .put("nonce", encode(nonce))
            .put("ciphertext_and_tag", encode(ciphertext))
            .toString()
        if (!prefs.edit().putString(walletId, envelope).commit()) {
            keyStore.deleteEntry(alias)
            throw VaultException("storage_failure")
        }
        return tier
    }

    fun <T> withSeed(walletId: String, operation: (ByteArray) -> T): T {
        validateWalletId(walletId)
        val encoded = prefs.getString(walletId, null) ?: throw VaultException("wallet_not_found")
        val envelope = try { JSONObject(encoded) } catch (error: Exception) {
            throw VaultException("malformed_envelope", error)
        }
        if (envelope.optInt("version") != 1) throw VaultException("malformed_envelope")
        val wrappingPrivate = keyStore().getKey(alias(walletId), null) as? PrivateKey
            ?: throw VaultException("wallet_not_found")
        val ephemeralPublic = decodePublicKey(envelope.getString("ephemeral_public_key"))
        val shared = try {
            KeyAgreement.getInstance("ECDH").run {
                init(wrappingPrivate)
                doPhase(ephemeralPublic, true)
                generateSecret()
            }
        } catch (error: Exception) {
            throw VaultException("authentication_required", error)
        }
        val aad = associatedData(walletId)
        val key = hkdfSha256(shared, SALT, aad, 32)
        shared.fill(0)
        val seed = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, decode(envelope.getString("nonce"))),
                )
                updateAAD(aad)
                doFinal(decode(envelope.getString("ciphertext_and_tag")))
            }
        } catch (error: AEADBadTagException) {
            throw VaultException("vault_authentication_failed", error)
        } finally {
            key.fill(0)
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

    fun delete(walletId: String) {
        validateWalletId(walletId)
        keyStore().deleteEntry(alias(walletId))
        if (!prefs.edit().remove(walletId).commit()) throw VaultException("storage_failure")
    }

    fun trustTier(walletId: String): TrustTier {
        validateWalletId(walletId)
        val encoded = prefs.getString(walletId, null) ?: throw VaultException("wallet_not_found")
        return try {
            TrustTier.valueOf(JSONObject(encoded).getString("tier"))
        } catch (error: Exception) {
            throw VaultException("malformed_envelope", error)
        }
    }

    private fun generateWrappingKey(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
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

    private fun alias(walletId: String) = "org.noosphere.wallet.seed.v1.$walletId"

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun decodePublicKey(value: String): PublicKey = KeyFactory
        .getInstance(KeyProperties.KEY_ALGORITHM_EC)
        .generatePublic(X509EncodedKeySpec(decode(value)))

    companion object {
        private const val PREFERENCES = "mindchain_device_bound_seed_v1"
        private val WALLET_ID = Regex("^[a-z0-9_-]{3,64}$")
        private val DOMAIN = "NOOS/ANDROID/SEED/ENVELOPE/V1".toByteArray(Charsets.UTF_8)
        private val SALT = "NOOS/ANDROID/SEED/SALT/V1".toByteArray(Charsets.UTF_8)

        fun isStrongBoxAvailable(context: Context): Boolean =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
        private fun decode(value: String) = Base64.decode(value, Base64.NO_WRAP)

        private fun hkdfSha256(
            inputKeyMaterial: ByteArray,
            salt: ByteArray,
            info: ByteArray,
            length: Int,
        ): ByteArray {
            val extract = Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(salt, "HmacSHA256"))
                doFinal(inputKeyMaterial)
            }
            val output = ByteArray(length)
            var previous = ByteArray(0)
            var offset = 0
            var counter: Byte = 1
            while (offset < length) {
                previous = Mac.getInstance("HmacSHA256").run {
                    init(SecretKeySpec(extract, "HmacSHA256"))
                    update(previous)
                    update(info)
                    update(counter)
                    doFinal()
                }
                val copy = minOf(previous.size, length - offset)
                previous.copyInto(output, offset, 0, copy)
                offset += copy
                counter++
            }
            extract.fill(0)
            previous.fill(0)
            return output
        }
    }
}
