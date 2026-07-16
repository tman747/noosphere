package org.noosphere.wallet.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class StrongBoxSeedVaultContractTest {
    @Test
    fun rejectsInvalidChainIdentity() {
        val error = assertThrows(StrongBoxSeedVault.VaultException::class.java) {
            StrongBoxSeedVault(ApplicationProvider.getApplicationContext(), ByteArray(31))
        }
        assertEquals("invalid_chain_id", error.code)
    }

    @Test
    fun rejectsInvalidWalletIdentifierBeforeStorageAccess() {
        val vault = StrongBoxSeedVault(ApplicationProvider.getApplicationContext(), ByteArray(32))
        val error = assertThrows(StrongBoxSeedVault.VaultException::class.java) {
            vault.delete("A wallet")
        }
        assertEquals("invalid_wallet_id", error.code)
    }

    @Test
    fun rejectsInvalidSeedBeforeKeystoreAccess() {
        val vault = StrongBoxSeedVault(ApplicationProvider.getApplicationContext(), ByteArray(32))
        val error = assertThrows(StrongBoxSeedVault.VaultException::class.java) {
            vault.importSeed("primary", ByteArray(15))
        }
        assertEquals("invalid_seed", error.code)
    }
}
