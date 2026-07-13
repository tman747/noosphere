import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Device-bound custody for the Ed25519 master seed used by the shared Rust
/// wallet core. The Secure Enclave P-256 key unwraps the seed; it never acts as
/// a MindChain consensus signer.
@available(iOS 16.0, macOS 13.0, *)
public final class SecureEnclaveSeedVault {
    public enum VaultError: Error, Equatable {
        case invalidWalletID
        case invalidSeed
        case secureEnclaveUnavailable
        case keychainFailure(OSStatus)
        case malformedEnvelope
        case authenticationFailed
    }

    private struct Envelope: Codable {
        let version: UInt8
        let ephemeralPublicKey: Data
        let nonce: Data
        let ciphertextAndTag: Data
    }

    private let service = "org.noosphere.mindchain-wallet.mobile.seed.v1"
    private let keyService = "org.noosphere.mindchain-wallet.mobile.enclave.v1"
    private let chainID: Data

    public init(chainID: Data) throws {
        guard chainID.count == 32 else { throw VaultError.malformedEnvelope }
        self.chainID = chainID
    }

    /// Imports a seed under a wallet-scoped Secure Enclave wrapping key.
    /// `requireBiometry` controls whether every unwrap requires current
    /// biometric authentication or any enrolled device-owner authentication.
    public func importSeed(
        _ seed: Data,
        walletID: String,
        requireBiometry: Bool,
        context: LAContext? = nil
    ) throws {
        try validate(walletID: walletID)
        guard (16...128).contains(seed.count) else { throw VaultError.invalidSeed }

        let accessFlags: SecAccessControlCreateFlags = requireBiometry
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .userPresence]
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessFlags,
            nil
        ) else { throw VaultError.secureEnclaveUnavailable }

        let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false,
                accessControl: access,
                authenticationContext: context
            )
        } catch {
            throw VaultError.secureEnclaveUnavailable
        }

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let aad = associatedData(walletID: walletID)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("NOOS/IOS/SEED/SALT/V1".utf8),
            sharedInfo: aad,
            outputByteCount: 32
        )
        let box = try AES.GCM.seal(seed, using: wrappingKey, authenticating: aad)
        let combined = box.ciphertext + box.tag
        let envelope = Envelope(
            version: 1,
            ephemeralPublicKey: ephemeral.publicKey.x963Representation,
            nonce: Data(box.nonce),
            ciphertextAndTag: combined
        )
        try replaceKeychainItem(
            service: keyService,
            account: walletID,
            data: enclaveKey.dataRepresentation,
            accessControl: access
        )
        try replaceKeychainItem(
            service: service,
            account: walletID,
            data: try JSONEncoder().encode(envelope),
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    /// Returns seed bytes only to the native caller. The caller must pass them
    /// directly to the Rust signing operation and zeroize its buffer afterward.
    public func withSeed<T>(
        walletID: String,
        context: LAContext,
        operation: (Data) throws -> T
    ) throws -> T {
        try validate(walletID: walletID)
        context.localizedReason = "Authorize this MindChain wallet operation"
        let keyData = try readKeychainItem(service: keyService, account: walletID, context: context)
        let envelopeData = try readKeychainItem(service: service, account: walletID, context: context)
        let envelope = try JSONDecoder().decode(Envelope.self, from: envelopeData)
        guard envelope.version == 1, envelope.nonce.count == 12, envelope.ciphertextAndTag.count >= 16 else {
            throw VaultError.malformedEnvelope
        }

        do {
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: keyData,
                authenticationContext: context
            )
            let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: envelope.ephemeralPublicKey
            )
            let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let aad = associatedData(walletID: walletID)
            let wrappingKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("NOOS/IOS/SEED/SALT/V1".utf8),
                sharedInfo: aad,
                outputByteCount: 32
            )
            let ciphertext = envelope.ciphertextAndTag.dropLast(16)
            let tag = envelope.ciphertextAndTag.suffix(16)
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: envelope.nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            let seed = try AES.GCM.open(box, using: wrappingKey, authenticating: aad)
            guard (16...128).contains(seed.count) else { throw VaultError.invalidSeed }
            return try operation(seed)
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    public func delete(walletID: String) throws {
        try validate(walletID: walletID)
        try deleteKeychainItem(service: service, account: walletID)
        try deleteKeychainItem(service: keyService, account: walletID)
    }

    private func associatedData(walletID: String) -> Data {
        var data = Data("NOOS/IOS/SEED/ENVELOPE/V1".utf8)
        data.append(chainID)
        data.append(Data(walletID.utf8))
        return data
    }

    private func validate(walletID: String) throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")
        guard (3...64).contains(walletID.count),
              walletID.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw VaultError.invalidWalletID
        }
    }

    private func replaceKeychainItem(
        service: String,
        account: String,
        data: Data,
        accessible: CFString? = nil,
        accessControl: SecAccessControl? = nil
    ) throws {
        try? deleteKeychainItem(service: service, account: account)
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrSynchronizable: false
        ]
        if let accessControl { query[kSecAttrAccessControl] = accessControl }
        if let accessible { query[kSecAttrAccessible] = accessible }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.keychainFailure(status) }
    }

    private func readKeychainItem(
        service: String,
        account: String,
        context: LAContext
    ) throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw VaultError.keychainFailure(status)
        }
        return data
    }

    private func deleteKeychainItem(service: String, account: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.keychainFailure(status)
        }
    }
}
