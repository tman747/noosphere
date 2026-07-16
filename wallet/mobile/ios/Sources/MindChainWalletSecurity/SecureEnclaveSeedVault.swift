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
        case invalidChainID
        case invalidWalletID
        case invalidSeed
        case secureEnclaveUnavailable
        case keychainFailure(OSStatus)
        case malformedEnvelope
        case authenticationFailed
    }

    /// One Keychain value owns both the Secure Enclave key representation and
    /// its encrypted seed envelope. SecItemUpdate replaces this record
    /// atomically, so an interrupted import cannot split two generations.
    private struct Record: Codable {
        let version: UInt8
        let enclavePrivateKey: Data
        let ephemeralPublicKey: Data
        let nonce: Data
        let ciphertextAndTag: Data
    }

    private let service = "org.noosphere.mindchain-wallet.mobile.seed.v2"
    private let chainID: Data

    public init(chainID: Data) throws {
        guard chainID.count == 32 else { throw VaultError.invalidChainID }
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

        do {
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
            let aad = associatedData(walletID: walletID)
            let wrappingKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("NOOS/IOS/SEED/SALT/V2".utf8),
                sharedInfo: aad,
                outputByteCount: 32
            )
            let box = try AES.GCM.seal(seed, using: wrappingKey, authenticating: aad)
            let record = Record(
                version: 2,
                enclavePrivateKey: enclaveKey.dataRepresentation,
                ephemeralPublicKey: ephemeral.publicKey.x963Representation,
                nonce: Data(box.nonce),
                ciphertextAndTag: box.ciphertext + box.tag
            )
            try upsertKeychainItem(
                account: walletID,
                data: try JSONEncoder().encode(record),
                accessControl: access,
                context: context
            )
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    /// Supplies an ephemeral pointer only for the synchronous Rust signing
    /// call. The backing Data is reset before this function returns or throws.
    /// The pointer must never be retained by the operation.
    public func withSeed<T>(
        walletID: String,
        context: LAContext,
        operation: (UnsafeRawBufferPointer) throws -> T
    ) throws -> T {
        try validate(walletID: walletID)
        context.localizedReason = "Authorize this MindChain wallet operation"
        let recordData = try readKeychainItem(account: walletID, context: context)
        let record: Record
        do {
            record = try JSONDecoder().decode(Record.self, from: recordData)
        } catch {
            throw VaultError.malformedEnvelope
        }
        guard record.version == 2,
              record.nonce.count == 12,
              record.ciphertextAndTag.count >= 16 else {
            throw VaultError.malformedEnvelope
        }

        do {
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: record.enclavePrivateKey,
                authenticationContext: context
            )
            let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: record.ephemeralPublicKey
            )
            let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let aad = associatedData(walletID: walletID)
            let wrappingKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("NOOS/IOS/SEED/SALT/V2".utf8),
                sharedInfo: aad,
                outputByteCount: 32
            )
            let ciphertext = record.ciphertextAndTag.dropLast(16)
            let tag = record.ciphertextAndTag.suffix(16)
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            var seed = try AES.GCM.open(box, using: wrappingKey, authenticating: aad)
            guard (16...128).contains(seed.count) else {
                seed.resetBytes(in: 0..<seed.count)
                throw VaultError.invalidSeed
            }
            defer { seed.resetBytes(in: 0..<seed.count) }
            return try seed.withUnsafeBytes { bytes in
                try operation(bytes)
            }
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    public func delete(walletID: String) throws {
        try validate(walletID: walletID)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: walletID
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.keychainFailure(status)
        }
    }

    private func associatedData(walletID: String) -> Data {
        var data = Data("NOOS/IOS/SEED/ENVELOPE/V2".utf8)
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

    private func upsertKeychainItem(
        account: String,
        data: Data,
        accessControl: SecAccessControl,
        context: LAContext?
    ) throws {
        var updateQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: false
        ]
        if let context { updateQuery[kSecUseAuthenticationContext] = context }
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessControl: accessControl
        ]
        var status = SecItemUpdate(
            updateQuery as CFDictionary,
            attributes as CFDictionary
        )
        if status == errSecItemNotFound {
            var addQuery = updateQuery
            addQuery[kSecValueData] = data
            addQuery[kSecAttrAccessControl] = accessControl
            status = SecItemAdd(addQuery as CFDictionary, nil)
            if status == errSecDuplicateItem {
                status = SecItemUpdate(
                    updateQuery as CFDictionary,
                    attributes as CFDictionary
                )
            }
        }
        guard status == errSecSuccess else {
            throw VaultError.keychainFailure(status)
        }
    }

    private func readKeychainItem(
        account: String,
        context: LAContext
    ) throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: false,
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
}
