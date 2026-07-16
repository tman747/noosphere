import Combine
import Foundation
import LocalAuthentication
import MindChainWalletSecurity

@MainActor
final class WalletViewModel: ObservableObject {
    @Published var walletID = "primary" {
        didSet {
            if walletID != oldValue {
                walletSealed = presenceMarker()
                authority = nil
                pendingTransfer = nil
                transferReview = nil
            }
        }
    }
    @Published var account = "0"
    @Published var index = "0"
    @Published var seedHex = ""
    @Published var requireBiometry = true
    @Published private(set) var walletSealed = false
    @Published private(set) var nodeSnapshot: MobileNodeSnapshot?
    @Published private(set) var quorumEndpoints: UInt32?
    @Published private(set) var quorumClusters: UInt32?
    @Published private(set) var authority: DerivedAuthority?
    @Published var transactionSpec = "" {
        didSet {
            if transactionSpec != oldValue {
                pendingTransfer = nil
                transferReview = nil
                submissionResult = nil
            }
        }
    }
    @Published private(set) var transferReview: TransferReview?
    @Published private(set) var submissionResult: SubmissionResult?
    @Published private(set) var busyLabel: String?
    @Published private(set) var notice: String?
    @Published private(set) var errorCode: String?

    let networkEnabled: Bool
    let networkReason: String?
    let chainID: String
    let genesisHash: String

    private let configuration: MindChainNetworkConfiguration?
    private let vault: SecureEnclaveSeedVault?
    private let core: MobileWalletCore?
    private let client: MindChainWalletAPIClient?
    private var pendingTransfer: PendingTransfer?

    init() {
        do {
            let configuration = try MindChainNetworkConfiguration.load()
            let core = try MobileWalletCore(
                chainId: configuration.chainID,
                genesisHash: configuration.genesisHash,
                apiVersion: configuration.apiVersion,
                maximumFreshnessMs: configuration.maximumFreshnessMilliseconds
            )
            let vault = try SecureEnclaveSeedVault(chainID: configuration.chainIDData())
            self.configuration = configuration
            self.core = core
            self.vault = vault
            self.client = configuration.enabled
                ? try MindChainWalletAPIClient(configuration: configuration)
                : nil
            self.networkEnabled = configuration.enabled
            self.networkReason = configuration.disabledReason
            self.chainID = configuration.chainID
            self.genesisHash = configuration.genesisHash
        } catch {
            self.configuration = nil
            self.core = nil
            self.vault = nil
            self.client = nil
            self.networkEnabled = false
            self.networkReason = "malformed_mobile_network_profile"
            self.chainID = String(repeating: "0", count: 64)
            self.genesisHash = String(repeating: "0", count: 64)
            self.errorCode = "malformed_mobile_network_profile"
        }
        self.walletSealed = presenceMarker()
    }

    func dismissMessage() {
        notice = nil
        errorCode = nil
    }

    func synchronizeNode() {
        guard busyLabel == nil else { return }
        perform("Synchronizing finalized checkpoint") { [self] in
            let configuration = try requireConfiguration().requireEnabled()
            let outcome = try await MobileNodeRuntime.shared.synchronize(configuration: configuration)
            apply(outcome)
            notice = outcome.advanced ? "Finalized checkpoint advanced" : "Finalized checkpoint verified"
        }
    }

    func importSeed() {
        guard busyLabel == nil else { return }
        let walletID = walletID
        let requiresBiometry = requireBiometry
        let raw = seedHex
        seedHex = ""
        perform("Sealing seed in Secure Enclave") { [self] in
            guard var seed = Data(strictHex: raw), (16...128).contains(seed.count) else {
                throw AppError.invalidSeedHex
            }
            defer { seed.resetBytes(in: 0..<seed.count) }
            try requireVault().importSeed(
                seed,
                walletID: walletID,
                requireBiometry: requiresBiometry
            )
            setPresenceMarker(true, walletID: walletID)
            walletSealed = true
            authority = nil
            pendingTransfer = nil
            transferReview = nil
            submissionResult = nil
            notice = "Seed sealed by Secure Enclave"
        }
    }

    func deleteWallet() {
        guard busyLabel == nil else { return }
        let walletID = walletID
        perform("Deleting device-bound wallet") { [self] in
            try requireVault().delete(walletID: walletID)
            setPresenceMarker(false, walletID: walletID)
            walletSealed = false
            authority = nil
            pendingTransfer = nil
            transferReview = nil
            submissionResult = nil
            notice = "Device-bound wallet deleted"
        }
    }

    func deriveAuthority() {
        guard busyLabel == nil else { return }
        let walletID = walletID
        perform("Authenticating device-bound authority") { [self] in
            let account = try parseUInt32(account, error: .invalidAccount)
            let index = try parseUInt32(index, error: .invalidIndex)
            let context = LAContext()
            context.localizedReason = "Derive the public MindChain wallet authority"
            let derived = try requireVault().withSeed(walletID: walletID, context: context) { pointer in
                var seed = Data(pointer)
                defer { seed.resetBytes(in: 0..<seed.count) }
                return try requireCore().deriveAuthority(
                    seed: seed,
                    purpose: "sign",
                    suite: nil,
                    account: account,
                    index: index
                )
            }
            authority = derived
            notice = "Public authority derived"
        }
    }

    func reviewTransfer() {
        guard busyLabel == nil else { return }
        let specification = transactionSpec
        perform("Building quorum-verified review") { [self] in
            let configuration = try requireConfiguration().requireEnabled()
            let outcome = try await MobileNodeRuntime.shared.synchronize(configuration: configuration)
            let material = try await requireClient().fetchTransferMaterial(
                transactionSpecJSON: specification,
                trustedSnapshot: outcome.snapshot
            )
            let review = try requireCore().reviewTransfer(
                transactionSpecJson: specification,
                statusJson: material.statusJSON,
                notesJson: material.notesJSON
            )
            pendingTransfer = PendingTransfer(
                specification: specification,
                material: material,
                review: review
            )
            transferReview = review
            submissionResult = nil
            apply(outcome)
            notice = "Review locked to \(shortHash(review.reviewId))"
        }
    }

    func signAndSubmit() {
        guard busyLabel == nil else { return }
        let walletID = walletID
        perform("Revalidating, authenticating and signing") { [self] in
            guard let prior = pendingTransfer else { throw AppError.reviewRequired }
            let account = try parseUInt32(account, error: .invalidAccount)
            let index = try parseUInt32(index, error: .invalidIndex)
            let configuration = try requireConfiguration().requireEnabled()
            let outcome = try await MobileNodeRuntime.shared.synchronize(configuration: configuration)
            let material = try await requireClient().fetchTransferMaterial(
                transactionSpecJSON: prior.specification,
                trustedSnapshot: outcome.snapshot
            )
            let refreshed = try requireCore().reviewTransfer(
                transactionSpecJson: prior.specification,
                statusJson: material.statusJSON,
                notesJson: material.notesJSON
            )
            apply(outcome)
            guard refreshed.reviewId == prior.review.reviewId else {
                pendingTransfer = PendingTransfer(
                    specification: prior.specification,
                    material: material,
                    review: refreshed
                )
                transferReview = refreshed
                throw AppError.reviewChanged
            }

            let context = LAContext()
            context.localizedReason = "Sign the exact reviewed MindChain transfer"
            let signed = try requireVault().withSeed(walletID: walletID, context: context) { pointer in
                var seed = Data(pointer)
                defer { seed.resetBytes(in: 0..<seed.count) }
                return try requireCore().signReviewedTransfer(
                    seed: seed,
                    account: account,
                    index: index,
                    signerScope: 0,
                    transactionSpecJson: prior.specification,
                    statusJson: material.statusJSON,
                    notesJson: material.notesJSON,
                    expectedReviewId: refreshed.reviewId
                )
            }
            let response = try await requireClient().submit(
                signed.submissionJson,
                trustedSnapshot: outcome.snapshot
            )
            let result = try requireCore().validateSubmissionResponse(
                expectedTxid: signed.txid,
                responseJson: response
            )
            pendingTransfer = nil
            transferReview = nil
            submissionResult = result
            notice = "Transaction accepted into \(result.state)"
        }
    }

    private func perform(_ label: String, operation: @escaping @MainActor () async throws -> Void) {
        busyLabel = label
        errorCode = nil
        notice = nil
        Task { @MainActor in
            defer { busyLabel = nil }
            do {
                try await operation()
            } catch {
                errorCode = Self.code(for: error)
            }
        }
    }

    private func apply(_ outcome: MobileNodeSyncOutcome) {
        nodeSnapshot = outcome.snapshot
        quorumEndpoints = outcome.quorumEndpoints
        quorumClusters = outcome.quorumControlClusters
    }

    private func requireConfiguration() throws -> MindChainNetworkConfiguration {
        guard let configuration else { throw AppError.unavailable }
        return configuration
    }

    private func requireVault() throws -> SecureEnclaveSeedVault {
        guard let vault else { throw AppError.unavailable }
        return vault
    }

    private func requireCore() throws -> MobileWalletCore {
        guard let core else { throw AppError.unavailable }
        return core
    }

    private func requireClient() throws -> MindChainWalletAPIClient {
        guard let client else { throw AppError.networkDisabled }
        return client
    }

    private func presenceMarker(walletID: String? = nil) -> Bool {
        let wallet = walletID ?? self.walletID
        return UserDefaults.standard.bool(forKey: "mindchain.secure-enclave.\(chainID).\(wallet)")
    }

    private func setPresenceMarker(_ present: Bool, walletID: String) {
        let key = "mindchain.secure-enclave.\(chainID).\(walletID)"
        if present {
            UserDefaults.standard.set(true, forKey: key)
        } else {
            UserDefaults.standard.removeObject(forKey: key)
        }
    }

    private struct PendingTransfer {
        let specification: String
        let material: WalletTransferMaterial
        let review: TransferReview
    }

    private enum AppError: Error {
        case unavailable
        case networkDisabled
        case invalidSeedHex
        case invalidAccount
        case invalidIndex
        case reviewRequired
        case reviewChanged
    }

    private func parseUInt32(_ value: String, error: AppError) throws -> UInt32 {
        guard let number = UInt32(value) else { throw error }
        return number
    }

    private func shortHash(_ value: String) -> String {
        guard value.count > 20 else { return value }
        return "\(value.prefix(8))…\(value.suffix(8))"
    }

    private static func code(for error: Error) -> String {
        switch error {
        case AppError.unavailable: return "wallet_runtime_unavailable"
        case AppError.networkDisabled: return "network_not_configured"
        case AppError.invalidSeedHex: return "invalid_seed_hex"
        case AppError.invalidAccount: return "invalid_account"
        case AppError.invalidIndex: return "invalid_index"
        case AppError.reviewRequired: return "transfer_review_required"
        case AppError.reviewChanged: return "review_changed_reconfirm"
        case SecureEnclaveSeedVault.VaultError.invalidChainID: return "invalid_chain_id"
        case SecureEnclaveSeedVault.VaultError.invalidWalletID: return "invalid_wallet_id"
        case SecureEnclaveSeedVault.VaultError.invalidSeed: return "invalid_seed"
        case SecureEnclaveSeedVault.VaultError.secureEnclaveUnavailable: return "secure_enclave_unavailable"
        case SecureEnclaveSeedVault.VaultError.keychainFailure: return "keychain_failure"
        case SecureEnclaveSeedVault.VaultError.malformedEnvelope: return "malformed_envelope"
        case SecureEnclaveSeedVault.VaultError.authenticationFailed: return "authentication_failed"
        case MindChainNetworkConfiguration.ConfigurationError.disabled(let reason):
            return sanitize(reason)
        case MindChainNetworkConfiguration.ConfigurationError.missingProfile: return "missing_network_profile"
        case MindChainNetworkConfiguration.ConfigurationError.malformedProfile: return "malformed_network_profile"
        case MindChainNetworkConfiguration.ConfigurationError.invalidIdentity: return "invalid_network_identity"
        case MindChainNetworkConfiguration.ConfigurationError.invalidBoundary: return "invalid_network_boundary"
        case MindChainNetworkConfiguration.ConfigurationError.invalidEndpoint: return "invalid_network_endpoint"
        case WalletAPIError.invalidRequest: return "wallet_api_invalid_request"
        case WalletAPIError.invalidResponse: return "wallet_api_invalid_response"
        case WalletAPIError.responseTooLarge: return "wallet_api_response_too_large"
        case WalletAPIError.quorumUnavailable: return "wallet_api_quorum_unavailable"
        case WalletAPIError.submissionRejected: return "submission_rejected"
        case WalletAPIError.transportUnavailable: return "wallet_api_transport_unavailable"
        case MindChainMobileNodeError.invalidEndpoint: return "invalid_mobile_node_endpoint"
        case MindChainMobileNodeError.invalidEndpointSet: return "invalid_mobile_node_endpoint_set"
        case MindChainMobileNodeError.transportUnavailable: return "mobile_node_transport_unavailable"
        case MindChainMobileNodeError.invalidResponse: return "mobile_node_invalid_response"
        case MindChainMobileNodeError.responseTooLarge: return "mobile_node_response_too_large"
        case MindChainMobileNodeError.stateUnavailable: return "mobile_node_state_unavailable"
        default: return "operation_failed"
        }
    }

    private static func sanitize(_ value: String) -> String {
        let code = value.lowercased().replacingOccurrences(of: "-", with: "_")
        guard code.range(of: "^[a-z0-9_]{1,96}$", options: .regularExpression) != nil else {
            return "operation_failed"
        }
        return code
    }
}
