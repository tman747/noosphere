import Foundation
import XCTest
@testable import MindChainWalletSecurity

@available(iOS 16.0, macOS 13.0, *)
final class SecureEnclaveSeedVaultTests: XCTestCase {
    func testRejectsInvalidChainIdentity() {
        XCTAssertThrowsError(try SecureEnclaveSeedVault(chainID: Data(repeating: 0, count: 31))) { error in
            XCTAssertEqual(error as? SecureEnclaveSeedVault.VaultError, .invalidChainID)
        }
    }

    func testRejectsInvalidWalletIdentifierBeforeKeychainAccess() throws {
        let vault = try SecureEnclaveSeedVault(chainID: Data(repeating: 7, count: 32))
        XCTAssertThrowsError(try vault.delete(walletID: "A wallet")) { error in
            XCTAssertEqual(error as? SecureEnclaveSeedVault.VaultError, .invalidWalletID)
        }
    }

    func testRejectsInvalidSeedBeforeSecureEnclaveAccess() throws {
        let vault = try SecureEnclaveSeedVault(chainID: Data(repeating: 9, count: 32))
        XCTAssertThrowsError(
            try vault.importSeed(Data(repeating: 1, count: 15), walletID: "primary", requireBiometry: true)
        ) { error in
            XCTAssertEqual(error as? SecureEnclaveSeedVault.VaultError, .invalidSeed)
        }
    }
}
