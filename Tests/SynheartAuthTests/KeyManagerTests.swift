import XCTest
import CryptoKit
@testable import SynheartAuth

final class KeyManagerTests: XCTestCase {
    private var keyManager: MockKeyManager!
    private let appId = "com.test.app"

    override func setUp() {
        super.setUp()
        keyManager = MockKeyManager()
    }

    // MARK: - Key Generation

    func testGenerateKeyPairReturnsPublicKey() throws {
        let publicKeyData = try keyManager.generateKeyPair(appId: appId)
        // X9.62 uncompressed P-256 public key = 65 bytes (0x04 + 32 + 32)
        XCTAssertEqual(publicKeyData.count, 65)
        XCTAssertEqual(publicKeyData[0], 0x04) // uncompressed point prefix
    }

    func testHasKeyAfterGeneration() throws {
        XCTAssertFalse(keyManager.hasKey(appId: appId))
        _ = try keyManager.generateKeyPair(appId: appId)
        XCTAssertTrue(keyManager.hasKey(appId: appId))
    }

    // MARK: - Signing

    func testSignAndVerifyRoundTrip() throws {
        let publicKeyData = try keyManager.generateKeyPair(appId: appId)
        let message = Data("test message".utf8)

        let signatureData = try keyManager.sign(data: message, appId: appId)

        // Verify using CryptoKit
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSignWithoutKeyThrowsKeyInvalidated() {
        XCTAssertThrowsError(try keyManager.sign(data: Data("test".utf8), appId: appId)) { error in
            XCTAssertEqual(error as? SynheartAuthError, .keyInvalidated)
        }
    }

    // MARK: - Key Rotation

    func testKeyRotationPromote() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        let nextPublicKey = try keyManager.generateNextKeyPair(appId: appId)
        try keyManager.promoteNextKey(appId: appId)

        // Sign with the promoted key and verify against next public key
        let message = Data("rotation test".utf8)
        let signatureData = try keyManager.sign(data: message, appId: appId)

        let publicKey = try P256.Signing.PublicKey(x963Representation: nextPublicKey)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testDeleteNextKeyCleanup() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        _ = try keyManager.generateNextKeyPair(appId: appId)
        keyManager.deleteNextKey(appId: appId)
        // Primary key should still work
        XCTAssertTrue(keyManager.hasKey(appId: appId))
    }

    // MARK: - Delete

    func testDeleteKeyRemovesAll() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        keyManager.deleteKey(appId: appId)
        XCTAssertFalse(keyManager.hasKey(appId: appId))
    }

    // MARK: - Failure Simulation

    func testGenerateFailure() {
        keyManager.generateShouldFail = true
        XCTAssertThrowsError(try keyManager.generateKeyPair(appId: appId))
    }

    func testSignFailure() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        keyManager.signShouldFail = true
        XCTAssertThrowsError(try keyManager.sign(data: Data("test".utf8), appId: appId)) { error in
            XCTAssertEqual(error as? SynheartAuthError, .keyInvalidated)
        }
    }
}
