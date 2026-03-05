import XCTest
import CryptoKit
@testable import SynheartAuth

final class RequestSignerTests: XCTestCase {
    private var keyManager: MockKeyManager!
    private var storage: MockStorageManager!
    private var clockSkew: ClockSkewTracker!
    private var signer: RequestSigner!
    private let appId = "com.test.app"

    override func setUp() {
        super.setUp()
        keyManager = MockKeyManager()
        storage = MockStorageManager()
        clockSkew = ClockSkewTracker()
        signer = RequestSigner(keyManager: keyManager, storage: storage, clockSkew: clockSkew)
    }

    // MARK: - Message Format

    func testBuildMessageFormat() {
        let message = signer.buildMessage(
            method: "POST",
            path: "/v1/data",
            timestamp: "2026-01-01T00:00:00Z",
            bodyBytes: Data("{\"key\":\"value\"}".utf8)
        )
        let expected = "POST\n/v1/data\n2026-01-01T00:00:00Z\n{\"key\":\"value\"}"
        XCTAssertEqual(String(data: message, encoding: .utf8), expected)
    }

    func testBuildMessageWithNilBody() {
        let message = signer.buildMessage(
            method: "GET",
            path: "/v1/status",
            timestamp: "2026-01-01T00:00:00Z",
            bodyBytes: nil
        )
        let expected = "GET\n/v1/status\n2026-01-01T00:00:00Z\n"
        XCTAssertEqual(String(data: message, encoding: .utf8), expected)
    }

    func testBuildMessageUppercasesMethod() {
        let message = signer.buildMessage(
            method: "post",
            path: "/v1/data",
            timestamp: "2026-01-01T00:00:00Z",
            bodyBytes: nil
        )
        XCTAssertTrue(String(data: message, encoding: .utf8)!.hasPrefix("POST"))
    }

    // MARK: - Sign Happy Path

    func testSignReturnsAllHeaders() throws {
        // Setup: registered device with key
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        let headers = try signer.sign(
            appId: appId,
            method: "POST",
            path: "/v1/data",
            bodyBytes: Data("{\"test\":true}".utf8)
        )

        XCTAssertEqual(headers.appId, appId)
        XCTAssertEqual(headers.deviceId, "device-123")
        XCTAssertFalse(headers.signature.isEmpty)
        XCTAssertFalse(headers.timestamp.isEmpty)
        XCTAssertFalse(headers.nonce.isEmpty)
        XCTAssertEqual(headers.signatureVersion, "1")
    }

    func testSignedHeadersDictionaryHasAllKeys() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        let headers = try signer.sign(
            appId: appId,
            method: "GET",
            path: "/v1/status",
            bodyBytes: nil
        )

        let dict = headers.dictionary
        XCTAssertEqual(dict.count, 6)
        XCTAssertNotNil(dict["X-App-ID"])
        XCTAssertNotNil(dict["X-Device-ID"])
        XCTAssertNotNil(dict["X-Synheart-Signature"])
        XCTAssertNotNil(dict["X-Synheart-Timestamp"])
        XCTAssertNotNil(dict["X-Synheart-Nonce"])
        XCTAssertNotNil(dict["X-Synheart-Sig-Version"])
    }

    // MARK: - Signature Verification

    func testSignatureIsVerifiable() throws {
        let publicKeyData = try keyManager.generateKeyPair(appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        let headers = try signer.sign(
            appId: appId,
            method: "POST",
            path: "/v1/data",
            bodyBytes: Data("body".utf8)
        )

        // Reconstruct the message that was signed
        let message = signer.buildMessage(
            method: "POST",
            path: "/v1/data",
            timestamp: headers.timestamp,
            bodyBytes: Data("body".utf8)
        )

        // Verify signature
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
        let signatureData = Data(base64Encoded: headers.signature)!
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    // MARK: - Error Cases

    func testSignThrowsNotRegisteredWithoutDeviceId() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        // No device ID saved

        XCTAssertThrowsError(try signer.sign(
            appId: appId,
            method: "GET",
            path: "/v1/test",
            bodyBytes: nil
        )) { error in
            XCTAssertEqual(error as? SynheartAuthError, .notRegistered)
        }
    }

    func testSignThrowsKeyInvalidatedWithoutKey() throws {
        try storage.saveDeviceId("device-123", appId: appId)
        // No key generated

        XCTAssertThrowsError(try signer.sign(
            appId: appId,
            method: "GET",
            path: "/v1/test",
            bodyBytes: nil
        )) { error in
            XCTAssertEqual(error as? SynheartAuthError, .keyInvalidated)
        }
    }

    // MARK: - Nonce Uniqueness

    func testEachSignCallProducesUniqueNonce() throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        let h1 = try signer.sign(appId: appId, method: "GET", path: "/", bodyBytes: nil)
        let h2 = try signer.sign(appId: appId, method: "GET", path: "/", bodyBytes: nil)
        XCTAssertNotEqual(h1.nonce, h2.nonce)
    }
}
