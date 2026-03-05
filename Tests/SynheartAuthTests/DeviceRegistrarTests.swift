import XCTest
@testable import SynheartAuth

final class DeviceRegistrarTests: XCTestCase {
    private var keyManager: MockKeyManager!
    private var storage: MockStorageManager!
    private var network: MockAuthNetworkClient!
    private var registrar: DeviceRegistrar!
    private let appId = "com.test.app"

    override func setUp() {
        super.setUp()
        keyManager = MockKeyManager()
        storage = MockStorageManager()
        network = MockAuthNetworkClient()
        registrar = DeviceRegistrar(keyManager: keyManager, storage: storage, network: network)
    }

    // MARK: - Happy Path Registration

    func testRegisterHappyPath() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "test-challenge-abc",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-uuid-123",
            status: "ok"
        ))

        let result = try await registrar.register(appId: appId)

        XCTAssertEqual(result.status, .success)
        XCTAssertEqual(result.deviceId, "device-uuid-123")
        XCTAssertNil(result.error)

        // Verify state
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertEqual(storage.loadDeviceId(appId: appId), "device-uuid-123")

        // Verify network calls
        XCTAssertEqual(network.fetchChallengeCallCount, 1)
        XCTAssertEqual(network.registerCallCount, 1)

        // Verify register request contents
        XCTAssertEqual(network.lastRegisterRequest?.appId, appId)
        XCTAssertEqual(network.lastRegisterRequest?.challenge, "test-challenge-abc")
        XCTAssertNotNil(network.lastRegisterRequest?.publicKey)
        XCTAssertNotNil(network.lastRegisterRequest?.deviceMetadata)
    }

    // MARK: - Already Registered

    func testRegisterWhenAlreadyRegistered() async throws {
        try storage.saveState(.registered, appId: appId)
        try storage.saveDeviceId("existing-device", appId: appId)

        let result = try await registrar.register(appId: appId)

        XCTAssertEqual(result.status, .alreadyRegistered)
        XCTAssertEqual(result.deviceId, "existing-device")
        XCTAssertEqual(network.fetchChallengeCallCount, 0) // No network calls
    }

    // MARK: - Challenge Failure

    func testRegisterChallengeFails() async throws {
        network.challengeResult = .failure(SynheartAuthError.networkError("timeout"))

        let result = try await registrar.register(appId: appId)

        XCTAssertEqual(result.status, .failed)
        XCTAssertEqual(result.error, .networkError("timeout"))
        XCTAssertEqual(storage.loadState(appId: appId), .unregistered) // Reset
    }

    // MARK: - Server Registration Failure

    func testRegisterServerFails() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .failure(SynheartAuthError.serverError(
            code: "INVALID_ATTESTATION",
            message: "Attestation verification failed"
        ))

        let result = try await registrar.register(appId: appId)

        XCTAssertEqual(result.status, .failed)
        XCTAssertEqual(storage.loadState(appId: appId), .unregistered) // Reset
        // Key should be cleaned up
        XCTAssertFalse(keyManager.hasKey(appId: appId))
    }

    // MARK: - Key Rotation Happy Path

    func testRotateKeyHappyPath() async throws {
        // Setup: registered device
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveState(.registered, appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        network.rotateResult = .success(RotateKeyResponse(status: "ok"))

        let result = try await registrar.rotateKey(appId: appId)

        XCTAssertEqual(result.status, .success)
        XCTAssertNil(result.error)
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertEqual(network.rotateCallCount, 1)
    }

    // MARK: - Key Rotation Not Registered

    func testRotateKeyWhenNotRegistered() async throws {
        do {
            _ = try await registrar.rotateKey(appId: appId)
            XCTFail("Should have thrown")
        } catch {
            XCTAssertEqual(error as? SynheartAuthError, .notRegistered)
        }
    }

    // MARK: - Key Rotation Server Failure

    func testRotateKeyServerFails() async throws {
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveState(.registered, appId: appId)
        try storage.saveDeviceId("device-123", appId: appId)

        network.rotateResult = .failure(SynheartAuthError.serverError(
            code: "ROTATION_FAILED",
            message: "Server rejected"
        ))

        let result = try await registrar.rotateKey(appId: appId)

        XCTAssertEqual(result.status, .failed)
        // State should be restored to registered
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        // Primary key should still exist
        XCTAssertTrue(keyManager.hasKey(appId: appId))
    }
}
