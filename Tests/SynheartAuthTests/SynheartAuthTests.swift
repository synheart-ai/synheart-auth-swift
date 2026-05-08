import XCTest
@testable import SynheartAuth

final class SynheartAuthTests: XCTestCase {
    private var auth: SynheartAuth!
    private var keyManager: MockKeyManager!
    private var storage: MockStorageManager!
    private var network: MockAuthNetworkClient!
    private let appId = "com.test.app"

    override func setUp() {
        super.setUp()
        keyManager = MockKeyManager()
        storage = MockStorageManager()
        network = MockAuthNetworkClient()
        auth = SynheartAuth(keyManager: keyManager, storage: storage, network: network)
    }

    // MARK: - Registration

    func testIsRegisteredReturnsFalseInitially() {
        XCTAssertFalse(auth.isRegistered(appId: appId))
    }

    func testIsRegisteredReturnsTrueAfterRegistration() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-123",
            status: "ok"
        ))

        let result = try await auth.registerDevice(appId: appId)
        XCTAssertEqual(result.status, .success)
        XCTAssertTrue(auth.isRegistered(appId: appId))
    }

    // MARK: - Device ID

    func testGetDeviceIdReturnsNilBeforeRegistration() {
        XCTAssertNil(auth.getDeviceId(appId: appId))
    }

    func testGetDeviceIdAfterRegistration() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-abc",
            status: "ok"
        ))

        _ = try await auth.registerDevice(appId: appId)
        XCTAssertEqual(auth.getDeviceId(appId: appId), "device-abc")
    }

    // MARK: - Request Signing

    func testSignRequestAfterRegistration() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-123",
            status: "ok"
        ))

        _ = try await auth.registerDevice(appId: appId)

        let headers = try auth.signRequest(
            appId: appId,
            method: "POST",
            path: "/v1/data",
            bodyBytes: Data("{\"key\":\"value\"}".utf8)
        )

        XCTAssertEqual(headers.appId, appId)
        XCTAssertEqual(headers.deviceId, "device-123")
        XCTAssertFalse(headers.signature.isEmpty)
        XCTAssertEqual(headers.signatureVersion, "1")
        XCTAssertEqual(headers.dictionary.count, 6)
    }

    func testSignRequestFailsWhenNotRegistered() {
        XCTAssertThrowsError(try auth.signRequest(
            appId: appId,
            method: "GET",
            path: "/v1/test"
        )) { error in
            XCTAssertEqual(error as? SynheartAuthError, .notRegistered)
        }
    }

    // MARK: - Reset

    func testResetDeviceIdentity() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-123",
            status: "ok"
        ))

        _ = try await auth.registerDevice(appId: appId)
        XCTAssertTrue(auth.isRegistered(appId: appId))

        auth.resetDeviceIdentity(appId: appId)

        XCTAssertFalse(auth.isRegistered(appId: appId))
        XCTAssertNil(auth.getDeviceId(appId: appId))
        XCTAssertFalse(keyManager.hasKey(appId: appId))
    }

    // MARK: - Clock Skew

    func testCorrectClockSkew() {
        let serverTime = Date().timeIntervalSince1970 + 30
        auth.correctClockSkew(serverTimestamp: serverTime)
        // Just verifying it doesn't crash — the correction is tested in ClockSkewTrackerTests
    }

    // MARK: - Key Rotation

    func testRotateKeyAfterRegistration() async throws {
        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-123",
            status: "ok"
        ))
        network.rotateResult = .success(RotateKeyResponse(status: "ok"))

        _ = try await auth.registerDevice(appId: appId)
        let result = try await auth.rotateKey(appId: appId)

        XCTAssertEqual(result.status, .success)
        XCTAssertTrue(auth.isRegistered(appId: appId))
    }

    func testRotateKeyFailsWhenNotRegistered() async {
        do {
            _ = try await auth.rotateKey(appId: appId)
            XCTFail("Should have thrown")
        } catch {
            XCTAssertEqual(error as? SynheartAuthError, .notRegistered)
        }
    }

    // MARK: - Multiple Apps

    func testMultipleAppsIsolated() async throws {
        let app1 = "com.test.app1"
        let app2 = "com.test.app2"

        network.challengeResult = .success(ChallengeResponse(
            challenge: "challenge",
            expiresAt: "2026-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(
            deviceId: "device-app1",
            status: "ok"
        ))

        _ = try await auth.registerDevice(appId: app1)

        XCTAssertTrue(auth.isRegistered(appId: app1))
        XCTAssertFalse(auth.isRegistered(appId: app2))
        XCTAssertEqual(auth.getDeviceId(appId: app1), "device-app1")
        XCTAssertNil(auth.getDeviceId(appId: app2))
    }
}
