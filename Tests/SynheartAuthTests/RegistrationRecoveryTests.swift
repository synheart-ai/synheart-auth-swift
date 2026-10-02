import XCTest
@testable import SynheartAuth

/// Registration / rotation interrupted by a dead process, and identities whose
/// signing key is gone. Both used to be permanent until `resetDeviceIdentity`:
/// a stale intermediate state made every `registerDevice` throw
/// `registrationInProgress`, and a lost key left the state `registered`, so
/// `registerDevice` answered `alreadyRegistered` forever.
final class RegistrationRecoveryTests: XCTestCase {
    private var keyManager: MockKeyManager!
    private var storage: MockStorageManager!
    private var network: MockAuthNetworkClient!
    private var auth: SynheartAuth!
    /// Unique per test: `OperationClaims` is process-wide.
    private var appId: String!

    override func setUp() {
        super.setUp()
        makeFixture()
    }

    private func makeFixture() {
        appId = "com.test.recovery.\(UUID().uuidString)"
        keyManager = MockKeyManager()
        storage = MockStorageManager()
        network = MockAuthNetworkClient()
        network.challengeResult = .success(ChallengeResponse(
            challenge: "fresh-challenge",
            expiresAt: "2099-12-31T23:59:59Z"
        ))
        network.registerResult = .success(RegisterResponse(deviceId: "device-new", status: "ok"))
        network.rotateResult = .success(RotateKeyResponse(status: "ok"))
        auth = SynheartAuth(keyManager: keyManager, storage: storage, network: network)
    }

    /// A new SDK instance over the same Keychain — what the next app launch sees.
    private func relaunch() -> SynheartAuth {
        SynheartAuth(keyManager: keyManager, storage: storage, network: network)
    }

    private func pendingKeys() -> [String] {
        storage.loadMetadata(appId: appId).keys.filter { $0.hasPrefix("pending_") }.sorted()
    }

    // MARK: - Interrupted registration (state left by a killed process)

    /// 0.1.2 wrote no pending-operation marker: only the state and maybe a key.
    func testRecoversFromEachIntermediateStateWithoutMarker() async throws {
        for state in [DeviceAuthState.challengeReceived, .keyReady, .registering] {
            makeFixture()
            let stalePublicKey = try keyManager.generateKeyPair(appId: appId)
            try storage.saveState(state, appId: appId)

            let result = try await relaunch().registerDevice(appId: appId)

            XCTAssertEqual(result.status, .success, "state \(state)")
            XCTAssertEqual(result.deviceId, "device-new", "state \(state)")
            XCTAssertEqual(storage.loadState(appId: appId), .registered, "state \(state)")
            XCTAssertEqual(network.fetchChallengeCallCount, 1, "fresh challenge for \(state)")
            // A fresh key, not the one from the abandoned attempt.
            let sentKey = try XCTUnwrap(network.lastRegisterRequest?.publicKey)
            XCTAssertNotEqual(sentKey, stalePublicKey.base64EncodedString(), "state \(state)")
            XCTAssertTrue(keyManager.hasKey(appId: appId))
            XCTAssertEqual(pendingKeys(), [], "marker cleared for \(state)")
        }
    }

    /// The marker written by this version records the state to return to.
    func testInterruptedReRegistrationReturnsToKeyInvalidAndReusesDeviceId() async throws {
        try storage.saveDeviceId("device-old", appId: appId)
        try storage.saveMetadata([
            PendingOperation.opKey: "register",
            PendingOperation.priorStateKey: "keyInvalid",
            PendingOperation.startedAtKey: "2026-10-01T00:00:00Z",
        ], appId: appId)
        _ = try keyManager.generateKeyPair(appId: appId)
        try storage.saveState(.registering, appId: appId)

        // Recovery alone: back to keyInvalid, abandoned key deleted.
        let registrar = DeviceRegistrar(keyManager: keyManager, storage: storage, network: network)
        XCTAssertTrue(OperationClaims.claim(appId))
        try registrar.recoverInterruptedOperation(appId: appId)
        OperationClaims.release(appId)
        XCTAssertEqual(storage.loadState(appId: appId), .keyInvalid)
        XCTAssertFalse(keyManager.hasKey(appId: appId))
        XCTAssertEqual(pendingKeys(), [])

        let result = try await relaunch().registerDevice(appId: appId)
        XCTAssertEqual(result.status, .success)
        XCTAssertEqual(network.lastRegisterRequest?.deviceId, "device-old")
    }

    /// A registration genuinely parked in `registering`, whose process then
    /// dies: the claim vanishes with the process, the Keychain state stays.
    func testRecoversRegistrationParkedInRegisteringAfterProcessDeath() async throws {
        let parked = expectation(description: "first registration reached the server call")
        let stuckNetwork = MockAuthNetworkClient()
        stuckNetwork.challengeResult = network.challengeResult
        stuckNetwork.registerResult = network.registerResult
        stuckNetwork.beforeRegister = {
            parked.fulfill()
            try? await Task.sleep(nanoseconds: 3_600 * 1_000_000_000) // never answers
        }
        let firstLaunch = SynheartAuth(keyManager: keyManager, storage: storage, network: stuckNetwork)
        let appId = self.appId!
        let dead = Task { try await firstLaunch.registerDevice(appId: appId) }
        await fulfillment(of: [parked], timeout: 5)
        XCTAssertEqual(storage.loadState(appId: appId), .registering)
        XCTAssertEqual(storage.loadMetadata(appId: appId)[PendingOperation.opKey], "register")

        // Still the same process: a second registration must be refused.
        do {
            _ = try await relaunch().registerDevice(appId: appId)
            XCTFail("concurrent registration must be refused")
        } catch {
            XCTAssertEqual(error as? SynheartAuthError, .registrationInProgress)
        }

        // Simulate the process dying: the in-memory claim is gone.
        OperationClaims.release(appId)

        let result = try await relaunch().registerDevice(appId: appId)
        XCTAssertEqual(result.status, .success)
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertEqual(network.registerCallCount, 1)
        XCTAssertEqual(pendingKeys(), [])
        dead.cancel() // the "dead" task's own cleanup is irrelevant here
    }

    func testConcurrentRegistrationsInOneProcessAreSerialized() async throws {
        let gate = expectation(description: "first registration in flight")
        network.beforeRegister = {
            gate.fulfill()
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        let appId = self.appId!
        let first = Task { [auth] in try await auth!.registerDevice(appId: appId) }
        await fulfillment(of: [gate], timeout: 5)

        // Even a freshly configured instance shares the in-flight claim.
        do {
            _ = try await relaunch().registerDevice(appId: appId)
            XCTFail("second registration must be refused while the first runs")
        } catch {
            XCTAssertEqual(error as? SynheartAuthError, .registrationInProgress)
        }

        let firstResult = try await first.value
        XCTAssertEqual(firstResult.status, .success)
        XCTAssertEqual(network.registerCallCount, 1)

        let again = try await auth.registerDevice(appId: appId)
        XCTAssertEqual(again.status, .alreadyRegistered)
    }

    // MARK: - Interrupted rotation

    private func makeRegistered() async throws {
        let result = try await auth.registerDevice(appId: appId)
        XCTAssertEqual(result.status, .success)
    }

    /// Old key and `_next` both present: the server may not have committed.
    /// Keep the confirmed key, drop `_next`. (0.1.2 state: no marker.)
    func testInterruptedRotationKeepsConfirmedKey() async throws {
        try await makeRegistered()
        let before = try auth.signRequest(appId: appId, method: "GET", path: "/x")
        _ = try keyManager.generateNextKeyPair(appId: appId)
        try storage.saveState(.registering, appId: appId)

        XCTAssertFalse(relaunch().isRegistered(appId: appId))
        let result = try await relaunch().registerDevice(appId: appId)

        XCTAssertEqual(result.status, .alreadyRegistered)
        XCTAssertEqual(result.deviceId, "device-new")
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertEqual(keyManager.nextKeyPresence(appId: appId), .absent)
        XCTAssertEqual(network.registerCallCount, 1, "no re-registration")
        XCTAssertEqual(before.deviceId, try auth.signRequest(appId: appId, method: "GET", path: "/x").deviceId)
    }

    /// Only `_next` left: the old key was deleted by a promotion that the
    /// server had already confirmed. Finish it.
    func testInterruptedPromotionIsCompleted() async throws {
        try await makeRegistered()
        _ = try keyManager.generateNextKeyPair(appId: appId)
        try storage.saveMetadata([PendingOperation.opKey: "rotate"], appId: appId)
        try storage.saveState(.registering, appId: appId)
        keyManager.simulateKeyLoss(appId: appId) // promotion step 1 ran

        let result = try await relaunch().rotateKey(appId: appId)

        XCTAssertEqual(result.status, .success, "rotation works again after recovery")
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertTrue(keyManager.hasKey(appId: appId))
        XCTAssertEqual(pendingKeys(), [])
    }

    func testInterruptedRotationWithNoKeyLeftBecomesKeyInvalidAndReRegisters() async throws {
        try await makeRegistered()
        try storage.saveMetadata([PendingOperation.opKey: "rotate"], appId: appId)
        try storage.saveState(.registering, appId: appId)
        keyManager.deleteKey(appId: appId)

        let result = try await relaunch().registerDevice(appId: appId)

        XCTAssertEqual(result.status, .success)
        XCTAssertEqual(network.registerCallCount, 2)
        XCTAssertEqual(network.lastRegisterRequest?.deviceId, "device-new", "device id reused")
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
    }

    func testRecoveryLeavesStateAloneWhenKeychainIsUnreadable() async throws {
        try await makeRegistered()
        _ = try keyManager.generateNextKeyPair(appId: appId)
        try storage.saveState(.registering, appId: appId)
        keyManager.presenceUnavailableStatus = errSecInteractionNotAllowed

        do {
            _ = try await relaunch().rotateKey(appId: appId)
            XCTFail("expected keychainError")
        } catch {
            XCTAssertEqual(error as? SynheartAuthError, .keychainError(errSecInteractionNotAllowed))
        }
        XCTAssertEqual(storage.loadState(appId: appId), .registering, "untouched for a later attempt")
        keyManager.presenceUnavailableStatus = nil
        XCTAssertEqual(keyManager.nextKeyPresence(appId: appId), .present, "nothing deleted")
    }

    // MARK: - Key invalidation

    func testLostKeyMovesToKeyInvalidAndRegisterDeviceReRegisters() async throws {
        try await makeRegistered()
        keyManager.simulateKeyLoss(appId: appId) // e.g. restored to a new device

        XCTAssertThrowsError(try auth.signRequest(appId: appId, method: "GET", path: "/x")) { error in
            XCTAssertEqual(error as? SynheartAuthError, .keyInvalidated)
        }
        XCTAssertEqual(storage.loadState(appId: appId), .keyInvalid)
        XCTAssertFalse(auth.isRegistered(appId: appId))

        network.registerResult = .success(RegisterResponse(deviceId: "device-new", status: "ok"))
        let result = try await auth.registerDevice(appId: appId)

        XCTAssertEqual(result.status, .success, "re-registers instead of alreadyRegistered")
        XCTAssertEqual(network.registerCallCount, 2)
        XCTAssertEqual(network.lastRegisterRequest?.deviceId, "device-new", "same device id")
        XCTAssertTrue(auth.isRegistered(appId: appId))
        XCTAssertNoThrow(try auth.signRequest(appId: appId, method: "GET", path: "/x"))
    }

    func testUnreadableKeyIsNotTreatedAsInvalidated() async throws {
        try await makeRegistered()
        keyManager.signKeychainUnavailableStatus = errSecInteractionNotAllowed

        XCTAssertThrowsError(try auth.signRequest(appId: appId, method: "GET", path: "/x")) { error in
            XCTAssertEqual(error as? SynheartAuthError, .keychainError(errSecInteractionNotAllowed))
        }
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
        XCTAssertTrue(keyManager.hasKey(appId: appId))
    }

    func testRotationWithLostKeyMovesToKeyInvalid() async throws {
        try await makeRegistered()
        keyManager.simulateKeyLoss(appId: appId)

        let rotation = try await auth.rotateKey(appId: appId)

        XCTAssertEqual(rotation.status, .failed)
        XCTAssertEqual(rotation.error, .keyInvalidated)
        XCTAssertEqual(storage.loadState(appId: appId), .keyInvalid)
        XCTAssertEqual(keyManager.nextKeyPresence(appId: appId), .absent)
        XCTAssertEqual(network.rotateCallCount, 0)

        let result = try await auth.registerDevice(appId: appId)
        XCTAssertEqual(result.status, .success)
    }

    func testSignWhileRegistrationInFlightDoesNotInvalidate() async throws {
        // A stored device id with no key, state owned by a live flow.
        try storage.saveDeviceId("device-old", appId: appId)
        try storage.saveState(.registered, appId: appId)
        XCTAssertTrue(OperationClaims.claim(appId))
        defer { OperationClaims.release(appId) }

        XCTAssertThrowsError(try auth.signRequest(appId: appId, method: "GET", path: "/x"))
        XCTAssertEqual(storage.loadState(appId: appId), .registered, "owner of the claim decides")
    }
}
