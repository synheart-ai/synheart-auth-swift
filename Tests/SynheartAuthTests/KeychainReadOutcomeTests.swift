import XCTest
@testable import SynheartAuth

/// The absent / unavailable split behind the FFI Keychain reads. The C
/// callbacks can only return a pointer or NULL (or 1 / 0), so the SDK must
/// decide *before* that boundary which statuses are worth retrying and which
/// mean the item is really gone.
final class KeychainReadOutcomeTests: XCTestCase {

    func testLockedAndNotReadyStatusesAreTransient() {
        XCTAssertTrue(keychainStatusIsTransient(errSecInteractionNotAllowed))
        XCTAssertTrue(keychainStatusIsTransient(errSecNotAvailable))
        XCTAssertTrue(keychainStatusIsTransient(errSecIO))
    }

    func testPermanentStatusesAreNotRetried() {
        XCTAssertFalse(keychainStatusIsTransient(errSecParam))
        XCTAssertFalse(keychainStatusIsTransient(errSecMissingEntitlement))
        XCTAssertFalse(keychainStatusIsTransient(errSecDecode))
        XCTAssertFalse(keychainStatusIsTransient(errSecItemNotFound))
    }

    func testMissingItemIsAbsentNotUnavailable() throws {
        let outcome = keychainReadOnce([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ai.synheart.auth.test.absent",
            kSecAttrAccount as String: "never-stored-\(UUID().uuidString)",
        ])
        // A host without Keychain entitlements answers with an error status;
        // only a reachable Keychain can prove the absent branch.
        if case .unavailable = outcome {
            throw XCTSkip("Keychain unavailable in this test host (entitlements)")
        }
        XCTAssertEqual(outcome, .absent)
    }

    func testRetryReturnsPermanentFailureImmediately() {
        // errSecParam is not transient: a malformed query must come back on
        // the first attempt, not after the full backoff budget.
        let start = Date()
        let outcome = keychainReadWithRetry([kSecClass as String: "not-a-class"], what: "test")
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
        if case .found = outcome { XCTFail("a malformed query cannot find anything") }
    }
}
