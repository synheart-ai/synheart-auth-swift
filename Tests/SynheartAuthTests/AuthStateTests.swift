import XCTest
@testable import SynheartAuth

final class AuthStateTests: XCTestCase {
    // MARK: - Valid Transitions

    func testValidTransitions() throws {
        // Registration flow
        var state = DeviceAuthState.unregistered
        state = try state.transition(to: .challengeReceived)
        XCTAssertEqual(state, .challengeReceived)

        state = try state.transition(to: .keyReady)
        XCTAssertEqual(state, .keyReady)

        state = try state.transition(to: .registering)
        XCTAssertEqual(state, .registering)

        state = try state.transition(to: .registered)
        XCTAssertEqual(state, .registered)
    }

    func testKeyInvalidTransition() throws {
        let state = DeviceAuthState.registered
        let invalid = try state.transition(to: .keyInvalid)
        XCTAssertEqual(invalid, .keyInvalid)

        let reset = try invalid.transition(to: .unregistered)
        XCTAssertEqual(reset, .unregistered)
    }

    func testRegistrationFailureResets() throws {
        let state = DeviceAuthState.registering
        let reset = try state.transition(to: .unregistered)
        XCTAssertEqual(reset, .unregistered)
    }

    func testKeyRotationTransition() throws {
        let state = DeviceAuthState.registered
        let rotating = try state.transition(to: .registering)
        XCTAssertEqual(rotating, .registering)
    }

    // MARK: - Invalid Transitions

    func testInvalidTransitionThrows() {
        let state = DeviceAuthState.unregistered
        XCTAssertThrowsError(try state.transition(to: .registered)) { error in
            guard case SynheartAuthError.invalidStateTransition(let from, let to) = error else {
                XCTFail("Expected invalidStateTransition, got \(error)")
                return
            }
            XCTAssertEqual(from, "unregistered")
            XCTAssertEqual(to, "registered")
        }
    }

    func testCannotSkipChallenge() {
        let state = DeviceAuthState.unregistered
        XCTAssertFalse(state.canTransition(to: .keyReady))
        XCTAssertFalse(state.canTransition(to: .registering))
        XCTAssertFalse(state.canTransition(to: .registered))
    }

    func testRegisteredCannotGoBackToChallenge() {
        let state = DeviceAuthState.registered
        XCTAssertFalse(state.canTransition(to: .challengeReceived))
        XCTAssertFalse(state.canTransition(to: .keyReady))
        XCTAssertFalse(state.canTransition(to: .unregistered))
    }

    // MARK: - Codable

    func testCodableRoundTrip() throws {
        let state = DeviceAuthState.registered
        let data = try JSONEncoder().encode(state)
        let decoded = try JSONDecoder().decode(DeviceAuthState.self, from: data)
        XCTAssertEqual(decoded, .registered)
    }

    func testAllStatesAreCodable() throws {
        let allStates: [DeviceAuthState] = [
            .unregistered, .challengeReceived, .keyReady,
            .registering, .registered, .keyInvalid,
        ]
        for state in allStates {
            let data = try JSONEncoder().encode(state)
            let decoded = try JSONDecoder().decode(DeviceAuthState.self, from: data)
            XCTAssertEqual(decoded, state)
        }
    }
}
