import Foundation

/// Device authentication state machine.
///
/// Valid transitions:
/// ```
/// unregistered → challengeReceived → keyReady → registering → registered
///                                                              ↓
///                                                          keyInvalid → unregistered
/// ```
///
/// `keyInvalid` is entered when the signing key is found gone (`signRequest`,
/// `rotateKey`); `registerDevice` re-registers from it. An intermediate state
/// (`challengeReceived`, `keyReady`, `registering`) left by a process that
/// died mid-flow is settled by `DeviceRegistrar.recoverInterruptedOperation`
/// before the next register/rotate — back to the pre-attempt state, or to
/// `registered` / `keyInvalid` for a rotation. Those recovery writes are not
/// routed through `canTransition`.
public enum DeviceAuthState: String, Codable, Sendable, Equatable {
    case unregistered
    case challengeReceived
    case keyReady
    case registering
    case registered
    case keyInvalid

    /// Returns `true` if transitioning to `next` is valid per the RFC state machine.
    public func canTransition(to next: DeviceAuthState) -> Bool {
        switch (self, next) {
        case (.unregistered, .challengeReceived): return true
        case (.challengeReceived, .keyReady): return true
        case (.keyReady, .registering): return true
        case (.registering, .registered): return true
        case (.registering, .unregistered): return true  // registration failure → reset
        case (.registered, .keyInvalid): return true
        case (.registered, .registering): return true    // key rotation
        case (.keyInvalid, .unregistered): return true
        default: return false
        }
    }

    /// Attempt a state transition, throwing if invalid.
    public func transition(to next: DeviceAuthState) throws -> DeviceAuthState {
        guard canTransition(to: next) else {
            throw SynheartAuthError.invalidStateTransition(
                from: self.rawValue,
                to: next.rawValue
            )
        }
        return next
    }
}
