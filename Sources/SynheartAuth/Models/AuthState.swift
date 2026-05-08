import Foundation

/// Device authentication state machine.
///
/// Valid transitions:
/// ```
/// unregistered → challengeReceived → keyReady → registering → registered
///                                                              ↓
///                                                          keyInvalid → unregistered
/// ```
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
