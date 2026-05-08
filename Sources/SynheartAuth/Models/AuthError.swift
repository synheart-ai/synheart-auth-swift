import Foundation

/// All error codes from RFC-AUTH-MOBILE-0001.
public enum SynheartAuthError: Error, Equatable, Sendable {
    /// Network request failed (timeout, no connectivity, etc.)
    case networkError(String)
    /// Challenge has expired before registration could complete.
    case challengeExpired
    /// App Attest / DeviceCheck is not available on this device.
    case attestationUnavailable
    /// The Secure Enclave key has been invalidated (biometric change, device wipe, etc.)
    case keyInvalidated
    /// Client and server clocks are too far apart. Call `correctClockSkew` and retry.
    case clockSkew
    /// Device is already registered for this app.
    case alreadyRegistered
    /// Device is not registered — call `registerDevice` first.
    case notRegistered
    /// The SDK has not been configured — call `configure(baseUrl:)` first.
    case notConfigured
    /// Registration is already in progress.
    case registrationInProgress
    /// Server rejected the request with a specific error.
    case serverError(code: String, message: String)
    /// Keychain operation failed.
    case keychainError(OSStatus)
    /// Secure Enclave key generation or signing failed.
    case cryptoError(String)
    /// An invalid state transition was attempted.
    case invalidStateTransition(from: String, to: String)
}

extension SynheartAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .networkError(let msg): return "Network error: \(msg)"
        case .challengeExpired: return "Challenge expired"
        case .attestationUnavailable: return "App Attest unavailable on this device"
        case .keyInvalidated: return "Secure Enclave key invalidated"
        case .clockSkew: return "Clock skew detected — call correctClockSkew and retry"
        case .alreadyRegistered: return "Device already registered"
        case .notRegistered: return "Device not registered"
        case .notConfigured: return "SDK not configured — call configure(baseUrl:) first"
        case .registrationInProgress: return "Registration already in progress"
        case .serverError(let code, let msg): return "Server error [\(code)]: \(msg)"
        case .keychainError(let status): return "Keychain error: \(status)"
        case .cryptoError(let msg): return "Crypto error: \(msg)"
        case .invalidStateTransition(let from, let to): return "Invalid state transition: \(from) → \(to)"
        }
    }
}
