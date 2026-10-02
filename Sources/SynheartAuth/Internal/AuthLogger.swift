import Foundation
import os

/// The SDK's `os.Logger`.
///
/// Call sites interpolate straight into `Logger`'s `OSLogMessage` so every
/// value carries its own privacy annotation. Identifiers (app id, device id,
/// key tags, Keychain account names), key material, signatures, nonces,
/// challenges, server error bodies and error descriptions that can carry them
/// are `.private` — redacted in logs collected off-device unless a debugger or
/// a logging profile is attached. Use `.private(mask: .hash)` for identifiers
/// so log lines can still be correlated. Status text, step names, counts,
/// HTTP status codes and `OSStatus` values are `.public`.
///
/// (Through 0.1.2 this was a `String` wrapper that logged every message with
/// `privacy: .public`, which made per-value annotation impossible.)
enum AuthLogger {
    static let shared = Logger(subsystem: "ai.synheart.auth", category: "SynheartAuth")
}
