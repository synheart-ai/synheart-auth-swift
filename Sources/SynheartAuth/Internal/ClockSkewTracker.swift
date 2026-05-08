import Foundation

/// Thread-safe tracker for server-client clock offset.
///
/// When the server returns a CLOCK_SKEW error with its timestamp,
/// call `update(serverTimestamp:)` to store the offset. All subsequent
/// calls to `correctedTimestamp()` will apply the correction.
final class ClockSkewTracker: @unchecked Sendable {
    private var offsetSeconds: TimeInterval = 0
    private let lock = NSLock()
    private let logger = AuthLogger.shared

    /// Update the offset based on a known server timestamp (seconds since epoch).
    func update(serverTimestamp: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        let localNow = Date().timeIntervalSince1970
        offsetSeconds = serverTimestamp - localNow
        // Per RFC-AUTH-MOBILE-0001 §13, clock offset values must not be logged (reveals device clock state).
        logger.info("Clock skew offset updated")
    }

    /// Returns the current time corrected for server clock skew, formatted as
    /// Unix seconds in ASCII decimal (e.g. `"1709312345"`) per RFC-AUTH-MOBILE-0001 §4.
    func correctedTimestamp() -> String {
        lock.lock()
        let offset = offsetSeconds
        lock.unlock()

        let correctedEpoch = Date().timeIntervalSince1970 + offset
        return String(Int64(correctedEpoch))
    }

    /// Returns the current time corrected for server clock skew (seconds since epoch).
    func correctedEpochSeconds() -> TimeInterval {
        lock.lock()
        let offset = offsetSeconds
        lock.unlock()
        return Date().timeIntervalSince1970 + offset
    }

    /// Current stored offset in seconds.
    var currentOffset: TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return offsetSeconds
    }

    /// Reset the offset to zero.
    func reset() {
        lock.lock()
        defer { lock.unlock() }
        offsetSeconds = 0
    }
}
