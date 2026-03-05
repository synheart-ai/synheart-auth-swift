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
        logger.info("Clock skew updated: offset = \(offsetSeconds)s")
    }

    /// Returns the current time corrected for server clock skew (ISO 8601).
    func correctedTimestamp() -> String {
        lock.lock()
        let offset = offsetSeconds
        lock.unlock()

        let corrected = Date(timeIntervalSince1970: Date().timeIntervalSince1970 + offset)
        return ISO8601DateFormatter().string(from: corrected)
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
