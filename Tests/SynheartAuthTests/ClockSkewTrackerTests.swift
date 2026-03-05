import XCTest
@testable import SynheartAuth

final class ClockSkewTrackerTests: XCTestCase {
    private var tracker: ClockSkewTracker!

    override func setUp() {
        super.setUp()
        tracker = ClockSkewTracker()
    }

    func testInitialOffsetIsZero() {
        XCTAssertEqual(tracker.currentOffset, 0)
    }

    func testUpdateSetsOffset() {
        // Simulate server being 60 seconds ahead
        let serverTime = Date().timeIntervalSince1970 + 60
        tracker.update(serverTimestamp: serverTime)
        XCTAssertEqual(tracker.currentOffset, 60, accuracy: 1.0)
    }

    func testCorrectedTimestampAppliesOffset() {
        let serverTime = Date().timeIntervalSince1970 + 30
        tracker.update(serverTimestamp: serverTime)

        let corrected = tracker.correctedEpochSeconds()
        let expected = Date().timeIntervalSince1970 + 30
        XCTAssertEqual(corrected, expected, accuracy: 1.0)
    }

    func testCorrectedTimestampReturnsISO8601() {
        let ts = tracker.correctedTimestamp()
        // Should be parseable as ISO 8601
        let formatter = ISO8601DateFormatter()
        XCTAssertNotNil(formatter.date(from: ts))
    }

    func testReset() {
        let serverTime = Date().timeIntervalSince1970 + 100
        tracker.update(serverTimestamp: serverTime)
        XCTAssertNotEqual(tracker.currentOffset, 0)

        tracker.reset()
        XCTAssertEqual(tracker.currentOffset, 0)
    }

    func testNegativeOffset() {
        // Server is 45 seconds behind
        let serverTime = Date().timeIntervalSince1970 - 45
        tracker.update(serverTimestamp: serverTime)
        XCTAssertEqual(tracker.currentOffset, -45, accuracy: 1.0)
    }
}
