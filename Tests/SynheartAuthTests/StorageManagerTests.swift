import XCTest
@testable import SynheartAuth

final class StorageManagerTests: XCTestCase {
    private var storage: MockStorageManager!
    private let appId = "com.test.app"

    override func setUp() {
        super.setUp()
        storage = MockStorageManager()
    }

    // MARK: - Device ID

    func testSaveAndLoadDeviceId() throws {
        let deviceId = "device-abc-123"
        try storage.saveDeviceId(deviceId, appId: appId)
        XCTAssertEqual(storage.loadDeviceId(appId: appId), deviceId)
    }

    func testLoadDeviceIdReturnsNilWhenEmpty() {
        XCTAssertNil(storage.loadDeviceId(appId: appId))
    }

    func testDeviceIdIsolatedByAppId() throws {
        try storage.saveDeviceId("device-1", appId: "app1")
        try storage.saveDeviceId("device-2", appId: "app2")
        XCTAssertEqual(storage.loadDeviceId(appId: "app1"), "device-1")
        XCTAssertEqual(storage.loadDeviceId(appId: "app2"), "device-2")
    }

    // MARK: - State

    func testSaveAndLoadState() throws {
        try storage.saveState(.registered, appId: appId)
        XCTAssertEqual(storage.loadState(appId: appId), .registered)
    }

    func testLoadStateDefaultsToUnregistered() {
        XCTAssertEqual(storage.loadState(appId: appId), .unregistered)
    }

    // MARK: - Metadata

    func testSaveAndLoadMetadata() throws {
        let metadata = ["key1": "value1", "key2": "value2"]
        try storage.saveMetadata(metadata, appId: appId)
        XCTAssertEqual(storage.loadMetadata(appId: appId), metadata)
    }

    func testLoadMetadataDefaultsToEmpty() {
        XCTAssertEqual(storage.loadMetadata(appId: appId), [:])
    }

    // MARK: - Delete All

    func testDeleteAllRemovesEverything() throws {
        try storage.saveDeviceId("device-123", appId: appId)
        try storage.saveState(.registered, appId: appId)
        try storage.saveMetadata(["k": "v"], appId: appId)

        storage.deleteAll(appId: appId)

        XCTAssertNil(storage.loadDeviceId(appId: appId))
        XCTAssertEqual(storage.loadState(appId: appId), .unregistered)
        XCTAssertEqual(storage.loadMetadata(appId: appId), [:])
    }

    func testDeleteAllDoesNotAffectOtherApps() throws {
        try storage.saveDeviceId("device-1", appId: "app1")
        try storage.saveDeviceId("device-2", appId: "app2")

        storage.deleteAll(appId: "app1")

        XCTAssertNil(storage.loadDeviceId(appId: "app1"))
        XCTAssertEqual(storage.loadDeviceId(appId: "app2"), "device-2")
    }

    // MARK: - Overwrite

    func testSaveOverwritesPreviousValue() throws {
        try storage.saveDeviceId("old-id", appId: appId)
        try storage.saveDeviceId("new-id", appId: appId)
        XCTAssertEqual(storage.loadDeviceId(appId: appId), "new-id")
    }
}
