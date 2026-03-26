import Foundation
import Security

/// Protocol for Keychain-backed storage, enabling test injection.
protocol StorageManaging: Sendable {
    func saveDeviceId(_ deviceId: String, appId: String) throws
    func loadDeviceId(appId: String) -> String?
    func saveState(_ state: DeviceAuthState, appId: String) throws
    func loadState(appId: String) -> DeviceAuthState
    func saveMetadata(_ metadata: [String: String], appId: String) throws
    func loadMetadata(appId: String) -> [String: String]
    func deleteAll(appId: String)
}

/// Keychain-backed persistent storage for device auth data.
final class StorageManager: StorageManaging, @unchecked Sendable {
    static let serviceName = "ai.synheart.auth"

    private let logger = AuthLogger.shared

    // MARK: - Key Helpers

    private func key(_ suffix: String, appId: String) -> String {
        "synheart_auth_\(appId)_\(suffix)"
    }

    // MARK: - Device ID

    func saveDeviceId(_ deviceId: String, appId: String) throws {
        try save(data: Data(deviceId.utf8), key: key("device_id", appId: appId))
    }

    func loadDeviceId(appId: String) -> String? {
        guard let data = load(key: key("device_id", appId: appId)) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - State

    func saveState(_ state: DeviceAuthState, appId: String) throws {
        try save(data: Data(state.rawValue.utf8), key: key("state", appId: appId))
    }

    func loadState(appId: String) -> DeviceAuthState {
        guard let data = load(key: key("state", appId: appId)),
              let raw = String(data: data, encoding: .utf8),
              let state = DeviceAuthState(rawValue: raw) else {
            return .unregistered
        }
        return state
    }

    // MARK: - Metadata

    func saveMetadata(_ metadata: [String: String], appId: String) throws {
        let data = try JSONEncoder().encode(metadata)
        try save(data: data, key: key("metadata", appId: appId))
    }

    func loadMetadata(appId: String) -> [String: String] {
        guard let data = load(key: key("metadata", appId: appId)),
              let metadata = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return metadata
    }

    // MARK: - Delete All

    func deleteAll(appId: String) {
        delete(key: key("device_id", appId: appId))
        delete(key: key("state", appId: appId))
        delete(key: key("metadata", appId: appId))
        logger.info("Deleted all auth data for app: \(appId)")
    }

    // MARK: - Keychain Primitives

    private func save(data: Data, key: String) throws {
        // Delete first to avoid errSecDuplicateItem
        delete(key: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            logger.error("Keychain save failed for \(key): \(status)")
            throw SynheartAuthError.keychainError(status)
        }
    }

    private func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    private func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceName,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// In-memory mock for testing without Keychain access.
final class MockStorageManager: StorageManaging, @unchecked Sendable {
    private var store: [String: Data] = [:]
    private let lock = NSLock()

    private func key(_ suffix: String, appId: String) -> String {
        "synheart_auth_\(appId)_\(suffix)"
    }

    func saveDeviceId(_ deviceId: String, appId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        store[key("device_id", appId: appId)] = Data(deviceId.utf8)
    }

    func loadDeviceId(appId: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let data = store[key("device_id", appId: appId)] else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func saveState(_ state: DeviceAuthState, appId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        store[key("state", appId: appId)] = Data(state.rawValue.utf8)
    }

    func loadState(appId: String) -> DeviceAuthState {
        lock.lock()
        defer { lock.unlock() }
        guard let data = store[key("state", appId: appId)],
              let raw = String(data: data, encoding: .utf8),
              let state = DeviceAuthState(rawValue: raw) else {
            return .unregistered
        }
        return state
    }

    func saveMetadata(_ metadata: [String: String], appId: String) throws {
        lock.lock()
        defer { lock.unlock() }
        store[key("metadata", appId: appId)] = try JSONEncoder().encode(metadata)
    }

    func loadMetadata(appId: String) -> [String: String] {
        lock.lock()
        defer { lock.unlock() }
        guard let data = store[key("metadata", appId: appId)],
              let metadata = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return metadata
    }

    func deleteAll(appId: String) {
        lock.lock()
        defer { lock.unlock() }
        store.removeValue(forKey: key("device_id", appId: appId))
        store.removeValue(forKey: key("state", appId: appId))
        store.removeValue(forKey: key("metadata", appId: appId))
    }
}
