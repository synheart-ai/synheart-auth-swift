import Foundation
import Security
import CryptoKit

/// Protocol for key management, enabling test injection with software keys.
protocol KeyManaging: Sendable {
    /// Generate a new P-256 key pair. Returns the public key as uncompressed X9.62 data.
    func generateKeyPair(appId: String) throws -> Data
    /// Generate a new key pair with a `_next` suffix (for rotation).
    func generateNextKeyPair(appId: String) throws -> Data
    /// Promote the `_next` key to the primary key (after server confirms rotation).
    func promoteNextKey(appId: String) throws
    /// Delete the `_next` key (rotation failed).
    func deleteNextKey(appId: String)
    /// Sign raw data with the primary key. Returns ASN.1 DER encoded ECDSA signature.
    func sign(data: Data, appId: String) throws -> Data
    /// Delete the primary key pair.
    func deleteKey(appId: String)
    /// Check if a primary key exists.
    func hasKey(appId: String) -> Bool
}

/// Manages Secure Enclave P-256 keys, with software fallback for simulator/CI.
final class KeyManager: KeyManaging, @unchecked Sendable {
    private let logger = AuthLogger.shared
    private let useSecureEnclave: Bool

    init() {
        // Detect Secure Enclave availability
        #if targetEnvironment(simulator)
        self.useSecureEnclave = false
        #else
        self.useSecureEnclave = true
        #endif
    }

    /// For testing: force software or hardware keys.
    init(useSecureEnclave: Bool) {
        self.useSecureEnclave = useSecureEnclave
    }

    private func tag(appId: String) -> String {
        "ai.synheart.auth.\(appId)"
    }

    private func nextTag(appId: String) -> String {
        "ai.synheart.auth.\(appId)_next"
    }

    // MARK: - Key Generation

    func generateKeyPair(appId: String) throws -> Data {
        try generateKey(tag: tag(appId: appId))
    }

    func generateNextKeyPair(appId: String) throws -> Data {
        try generateKey(tag: nextTag(appId: appId))
    }

    private func generateKey(tag: String) throws -> Data {
        // Delete any existing key with this tag
        deleteKeyByTag(tag)

        let tagData = Data(tag.utf8)
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
            ] as [String: Any],
        ]

        if useSecureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            logger.debug("Generating Secure Enclave P-256 key: \(tag)")
        } else {
            logger.warning("Secure Enclave unavailable — using software P-256 key: \(tag)")
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SynheartAuthError.cryptoError("Key generation failed: \(msg)")
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SynheartAuthError.cryptoError("Failed to extract public key")
        }

        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SynheartAuthError.cryptoError("Failed to export public key: \(msg)")
        }

        logger.info("Generated key pair: \(tag) (\(publicKeyData.count) bytes public key)")
        return publicKeyData
    }

    // MARK: - Key Promotion (Rotation)

    func promoteNextKey(appId: String) throws {
        let currentTag = tag(appId: appId)
        let nextTagValue = nextTag(appId: appId)

        // 1. Delete the old primary key
        deleteKeyByTag(currentTag)

        // 2. Re-tag the _next key to the primary tag
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(nextTagValue.utf8),
        ]
        let update: [String: Any] = [
            kSecAttrApplicationTag as String: Data(currentTag.utf8),
        ]

        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        guard status == errSecSuccess else {
            throw SynheartAuthError.cryptoError("Key promotion failed: \(status)")
        }
        logger.info("Promoted _next key to primary for app: \(appId)")
    }

    func deleteNextKey(appId: String) {
        deleteKeyByTag(nextTag(appId: appId))
    }

    // MARK: - Signing

    func sign(data: Data, appId: String) throws -> Data {
        guard let privateKey = loadPrivateKey(tag: tag(appId: appId)) else {
            throw SynheartAuthError.keyInvalidated
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            let cfError = error?.takeRetainedValue()
            let code = cfError.map { CFErrorGetCode($0) } ?? 0

            // Detect key invalidation
            if code == Int(errSecItemNotFound) || code == Int(errSecAuthFailed) {
                throw SynheartAuthError.keyInvalidated
            }
            let msg = cfError?.localizedDescription ?? "Unknown error"
            throw SynheartAuthError.cryptoError("Signing failed: \(msg)")
        }

        return signature
    }

    // MARK: - Key Lifecycle

    func deleteKey(appId: String) {
        deleteKeyByTag(tag(appId: appId))
        deleteKeyByTag(nextTag(appId: appId))
        logger.info("Deleted all keys for app: \(appId)")
    }

    func hasKey(appId: String) -> Bool {
        loadPrivateKey(tag: tag(appId: appId)) != nil
    }

    // MARK: - Private Helpers

    private func loadPrivateKey(tag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            return nil
        }
        return result as! SecKey?  // swiftlint:disable:this force_cast
    }

    private func deleteKeyByTag(_ tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// In-memory mock using CryptoKit software keys for testing.
final class MockKeyManager: KeyManaging, @unchecked Sendable {
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private let lock = NSLock()

    var generateShouldFail = false
    var signShouldFail = false

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    func generateKeyPair(appId: String) throws -> Data {
        if generateShouldFail {
            throw SynheartAuthError.cryptoError("Mock generate failure")
        }
        return withLock {
            let key = P256.Signing.PrivateKey()
            keys[appId] = key
            return key.publicKey.x963Representation
        }
    }

    func generateNextKeyPair(appId: String) throws -> Data {
        if generateShouldFail {
            throw SynheartAuthError.cryptoError("Mock generate failure")
        }
        return withLock {
            let key = P256.Signing.PrivateKey()
            keys["\(appId)_next"] = key
            return key.publicKey.x963Representation
        }
    }

    func promoteNextKey(appId: String) throws {
        try withLock {
            guard let nextKey = keys["\(appId)_next"] else {
                throw SynheartAuthError.cryptoError("No _next key to promote")
            }
            keys[appId] = nextKey
            keys.removeValue(forKey: "\(appId)_next")
        }
    }

    func deleteNextKey(appId: String) {
        lock.lock()
        defer { lock.unlock() }
        keys.removeValue(forKey: "\(appId)_next")
    }

    func sign(data: Data, appId: String) throws -> Data {
        if signShouldFail {
            throw SynheartAuthError.keyInvalidated
        }
        return try withLock {
            guard let key = keys[appId] else {
                throw SynheartAuthError.keyInvalidated
            }
            let signature = try key.signature(for: data)
            return signature.derRepresentation
        }
    }

    func deleteKey(appId: String) {
        withLock {
            keys.removeValue(forKey: appId)
            keys.removeValue(forKey: "\(appId)_next")
        }
    }

    func hasKey(appId: String) -> Bool {
        withLock { keys[appId] != nil }
    }
}
