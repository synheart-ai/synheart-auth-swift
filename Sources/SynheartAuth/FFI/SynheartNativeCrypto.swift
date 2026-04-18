import Foundation
import CryptoKit
import os
#if canImport(DeviceCheck)
import DeviceCheck
#endif

private let ffiLog = Logger(subsystem: "ai.synheart.auth", category: "SynheartFFI")

/// C-ABI exports consumed by the synheart-core-runtime FFI bridge.
///
/// Dart resolves these via `DynamicLibrary.process()` and hands the function
/// pointers to Rust through `synheart_core_sdk_set_crypto_callbacks`. Rust
/// then calls them directly — no Dart trampoline in the hot path.
///
/// Return contracts (Rust frees with `CString::from_raw`, i.e. system free):
/// - `generate_key` → JSON `{"x":"<b64url>","y":"<b64url>"}`
/// - `sign_bytes`   → base64url(raw 64-byte r||s) — Rust FFI bridge expects
///   compact form, then converts to DER before sending to the server.
/// - `get_attestation` → JSON `{"format":"apple-app-attest","blob":"<b64>"}` or null
/// - `key_exists`, `delete_key` → i32 (1/0 for exists, 0=ok / nonzero=err for delete)

// MARK: - Secure Enclave key store (CryptoKit-backed)
//
// CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` provides first-class
// support for digest signing (`signature(for: SHA256Digest)`) and produces a
// raw 64-byte r||s signature. SecKey on Secure Enclave does not always honour
// the `.ecdsaSignatureDigest*` algorithm reliably (only Message-mode is in
// Apple's documented support matrix). The Rust core passes us a precomputed
// `client_data_hash`, so we need digest signing — hence CryptoKit.
//
// The key is opaque from outside the enclave. We persist its
// `dataRepresentation` (an encrypted handle valid only on this device) in the
// generic-password keychain class, keyed by deviceId.

private let ffiKeyService = "ai.synheart.auth.fficrypto"
private let ffiAppAttestKeyIdService = "ai.synheart.auth.fficrypto.appattest"

private func ffiKeychainQuery(service: String, deviceId: String) -> [String: Any] {
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: deviceId,
    ]
}

private func loadEnclaveKey(deviceId: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    var q = ffiKeychainQuery(service: ffiKeyService, deviceId: deviceId)
    q[kSecReturnData as String] = true
    var item: AnyObject?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data else { return nil }
    return try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
}

private func storeEnclaveKey(_ key: SecureEnclave.P256.Signing.PrivateKey, deviceId: String) -> Bool {
    SecItemDelete(ffiKeychainQuery(service: ffiKeyService, deviceId: deviceId) as CFDictionary)
    var attrs = ffiKeychainQuery(service: ffiKeyService, deviceId: deviceId)
    attrs[kSecValueData as String] = key.dataRepresentation
    attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
}

private func deleteEnclaveKey(deviceId: String) -> Bool {
    let s = SecItemDelete(ffiKeychainQuery(service: ffiKeyService, deviceId: deviceId) as CFDictionary)
    return s == errSecSuccess || s == errSecItemNotFound
}

/// Rule 2 / 4: persist a stable App Attest keyId per device_id so every
/// `get_attestation` call reuses the same credential (avoiding both per-call
/// regeneration against Apple's quota and any risk of switching identities
/// between callbacks within one registration flow).
private func loadAppAttestKeyId(deviceId: String) -> String? {
    var q = ffiKeychainQuery(service: ffiAppAttestKeyIdService, deviceId: deviceId)
    q[kSecReturnData as String] = true
    var item: AnyObject?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data,
          let s = String(data: data, encoding: .utf8) else { return nil }
    return s
}

private func storeAppAttestKeyId(_ keyId: String, deviceId: String) -> Bool {
    SecItemDelete(ffiKeychainQuery(service: ffiAppAttestKeyIdService, deviceId: deviceId) as CFDictionary)
    var attrs = ffiKeychainQuery(service: ffiAppAttestKeyIdService, deviceId: deviceId)
    attrs[kSecValueData as String] = Data(keyId.utf8)
    attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
}

private func deleteAppAttestKeyId(deviceId: String) -> Bool {
    let s = SecItemDelete(ffiKeychainQuery(service: ffiAppAttestKeyIdService, deviceId: deviceId) as CFDictionary)
    return s == errSecSuccess || s == errSecItemNotFound
}

private func cString(_ s: String) -> UnsafeMutablePointer<CChar>? {
    return strdup(s)
}

private func base64Url(_ data: Data) -> String {
    var s = data.base64EncodedString()
    s = s.replacingOccurrences(of: "+", with: "-")
    s = s.replacingOccurrences(of: "/", with: "_")
    s = s.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    return s
}

/// X9.62 uncompressed (0x04 ‖ X32 ‖ Y32) → (X, Y) base64url strings.
private func splitUncompressedPoint(_ data: Data) -> (String, String)? {
    guard data.count == 65, data[0] == 0x04 else { return nil }
    let x = data.subdata(in: 1..<33)
    let y = data.subdata(in: 33..<65)
    return (base64Url(x), base64Url(y))
}

// MARK: - FFI exports

@_cdecl("synheart_native_generate_key")
public func synheart_native_generate_key(_ deviceId: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let deviceId, let id = String(validatingUTF8: deviceId) else { return nil }
    do {
        // Rule 1: load-or-create. If an SE key already exists for this
        // device_id we reuse it so every callback (generate_key, sign_bytes)
        // within one registration flow operates on the identical credential.
        let key: SecureEnclave.P256.Signing.PrivateKey
        if let existing = loadEnclaveKey(deviceId: id) {
            key = existing
        } else {
            let fresh = try SecureEnclave.P256.Signing.PrivateKey()
            guard storeEnclaveKey(fresh, deviceId: id) else {
                ffiLog.error("[SynheartFFI] generate_key: keychain store failed for id=\(id, privacy: .public)")
                return nil
            }
            key = fresh
        }
        let pub = key.publicKey.x963Representation
        guard let (x, y) = splitUncompressedPoint(pub) else { return nil }
        let json = "{\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return cString(json)
    } catch {
        ffiLog.error("[SynheartFFI] generate_key: SE keygen failed: \(error.localizedDescription, privacy: .public)")
        return nil
    }
}

@_cdecl("synheart_native_sign_bytes")
public func synheart_native_sign_bytes(
    _ deviceId: UnsafePointer<CChar>?,
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int
) -> UnsafeMutablePointer<CChar>? {
    guard let deviceId, let id = String(validatingUTF8: deviceId),
          let data, dataLen > 0 else { return nil }
    guard let key = loadEnclaveKey(deviceId: id) else {
        ffiLog.error("[SynheartFFI] sign: no SE key for id=\(id, privacy: .public)")
        return nil
    }
    do {
        // Rust passes raw signing input (variable length). Hash it with
        // SHA-256 first, matching the software_bridge behaviour, then sign
        // the resulting digest with the Secure Enclave key.
        let inputData = Data(bytes: data, count: dataLen)
        let digest = SHA256.hash(data: inputData)
        let sig = try key.signature(for: digest)
        // Rust FFI bridge expects raw 64-byte r||s (compact), then
        // converts to DER itself before sending to the server.
        return cString(base64Url(sig.rawRepresentation))
    } catch {
        ffiLog.error("[SynheartFFI] sign: SE sign failed: \(error.localizedDescription, privacy: .public)")
        return nil
    }
}

@_cdecl("synheart_native_get_attestation")
public func synheart_native_get_attestation(
    _ deviceId: UnsafePointer<CChar>?,
    _ challengeHash: UnsafePointer<UInt8>?,
    _ challengeHashLen: Int
) -> UnsafeMutablePointer<CChar>? {
    guard let deviceId, let id = String(validatingUTF8: deviceId),
          let challengeHash, challengeHashLen > 0 else { return nil }
    let clientDataHash = Data(bytes: challengeHash, count: challengeHashLen)

    #if canImport(DeviceCheck) && !targetEnvironment(simulator)
    guard DCAppAttestService.shared.isSupported else { return nil }
    // Rule 2 / 4: reuse a single App Attest keyId per device_id. Generate one
    // on first call and persist in Keychain; every subsequent attestation for
    // the same device_id reuses the same credential. Task.detached keeps the
    // async DCAppAttestService calls off this caller thread so the
    // DispatchSemaphore wait can't starve the cooperative pool.
    let cachedKeyId = loadAppAttestKeyId(deviceId: id)
    let semaphore = DispatchSemaphore(value: 0)
    let box = UnsafeMutablePointer<(Data, String)?>.allocate(capacity: 1)
    box.initialize(to: nil)
    defer {
        box.deinitialize(count: 1)
        box.deallocate()
    }
    Task.detached(priority: .userInitiated) {
        defer { semaphore.signal() }
        do {
            let keyId: String
            if let existing = cachedKeyId {
                keyId = existing
            } else {
                keyId = try await DCAppAttestService.shared.generateKey()
            }
            let att = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
            box.pointee = (att, keyId)
        } catch {
            box.pointee = nil
        }
    }
    semaphore.wait()
    guard let (blob, keyId) = box.pointee else { return nil }
    if cachedKeyId == nil {
        _ = storeAppAttestKeyId(keyId, deviceId: id)
    }
    let json = "{\"format\":\"apple-app-attest\",\"blob\":\"\(blob.base64EncodedString())\"}"
    return cString(json)
    #else
    return nil
    #endif
}

@_cdecl("synheart_native_key_exists")
public func synheart_native_key_exists(_ deviceId: UnsafePointer<CChar>?) -> Int32 {
    guard let deviceId, let id = String(validatingUTF8: deviceId) else { return 0 }
    return loadEnclaveKey(deviceId: id) != nil ? 1 : 0
}

@_cdecl("synheart_native_delete_key")
public func synheart_native_delete_key(_ deviceId: UnsafePointer<CChar>?) -> Int32 {
    guard let deviceId, let id = String(validatingUTF8: deviceId) else { return 1 }
    // Rule 4: clear BOTH persisted mappings so the next registration for this
    // device_id starts clean. The App Attest key itself cannot be revoked via
    // the Apple API, but dropping the cached keyId means we won't try to
    // reuse it (and we'll generate a fresh one on the next attestation).
    let seOk = deleteEnclaveKey(deviceId: id)
    let aaOk = deleteAppAttestKeyId(deviceId: id)
    return (seOk && aaOk) ? 0 : 1
}

// MARK: - Secure Storage FFI
//
// Backs `synheart_core_set_storage_callbacks` so the Rust core can persist
// consent tokens, device records, and other state across app restarts.
// Keys are stored as Keychain generic-password items, scoped by `service`
// (a C string the core provides, e.g. "consent_tokens") and `key` (account).

@_cdecl("synheart_native_secure_store")
public func synheart_native_secure_store(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?,
    _ value: UnsafePointer<CChar>?
) -> Int32 {
    guard let service, let key, let value,
          let svc = String(validatingUTF8: service),
          let k = String(validatingUTF8: key),
          let v = String(validatingUTF8: value) else { return 1 }
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: svc,
        kSecAttrAccount as String: k,
    ]
    SecItemDelete(q as CFDictionary)
    var attrs = q
    attrs[kSecValueData as String] = Data(v.utf8)
    attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(attrs as CFDictionary, nil)
    if status != errSecSuccess {
        ffiLog.error("[SynheartFFI] secure_store failed status=\(status, privacy: .public) service=\(svc, privacy: .public)")
        return 1
    }
    return 0
}

@_cdecl("synheart_native_secure_load")
public func synheart_native_secure_load(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>? {
    guard let service, let key,
          let svc = String(validatingUTF8: service),
          let k = String(validatingUTF8: key) else { return nil }
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: svc,
        kSecAttrAccount as String: k,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: AnyObject?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    guard status == errSecSuccess,
          let data = item as? Data,
          let s = String(data: data, encoding: .utf8) else {
        return nil
    }
    return cString(s)
}

@_cdecl("synheart_native_secure_delete")
public func synheart_native_secure_delete(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?
) -> Int32 {
    guard let service, let key,
          let svc = String(validatingUTF8: service),
          let k = String(validatingUTF8: key) else { return 1 }
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: svc,
        kSecAttrAccount as String: k,
    ]
    let status = SecItemDelete(q as CFDictionary)
    return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : 1
}

/// Anchor references to prevent the linker from dead-stripping the @_cdecl
/// symbols when this package is linked into a host app as a static library.
/// The Flutter plugin (or any FFI consumer) should touch `all` during its
/// registration path to keep the symbols live for `DynamicLibrary.process()`
/// lookups at runtime.
public enum SynheartNativeCryptoAnchor {
    public static let all: [Any] = [
        synheart_native_generate_key,
        synheart_native_sign_bytes,
        synheart_native_get_attestation,
        synheart_native_key_exists,
        synheart_native_delete_key,
        synheart_native_secure_store,
        synheart_native_secure_load,
        synheart_native_secure_delete,
    ]
}
