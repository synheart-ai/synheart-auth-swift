import Foundation
import CryptoKit
#if canImport(DeviceCheck)
import DeviceCheck
#endif
#if canImport(UIKit)
import UIKit
#endif

/// Hard cap on the App Attest calls in `DeviceRegistrar.fetchAttestation`.
/// App Attest normally returns an error rather than hanging, but the
/// network-backed `generateKey`/`attestKey` can stall on a degraded connection
/// or an unresponsive attestation service; bounding the wait keeps a stalled
/// call from suspending registration indefinitely so it can fail fast.
private let attestationTimeoutSeconds: UInt64 = 30

private struct AttestationTimeoutError: Error {}

/// Runs `operation`, throwing `AttestationTimeoutError` if it does not finish
/// within `seconds`. The losing child task is cancelled; a non-cancellable
/// in-flight App Attest call keeps running but its result is discarded.
private func withAttestationTimeout<T: Sendable>(
    seconds: UInt64,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            throw AttestationTimeoutError()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw AttestationTimeoutError()
        }
        return result
    }
}

/// Orchestrates device registration and key rotation flows.
final class DeviceRegistrar: @unchecked Sendable {
    private let keyManager: KeyManaging
    private let storage: StorageManaging
    private let network: AuthNetworking
    private let logger = AuthLogger.shared

    init(keyManager: KeyManaging, storage: StorageManaging, network: AuthNetworking) {
        self.keyManager = keyManager
        self.storage = storage
        self.network = network
    }

    // MARK: - Registration

    /// Full 6-step device registration flow.
    ///
    /// 1. Fetch challenge from server
    /// 2. Generate key pair in Secure Enclave
    /// 3. Request App Attest proof (if available)
    /// 4. Send register request to server
    /// 5. Store device ID and update state
    /// 6. Return result
    ///
    /// An intermediate state persisted by a process that died mid-flow is
    /// recovered first (see `recoverInterruptedOperation`); only a register or
    /// rotate running in *this* process yields `registrationInProgress`.
    func register(appId: String) async throws -> RegistrationResult {
        // Fast path, no claim needed: already registered.
        if storage.loadState(appId: appId) == .registered,
           let deviceId = storage.loadDeviceId(appId: appId) {
            return RegistrationResult(status: .alreadyRegistered, deviceId: deviceId)
        }

        // Atomic test-and-set: only one in-flight register/rotate per appId
        // in this process.
        guard OperationClaims.claim(appId) else {
            throw SynheartAuthError.registrationInProgress
        }
        defer { OperationClaims.release(appId) }

        // Nothing else in this process is working on appId, so an
        // intermediate state on disk is left over from a dead process.
        try recoverInterruptedOperation(appId: appId)

        let currentState = storage.loadState(appId: appId)

        // Guard: already registered (possibly by a recovered rotation)
        if currentState == .registered {
            if let deviceId = storage.loadDeviceId(appId: appId) {
                return RegistrationResult(status: .alreadyRegistered, deviceId: deviceId)
            }
        }

        // Guard: must be unregistered or keyInvalid to start fresh
        guard currentState == .unregistered || currentState == .keyInvalid else {
            throw SynheartAuthError.registrationInProgress
        }

        do {
            // Record the operation before the first intermediate state, so a
            // later process knows what to undo and which state to return to.
            try beginPending(.register, prior: currentState, appId: appId)

            // Step 1: Fetch challenge (with retry)
            logger.info("Step 1/6: Fetching challenge for \(appId, privacy: .private(mask: .hash))")
            let challengeResponse = try await withRetry { [network] in
                try await network.fetchChallenge(appId: appId)
            }
            try storage.saveState(.challengeReceived, appId: appId)
            logger.info("Challenge received: \(challengeResponse.challenge, privacy: .private) expiresAt=\(challengeResponse.expiresAt, privacy: .public)")

            // Validate challenge hasn't expired (90s TTL per RFC)
            if challengeResponse.isExpired {
                throw SynheartAuthError.challengeExpired
            }

            // Step 2: Generate key pair
            logger.info("Step 2/6: Generating key pair")
            let publicKeyData = try keyManager.generateKeyPair(appId: appId)
            try storage.saveState(.keyReady, appId: appId)

            // Step 3: App Attest proof (best-effort)
            let publicKeyBase64 = publicKeyData.base64EncodedString()
            // Per RFC-AUTH-MOBILE-0001 §13, public key material must not be logged in prod.
            #if DEBUG
            logger.debug("Public key generated: bytes=\(publicKeyData.count, privacy: .public) base64=\(publicKeyBase64, privacy: .private)")
            #else
            logger.info("Public key generated: bytes=\(publicKeyData.count, privacy: .public)")
            #endif
            let proof = await fetchAttestation(
                challenge: challengeResponse.challenge,
                publicKey: publicKeyBase64,
                appId: appId
            )

            // Generate or reuse device ID
            let deviceId = storage.loadDeviceId(appId: appId) ?? UUID().uuidString

            // Step 4: Register with server
            logger.info("Step 4/6: Registering with server")
            try storage.saveState(.registering, appId: appId)

            let request = RegisterRequest(
                appId: appId,
                deviceId: deviceId,
                challenge: challengeResponse.challenge,
                publicKey: publicKeyBase64,
                platform: "ios",
                proof: proof ?? "none"
            )

            let response = try await withRetry { [network] in
                try await network.registerDevice(request: request)
            }

            // Step 5: Store result
            logger.info("Step 5/6: Storing device ID: \(response.deviceId, privacy: .private(mask: .hash))")
            try storage.saveDeviceId(response.deviceId, appId: appId)
            try storage.saveState(.registered, appId: appId)
            clearPending(appId: appId)

            // Step 6: Return
            logger.info("Step 6/6: Registration complete")
            return RegistrationResult(status: .success, deviceId: response.deviceId)

        } catch {
            logger.error("Registration failed: \(error.localizedDescription, privacy: .private)")
            // Reset state on failure
            try? storage.saveState(
                (currentState == .unregistered) ? .unregistered : .keyInvalid,
                appId: appId
            )
            keyManager.deleteKey(appId: appId)
            clearPending(appId: appId)

            if let authError = error as? SynheartAuthError {
                return RegistrationResult(status: .failed, error: authError)
            }
            return RegistrationResult(
                status: .failed,
                error: .networkError(error.localizedDescription)
            )
        }
    }

    // MARK: - Key Rotation

    /// Rotate the device key. Creates a new key, has old key sign the new public key,
    /// sends to server, and atomically swaps on success.
    func rotateKey(appId: String) async throws -> RotationResult {
        // Atomic test-and-set: serialize register/rotate per appId.
        guard OperationClaims.claim(appId) else {
            throw SynheartAuthError.registrationInProgress
        }
        defer { OperationClaims.release(appId) }

        // A rotation interrupted by a dead process left `registering`; settle
        // it so the device is `registered` (or `keyInvalid`) again.
        try recoverInterruptedOperation(appId: appId)

        guard storage.loadState(appId: appId) == .registered else {
            throw SynheartAuthError.notRegistered
        }

        guard let deviceId = storage.loadDeviceId(appId: appId) else {
            throw SynheartAuthError.notRegistered
        }

        var oldKeyIsGone = false
        do {
            try beginPending(.rotate, prior: .registered, appId: appId)

            // Generate new key pair
            logger.info("Rotating key: generating new key pair")
            let newPublicKeyData = try keyManager.generateNextKeyPair(appId: appId)

            // Sign the new public key with the old key (proof of possession)
            let oldKeySignature: Data
            do {
                oldKeySignature = try keyManager.sign(data: newPublicKeyData, appId: appId)
            } catch SynheartAuthError.keyInvalidated {
                oldKeyIsGone = true
                throw SynheartAuthError.keyInvalidated
            }

            // Transition to registering state for rotation
            try storage.saveState(.registering, appId: appId)

            // Send rotation request
            let request = RotateKeyRequest(
                appId: appId,
                deviceId: deviceId,
                newPublicKey: newPublicKeyData.base64EncodedString(),
                oldKeySignature: oldKeySignature.base64EncodedString()
            )

            let response = try await withRetry { [network] in
                try await network.rotateKey(request: request)
            }

            guard response.status == "ok" || response.status == "success" else {
                throw SynheartAuthError.serverError(code: "ROTATION_FAILED", message: response.status)
            }

            // Promote: atomic swap
            try keyManager.promoteNextKey(appId: appId)
            try storage.saveState(.registered, appId: appId)
            clearPending(appId: appId)

            logger.info("Key rotation complete for \(appId, privacy: .private(mask: .hash))")
            return RotationResult(status: .success)

        } catch {
            logger.error("Key rotation failed: \(error.localizedDescription, privacy: .private)")
            // Cleanup: delete the _next key, restore state
            keyManager.deleteNextKey(appId: appId)
            try? storage.saveState(.registered, appId: appId)
            clearPending(appId: appId)
            if oldKeyIsGone {
                // There is no key left to sign with: rotation cannot help,
                // re-registration can.
                invalidateRegisteredIdentity(appId: appId, keyManager: keyManager, storage: storage)
            }

            if let authError = error as? SynheartAuthError {
                return RotationResult(status: .failed, error: authError)
            }
            return RotationResult(status: .failed, error: .networkError(error.localizedDescription))
        }
    }

    // MARK: - Interrupted-operation recovery

    /// Settle an intermediate state (`challengeReceived`, `keyReady`,
    /// `registering`) written by a register/rotate whose process died.
    ///
    /// The caller must hold the `OperationClaims` claim for `appId`: that is
    /// what proves the state is stale rather than owned by a live flow.
    ///
    /// - Interrupted **registration**: the challenge was never persisted and
    ///   has a 90 s TTL, so the flow cannot be resumed. The half-made key —
    ///   never confirmed to this device — is deleted (no orphaned Keychain
    ///   key, no reuse of a key from an abandoned attempt) and the state goes
    ///   back to what it was before the attempt (`unregistered` or
    ///   `keyInvalid`). The caller then runs a fresh registration.
    /// - Interrupted **rotation**: the primary key is only ever replaced after
    ///   the server confirmed the rotation, so
    ///   - primary + `_next` present → server outcome unknown; keep the
    ///     confirmed primary, discard `_next`;
    ///   - only `_next` present → promotion had started (server confirmed);
    ///     finish it;
    ///   - only primary present → rotation finished or never sent; keep it;
    ///   - neither present → no key to sign with → `keyInvalid`.
    ///
    /// States written by 0.1.2 carry no pending-operation marker; `registering`
    /// with a stored device id is then a rotation (0.1.2 only stored the
    /// device id once registration succeeded), anything else a registration.
    ///
    /// Throws `keychainError` if key presence cannot be read right now; the
    /// state is then left untouched for a later attempt.
    func recoverInterruptedOperation(appId: String) throws {
        let state = storage.loadState(appId: appId)
        let metadata = storage.loadMetadata(appId: appId)
        let recorded = metadata[PendingOperation.opKey].flatMap(PendingOperation.init(rawValue:))

        switch state {
        case .challengeReceived, .keyReady, .registering:
            break
        case .unregistered, .registered, .keyInvalid:
            // Not mid-operation. A marker here is debris from a process that
            // died just before its first, or just after its last, state write.
            if recorded == .rotate { keyManager.deleteNextKey(appId: appId) }
            if recorded != nil { clearPending(appId: appId) }
            return
        }

        let operation = recorded
            ?? ((state == .registering && storage.loadDeviceId(appId: appId) != nil) ? .rotate : .register)
        let startedAt = metadata[PendingOperation.startedAtKey] ?? "unknown"
        logger.warning("Recovering interrupted \(operation.rawValue, privacy: .public) left in state \(state.rawValue, privacy: .public) (started \(startedAt, privacy: .public))")

        switch operation {
        case .register:
            let prior = metadata[PendingOperation.priorStateKey].flatMap(DeviceAuthState.init(rawValue:))
            keyManager.deleteKey(appId: appId)
            try storage.saveState(prior == .keyInvalid ? .keyInvalid : .unregistered, appId: appId)

        case .rotate:
            let primary = keyManager.primaryKeyPresence(appId: appId)
            let next = keyManager.nextKeyPresence(appId: appId)
            if case .unavailable(let status) = primary { throw SynheartAuthError.keychainError(status) }
            if case .unavailable(let status) = next { throw SynheartAuthError.keychainError(status) }

            switch (primary, next) {
            case (.present, .present):
                logger.warning("Interrupted rotation: server outcome unknown — keeping the confirmed key")
                keyManager.deleteNextKey(appId: appId)
                try storage.saveState(.registered, appId: appId)
            case (.absent, .present):
                logger.warning("Interrupted rotation: finishing the key promotion")
                try keyManager.promoteNextKey(appId: appId)
                try storage.saveState(.registered, appId: appId)
            case (.present, _):
                try storage.saveState(.registered, appId: appId)
            default:
                keyManager.deleteKey(appId: appId)
                try storage.saveState(.keyInvalid, appId: appId)
            }
        }
        clearPending(appId: appId)
    }

    private func beginPending(_ operation: PendingOperation, prior: DeviceAuthState, appId: String) throws {
        var metadata = storage.loadMetadata(appId: appId)
        metadata[PendingOperation.opKey] = operation.rawValue
        metadata[PendingOperation.priorStateKey] = prior.rawValue
        metadata[PendingOperation.startedAtKey] = ISO8601DateFormatter().string(from: Date())
        try storage.saveMetadata(metadata, appId: appId)
    }

    private func clearPending(appId: String) {
        var metadata = storage.loadMetadata(appId: appId)
        let keys = [PendingOperation.opKey, PendingOperation.priorStateKey, PendingOperation.startedAtKey]
        guard keys.contains(where: { metadata[$0] != nil }) else { return }
        keys.forEach { metadata.removeValue(forKey: $0) }
        try? storage.saveMetadata(metadata, appId: appId)
    }

    // MARK: - Retry

    /// Retry an async operation with exponential backoff and jitter.
    /// - Parameters:
    ///   - maxAttempts: Maximum number of attempts (default 5 per RFC-AUTH-MOBILE-0001 §12)
    ///   - operation: The async throwing operation to retry
    /// - Returns: The result of the first successful attempt
    /// - Throws: The last error if all attempts fail
    private func withRetry<T>(maxAttempts: Int = 5, _ operation: () async throws -> T) async throws -> T {
        var lastError: Error?
        for attempt in 0..<maxAttempts {
            do {
                return try await operation()
            } catch {
                lastError = error
                // Don't retry on client errors (4xx) or known non-transient errors
                if let authError = error as? SynheartAuthError {
                    switch authError {
                    case .challengeExpired, .notRegistered, .notConfigured,
                         .alreadyRegistered, .registrationInProgress,
                         .invalidStateTransition, .keyInvalidated:
                        throw error // Non-retryable
                    case .serverError(let code, _):
                        // 4xx errors from server are client errors — don't retry
                        if code.hasPrefix("4") { throw error }
                    default:
                        break // Retryable (network, crypto, etc.)
                    }
                }

                if attempt < maxAttempts - 1 {
                    // Exponential backoff: min(1s * 2^attempt + jitter, 30s)
                    let baseDelay: Double = 1.0 * pow(2.0, Double(attempt))
                    let jitter = Double.random(in: 0...0.5)
                    let delay = min(baseDelay + jitter, 30.0)
                    logger.info("Retry \(attempt + 1, privacy: .public)/\(maxAttempts - 1, privacy: .public) after \(String(format: "%.1f", delay), privacy: .public)s")
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                }
            }
        }
        throw lastError!
    }

    // MARK: - App Attest

    private func fetchAttestation(challenge: String, publicKey: String, appId: String) async -> String? {
        #if canImport(DeviceCheck) && !targetEnvironment(simulator)
        guard DCAppAttestService.shared.isSupported else {
            logger.warning("App Attest not supported on this device")
            return nil
        }

        do {
            return try await withAttestationTimeout(seconds: attestationTimeoutSeconds) {
                let keyId = try await DCAppAttestService.shared.generateKey()
                // The server binds the attestation to (challenge, public_key) using:
                // bindingHex = hex(SHA256(challenge || public_key))  // 64-char lowercase hex string
                // clientDataHash = SHA256(utf8(bindingHex))          // 32 bytes
                let bindingInput = challenge + publicKey
                let bindingDigest = SHA256.hash(data: Data(bindingInput.utf8))
                let bindingHex = bindingDigest.compactMap { String(format: "%02x", $0) }.joined()
                let clientDataHash = Data(SHA256.hash(data: Data(bindingHex.utf8)))

                let attestation = try await DCAppAttestService.shared.attestKey(
                    keyId,
                    clientDataHash: clientDataHash
                )
                return attestation.base64EncodedString()
            }
        } catch is AttestationTimeoutError {
            logger.warning("App Attest timed out after \(attestationTimeoutSeconds, privacy: .public)s (non-fatal)")
            return nil
        } catch {
            logger.warning("App Attest failed (non-fatal): \(error.localizedDescription, privacy: .private)")
            return nil
        }
        #else
        logger.info("App Attest not available (simulator/macOS)")
        return nil
        #endif
    }
}
