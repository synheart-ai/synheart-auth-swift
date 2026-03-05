import Foundation
import CryptoKit
#if canImport(DeviceCheck)
import DeviceCheck
#endif
#if canImport(UIKit)
import UIKit
#endif

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
    /// 3. Request App Attest attestation (if available)
    /// 4. Send register request to server
    /// 5. Store device ID and update state
    /// 6. Return result
    func register(appId: String) async throws -> RegistrationResult {
        let currentState = storage.loadState(appId: appId)

        // Guard: already registered
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
            // Step 1: Fetch challenge
            logger.info("Step 1/6: Fetching challenge for \(appId)")
            let challengeResponse = try await network.fetchChallenge(appId: appId)
            try storage.saveState(.challengeReceived, appId: appId)

            // Step 2: Generate key pair
            logger.info("Step 2/6: Generating key pair")
            let publicKeyData = try keyManager.generateKeyPair(appId: appId)
            try storage.saveState(.keyReady, appId: appId)

            // Step 3: App Attest (best-effort)
            let attestation = await fetchAttestation(
                challenge: challengeResponse.challenge,
                appId: appId
            )

            // Step 4: Register with server
            logger.info("Step 4/6: Registering with server")
            try storage.saveState(.registering, appId: appId)

            let request = RegisterRequest(
                appId: appId,
                challenge: challengeResponse.challenge,
                publicKey: publicKeyData.base64EncodedString(),
                attestation: attestation,
                deviceMetadata: buildDeviceMetadata()
            )

            let response = try await network.registerDevice(request: request)

            // Step 5: Store result
            logger.info("Step 5/6: Storing device ID: \(response.deviceId)")
            try storage.saveDeviceId(response.deviceId, appId: appId)
            try storage.saveState(.registered, appId: appId)

            // Step 6: Return
            logger.info("Step 6/6: Registration complete")
            return RegistrationResult(status: .success, deviceId: response.deviceId)

        } catch {
            logger.error("Registration failed: \(error.localizedDescription)")
            // Reset state on failure
            try? storage.saveState(
                (currentState == .unregistered) ? .unregistered : .keyInvalid,
                appId: appId
            )
            keyManager.deleteKey(appId: appId)

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
        guard storage.loadState(appId: appId) == .registered else {
            throw SynheartAuthError.notRegistered
        }

        guard let deviceId = storage.loadDeviceId(appId: appId) else {
            throw SynheartAuthError.notRegistered
        }

        do {
            // Generate new key pair
            logger.info("Rotating key: generating new key pair")
            let newPublicKeyData = try keyManager.generateNextKeyPair(appId: appId)

            // Sign the new public key with the old key (proof of possession)
            let oldKeySignature = try keyManager.sign(data: newPublicKeyData, appId: appId)

            // Transition to registering state for rotation
            try storage.saveState(.registering, appId: appId)

            // Send rotation request
            let request = RotateKeyRequest(
                appId: appId,
                deviceId: deviceId,
                newPublicKey: newPublicKeyData.base64EncodedString(),
                oldKeySignature: oldKeySignature.base64EncodedString()
            )

            let response = try await network.rotateKey(request: request)

            guard response.status == "ok" || response.status == "success" else {
                throw SynheartAuthError.serverError(code: "ROTATION_FAILED", message: response.status)
            }

            // Promote: atomic swap
            try keyManager.promoteNextKey(appId: appId)
            try storage.saveState(.registered, appId: appId)

            logger.info("Key rotation complete for \(appId)")
            return RotationResult(status: .success)

        } catch {
            logger.error("Key rotation failed: \(error.localizedDescription)")
            // Cleanup: delete the _next key, restore state
            keyManager.deleteNextKey(appId: appId)
            try? storage.saveState(.registered, appId: appId)

            if let authError = error as? SynheartAuthError {
                return RotationResult(status: .failed, error: authError)
            }
            return RotationResult(status: .failed, error: .networkError(error.localizedDescription))
        }
    }

    // MARK: - App Attest

    private func fetchAttestation(challenge: String, appId: String) async -> String? {
        #if canImport(DeviceCheck) && !targetEnvironment(simulator)
        guard DCAppAttestService.shared.isSupported else {
            logger.warning("App Attest not supported on this device")
            return nil
        }

        do {
            let keyId = try await DCAppAttestService.shared.generateKey()
            let challengeHash = Data(SHA256.hash(data: Data(challenge.utf8)))
            let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: challengeHash)
            return attestation.base64EncodedString()
        } catch {
            logger.warning("App Attest failed (non-fatal): \(error.localizedDescription)")
            return nil
        }
        #else
        logger.info("App Attest not available (simulator/macOS)")
        return nil
        #endif
    }

    // MARK: - Device Metadata

    private func buildDeviceMetadata() -> DeviceMetadata {
        let osVersion: String
        let model: String
        let secureEnclave: Bool

        #if os(iOS)
        osVersion = UIDevice.current.systemVersion
        model = UIDevice.current.model
        #else
        let processInfo = ProcessInfo.processInfo
        osVersion = processInfo.operatingSystemVersionString
        model = "Mac"
        #endif

        #if targetEnvironment(simulator)
        secureEnclave = false
        #else
        secureEnclave = true
        #endif

        return DeviceMetadata(
            platform: "iOS",
            osVersion: osVersion,
            model: model,
            secureEnclave: secureEnclave
        )
    }
}
