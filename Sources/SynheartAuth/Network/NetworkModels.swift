import Foundation

// MARK: - Challenge

struct ChallengeRequest: Codable {
    let appId: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
    }
}

struct ChallengeResponse: Codable {
    let challenge: String
    let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresAt = "expires_at"
    }
}

// MARK: - Register

struct RegisterRequest: Codable {
    let appId: String
    let challenge: String
    let publicKey: String
    let attestation: String?
    let deviceMetadata: DeviceMetadata?

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case challenge
        case publicKey = "public_key"
        case attestation
        case deviceMetadata = "device_metadata"
    }
}

struct DeviceMetadata: Codable {
    let platform: String
    let osVersion: String
    let model: String
    let secureEnclave: Bool

    enum CodingKeys: String, CodingKey {
        case platform
        case osVersion = "os_version"
        case model
        case secureEnclave = "secure_enclave"
    }
}

struct RegisterResponse: Codable {
    let deviceId: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case status
    }
}

// MARK: - Rotate Key

struct RotateKeyRequest: Codable {
    let appId: String
    let deviceId: String
    let newPublicKey: String
    let oldKeySignature: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case deviceId = "device_id"
        case newPublicKey = "new_public_key"
        case oldKeySignature = "old_key_signature"
    }
}

struct RotateKeyResponse: Codable {
    let status: String
}

// MARK: - Error

struct AuthErrorResponse: Codable {
    let code: String
    let message: String
    let serverTimestamp: Double?

    enum CodingKeys: String, CodingKey {
        case code
        case message
        case serverTimestamp = "server_timestamp"
    }
}
