import Foundation

// MARK: - API Envelope

/// Generic wrapper for Synheart API responses: {"success":true,"data":{...}}
struct ApiEnvelope<T: Decodable>: Decodable {
    let success: Bool?
    let data: T?

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.success = try container.decodeIfPresent(Bool.self, forKey: .success)
        self.data = try container.decodeIfPresent(T.self, forKey: .data)
    }

    enum CodingKeys: String, CodingKey {
        case success, data
    }
}

// MARK: - Challenge

struct ChallengeRequest: Codable {
    let appId: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
    }
}

/// Internal model matching the API's data payload
struct ChallengeDataPayload: Decodable {
    let challenge: String
    let expiresIn: Int?
    let expiresAt: String?

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresIn = "expires_in"
        case expiresAt = "expires_at"
    }
}

struct ChallengeResponse: Codable {
    let challenge: String
    let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresAt = "expires_at"
    }

    /// Parse from API envelope or flat response
    static func fromApiData(_ data: Data) throws -> ChallengeResponse {
        let decoder = JSONDecoder()
        // Try envelope format first
        if let envelope = try? decoder.decode(ApiEnvelope<ChallengeDataPayload>.self, from: data),
           let payload = envelope.data {
            let expiresAt: String
            if let ea = payload.expiresAt {
                expiresAt = ea
            } else if let ei = payload.expiresIn {
                expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval(ei)))
            } else {
                expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(300))
            }
            return ChallengeResponse(challenge: payload.challenge, expiresAt: expiresAt)
        }
        // Fallback: flat format
        return try decoder.decode(ChallengeResponse.self, from: data)
    }
}

// MARK: - Register

struct RegisterRequest: Codable {
    let appId: String
    let deviceId: String
    let challenge: String
    let publicKey: String
    let platform: String
    let proof: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case deviceId = "device_id"
        case challenge
        case publicKey = "public_key"
        case platform
        case proof
    }
}

/// Internal model for parsing the register response payload
struct RegisterDataPayload: Decodable {
    let deviceId: String
    let appId: String?
    let platform: String?
    let registered: Bool?
    let status: String?

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case appId = "app_id"
        case platform
        case registered
        case status
    }
}

struct RegisterResponse: Codable {
    let deviceId: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case status
    }

    static func fromApiData(_ data: Data) throws -> RegisterResponse {
        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(ApiEnvelope<RegisterDataPayload>.self, from: data),
           let payload = envelope.data {
            let status: String
            if let s = payload.status {
                status = s
            } else if payload.registered == true {
                status = "success"
            } else {
                status = "failed"
            }
            return RegisterResponse(deviceId: payload.deviceId, status: status)
        }
        return try decoder.decode(RegisterResponse.self, from: data)
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

    static func fromApiData(_ data: Data) throws -> RotateKeyResponse {
        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(ApiEnvelope<RotateKeyResponse>.self, from: data),
           let payload = envelope.data {
            return payload
        }
        return try decoder.decode(RotateKeyResponse.self, from: data)
    }
}

// MARK: - Error

struct AuthErrorResponse: Decodable {
    let code: String
    let message: String
    let serverTimestamp: Double?

    init(code: String, message: String, serverTimestamp: Double? = nil) {
        self.code = code
        self.message = message
        self.serverTimestamp = serverTimestamp
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.code = (try? container.decode(String.self, forKey: .errorCode))
            ?? (try? container.decode(String.self, forKey: .code))
            ?? (try? container.decode(String.self, forKey: .error))
            ?? "UNKNOWN"
        self.message = (try? container.decode(String.self, forKey: .errorDescription))
            ?? (try? container.decode(String.self, forKey: .message))
            ?? "Unknown error"
        self.serverTimestamp = try? container.decode(Double.self, forKey: .serverTimestamp)
    }

    enum CodingKeys: String, CodingKey {
        case code
        case message
        case error
        case errorCode = "error_code"
        case errorDescription = "error_description"
        case serverTimestamp = "server_timestamp"
    }
}
