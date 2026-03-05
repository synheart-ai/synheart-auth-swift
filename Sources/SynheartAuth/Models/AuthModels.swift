import Foundation

/// Status of a device registration attempt.
public enum RegistrationStatus: String, Sendable {
    case success
    case alreadyRegistered
    case failed
}

/// Result of `registerDevice(appId:)`.
public struct RegistrationResult: Sendable {
    public let status: RegistrationStatus
    public let deviceId: String?
    public let error: SynheartAuthError?

    public init(status: RegistrationStatus, deviceId: String? = nil, error: SynheartAuthError? = nil) {
        self.status = status
        self.deviceId = deviceId
        self.error = error
    }
}

/// Status of a key rotation attempt.
public enum RotationStatus: String, Sendable {
    case success
    case failed
}

/// Result of `rotateKey(appId:)`.
public struct RotationResult: Sendable {
    public let status: RotationStatus
    public let error: SynheartAuthError?

    public init(status: RotationStatus, error: SynheartAuthError? = nil) {
        self.status = status
        self.error = error
    }
}

/// Headers to attach to every authenticated HTTP request.
public struct SignedHeaders: Sendable, Equatable {
    public let appId: String
    public let deviceId: String
    public let signature: String
    public let timestamp: String
    public let nonce: String
    public let signatureVersion: String

    /// Returns headers as a dictionary suitable for URLRequest.
    public var dictionary: [String: String] {
        [
            "X-App-ID": appId,
            "X-Device-ID": deviceId,
            "X-Synheart-Signature": signature,
            "X-Synheart-Timestamp": timestamp,
            "X-Synheart-Nonce": nonce,
            "X-Synheart-Sig-Version": signatureVersion,
        ]
    }

    public init(
        appId: String,
        deviceId: String,
        signature: String,
        timestamp: String,
        nonce: String,
        signatureVersion: String = "1"
    ) {
        self.appId = appId
        self.deviceId = deviceId
        self.signature = signature
        self.timestamp = timestamp
        self.nonce = nonce
        self.signatureVersion = signatureVersion
    }
}
