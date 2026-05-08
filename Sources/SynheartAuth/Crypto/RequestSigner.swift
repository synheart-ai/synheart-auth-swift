import Foundation
import CryptoKit

/// Constructs the signing message and produces `SignedHeaders` for every HTTP request.
///
/// This is **synchronous** — `SecKeyCreateSignature` is sync, so no async overhead
/// on every HTTP request.
final class RequestSigner: @unchecked Sendable {
    private let keyManager: KeyManaging
    private let storage: StorageManaging
    private let clockSkew: ClockSkewTracker
    private let logger = AuthLogger.shared

    init(keyManager: KeyManaging, storage: StorageManaging, clockSkew: ClockSkewTracker) {
        self.keyManager = keyManager
        self.storage = storage
        self.clockSkew = clockSkew
    }

    /// Sign an HTTP request, returning all required auth headers.
    ///
    /// Message format: `method + "\n" + path + "\n" + timestamp + "\n" + bodyBytes`
    /// The message is SHA-256 hashed, then ECDSA-signed in the Secure Enclave.
    func sign(
        appId: String,
        method: String,
        path: String,
        bodyBytes: Data?
    ) throws -> SignedHeaders {
        guard let deviceId = storage.loadDeviceId(appId: appId) else {
            throw SynheartAuthError.notRegistered
        }

        let timestamp = clockSkew.correctedTimestamp()
        let nonce = UUID().uuidString

        // Construct the signing message
        let message = buildMessage(
            method: method,
            path: path,
            timestamp: timestamp,
            bodyBytes: bodyBytes
        )

        // Sign the message
        let signatureData = try keyManager.sign(data: message, appId: appId)
        let signatureBase64 = signatureData.base64EncodedString()

        return SignedHeaders(
            appId: appId,
            deviceId: deviceId,
            signature: signatureBase64,
            timestamp: timestamp,
            nonce: nonce
        )
    }

    /// Build the canonical message bytes for signing.
    func buildMessage(method: String, path: String, timestamp: String, bodyBytes: Data?) -> Data {
        var message = Data()
        message.append(Data(method.uppercased().utf8))
        message.append(Data("\n".utf8))
        message.append(Data(path.utf8))
        message.append(Data("\n".utf8))
        message.append(Data(timestamp.utf8))
        message.append(Data("\n".utf8))
        if let body = bodyBytes {
            message.append(body)
        }
        return message
    }
}
