import Foundation

/// Public facade for the Synheart device authentication SDK.
///
/// Usage:
/// ```swift
/// // 1. Configure once at app launch
/// SynheartAuth.shared.configure(baseUrl: "https://auth.synheart.io")
///
/// // 2. Register device (once)
/// let result = try await SynheartAuth.shared.registerDevice(appId: "com.myapp")
///
/// // 3. Sign every HTTP request
/// let headers = try SynheartAuth.shared.signRequest(
///     appId: "com.myapp",
///     method: "POST",
///     path: "/v1/data",
///     bodyBytes: jsonData
/// )
/// ```
public final class SynheartAuth: @unchecked Sendable {
    /// Singleton instance.
    public static let shared = SynheartAuth()

    private var registrar: DeviceRegistrar?
    private var signer: RequestSigner?
    private var storageManager: StorageManaging = StorageManager()
    private var keyManager: KeyManaging = KeyManager()
    private let clockSkew = ClockSkewTracker()
    private let logger = AuthLogger.shared
    private let lock = NSLock()

    private var isConfigured: Bool {
        lock.lock()
        defer { lock.unlock() }
        return registrar != nil
    }

    private init() {}

    /// Internal initializer for testing with injected dependencies.
    init(
        keyManager: KeyManaging,
        storage: StorageManaging,
        network: AuthNetworking
    ) {
        self.keyManager = keyManager
        self.storageManager = storage
        self.signer = RequestSigner(keyManager: keyManager, storage: storage, clockSkew: clockSkew)
        self.registrar = DeviceRegistrar(keyManager: keyManager, storage: storage, network: network)
    }

    // MARK: - Configuration

    /// Configure the SDK with the auth service base URL. Must be called before any other method.
    public func configure(baseUrl: String) {
        guard let url = URL(string: baseUrl) else {
            logger.error("Invalid base URL: \(baseUrl)")
            return
        }

        lock.lock()
        defer { lock.unlock() }

        let network = AuthNetworkClient(baseUrl: url)
        self.signer = RequestSigner(keyManager: keyManager, storage: storageManager, clockSkew: clockSkew)
        self.registrar = DeviceRegistrar(keyManager: keyManager, storage: storageManager, network: network)
        logger.info("SynheartAuth configured with base URL: \(baseUrl)")
    }

    // MARK: - Registration

    /// Check if a device is already registered for the given app.
    public func isRegistered(appId: String) -> Bool {
        storageManager.loadState(appId: appId) == .registered
            && storageManager.loadDeviceId(appId: appId) != nil
    }

    /// Register this device with the Synheart auth service.
    ///
    /// This is idempotent — if already registered, returns `.alreadyRegistered`.
    public func registerDevice(appId: String) async throws -> RegistrationResult {
        guard let registrar = getRegistrar() else {
            throw SynheartAuthError.notConfigured
        }
        return try await registrar.register(appId: appId)
    }

    // MARK: - Request Signing

    /// Sign an HTTP request. This is **synchronous** for minimal overhead.
    ///
    /// - Parameters:
    ///   - appId: The app identifier
    ///   - method: HTTP method (GET, POST, etc.)
    ///   - path: Request path (e.g., "/v1/data")
    ///   - bodyBytes: Raw request body bytes (nil for GET requests)
    /// - Returns: `SignedHeaders` containing all required auth headers
    public func signRequest(
        appId: String,
        method: String,
        path: String,
        bodyBytes: Data? = nil
    ) throws -> SignedHeaders {
        guard let signer = getSigner() else {
            throw SynheartAuthError.notConfigured
        }
        return try signer.sign(appId: appId, method: method, path: path, bodyBytes: bodyBytes)
    }

    // MARK: - Device ID

    /// Get the device ID for the given app, or nil if not registered.
    public func getDeviceId(appId: String) -> String? {
        storageManager.loadDeviceId(appId: appId)
    }

    // MARK: - Key Rotation

    /// Rotate the device key. The old key signs the new public key as proof of possession.
    public func rotateKey(appId: String) async throws -> RotationResult {
        guard let registrar = getRegistrar() else {
            throw SynheartAuthError.notConfigured
        }
        return try await registrar.rotateKey(appId: appId)
    }

    // MARK: - Reset

    /// Destructive: delete all local auth state for this app. The device will need to re-register.
    public func resetDeviceIdentity(appId: String) {
        keyManager.deleteKey(appId: appId)
        storageManager.deleteAll(appId: appId)
        logger.warning("Device identity reset for \(appId)")
    }

    // MARK: - Clock Skew

    /// Correct clock skew using a server-provided timestamp (seconds since epoch).
    ///
    /// Call this when you receive a CLOCK_SKEW error from the server.
    public func correctClockSkew(serverTimestamp: TimeInterval) {
        clockSkew.update(serverTimestamp: serverTimestamp)
    }

    // MARK: - Private Helpers

    private func getRegistrar() -> DeviceRegistrar? {
        lock.lock()
        defer { lock.unlock() }
        return registrar
    }

    private func getSigner() -> RequestSigner? {
        lock.lock()
        defer { lock.unlock() }
        return signer
    }
}
