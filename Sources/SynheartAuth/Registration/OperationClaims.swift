import Foundation

/// Process-wide registry of the appIds with a register / rotate / invalidate
/// operation running *in this process*.
///
/// The persisted `DeviceAuthState` cannot tell a live registration from one
/// whose process was killed: both read `challengeReceived`, `keyReady` or
/// `registering`. This registry can. If an intermediate state is on disk but
/// no claim is held here, the operation that wrote it is dead — it belonged to
/// an earlier process — and `DeviceRegistrar` recovers it instead of refusing
/// with `registrationInProgress` forever.
///
/// It is static (not per `DeviceRegistrar`) because `SynheartAuth.configure`
/// builds a new registrar on every call; a per-instance set would let a
/// re-configure during a registration start a second, concurrent one.
enum OperationClaims {
    private static let lock = NSLock()
    private static var inFlight: Set<String> = []

    /// Atomic test-and-set. Returns `false` if `appId` is already claimed.
    static func claim(_ appId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return inFlight.insert(appId).inserted
    }

    static func release(_ appId: String) {
        lock.lock()
        defer { lock.unlock() }
        inFlight.remove(appId)
    }
}

/// Metadata keys recording which multi-step operation wrote an intermediate
/// state, so a later process can recover it correctly. Stored alongside the
/// state in the Keychain via `StorageManaging.saveMetadata`.
enum PendingOperation: String {
    case register
    case rotate

    static let opKey = "pending_op"
    static let priorStateKey = "pending_prior_state"
    static let startedAtKey = "pending_started_at"
}

/// Moves an identity whose signing key is provably gone into `.keyInvalid`,
/// from which `registerDevice` re-registers.
///
/// Only acts when the state is `.registered`: any other state is either
/// already invalid or owned by a register/rotate flow. The caller must hold
/// the `OperationClaims` claim for `appId`. The device id is kept, so the
/// re-registration reuses it (as `DeviceRegistrar.register` always has).
@discardableResult
func invalidateRegisteredIdentity(
    appId: String,
    keyManager: KeyManaging,
    storage: StorageManaging
) -> Bool {
    guard storage.loadState(appId: appId) == .registered else { return false }
    keyManager.deleteKey(appId: appId)
    do {
        try storage.saveState(.keyInvalid, appId: appId)
    } catch {
        AuthLogger.shared.error("Could not persist keyInvalid: \(error.localizedDescription, privacy: .private)")
        return false
    }
    AuthLogger.shared.warning("Signing key is gone — identity marked keyInvalid; registerDevice will re-register")
    return true
}
