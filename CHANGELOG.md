# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — an interrupted registration no longer blocks registration forever

- **A registration killed mid-flow was permanent.** The state is persisted in
  the Keychain, and `registerDevice` refused anything but `unregistered` /
  `keyInvalid` with `registrationInProgress`. An app killed while the state
  was `challengeReceived`, `keyReady` or `registering` could therefore never
  register again without `resetDeviceIdentity`. The same applied to a key
  rotation killed while `registering`, which also made `rotateKey` throw
  `notRegistered`.
  `registrationInProgress` is now decided by a **process-wide** in-flight
  claim (shared across `configure` calls, which build a new registrar each
  time). An intermediate state on disk with no claim in this process belongs
  to a dead process and is recovered before the new attempt:
  - registration → the half-made key is deleted and the state returns to
    what it was before the attempt (`unregistered` or `keyInvalid`); the call
    then runs a fresh registration with a new challenge and a new key;
  - rotation → old + new key present: keep the key the server last
    confirmed, discard the new one; only the new key present (the swap had
    started, so the server had confirmed): finish it; no key: `keyInvalid`.
  Register and rotate now record which operation is pending (and the state to
  return to) in the Keychain metadata, so recovery does not have to guess;
  states written by 0.1.2 are classified by whether a device id is stored.
  If key presence cannot be read during recovery the call throws
  `keychainError` and leaves the state untouched.

### Fixed — a lost signing key can re-register

- **`keyInvalidated` left the state `registered`**, so `registerDevice`
  answered `alreadyRegistered` and the app could not recover without
  `resetDeviceIdentity`. `keyInvalid` was in the state machine but never
  entered. Now, when `signRequest` or `rotateKey` finds the signing key gone,
  the keys are deleted and the state becomes `keyInvalid`; `isRegistered`
  returns `false` and the next `registerDevice` re-registers under the same
  device id. Skipped while a register/rotate in this process owns the state.
- **A Keychain that cannot be read is no longer reported as an invalidated
  key.** `KeyManager.sign` threw `keyInvalidated` for any failed key lookup,
  including a locked device (`errSecInteractionNotAllowed`). With
  invalidation now acting on the state, that would have destroyed a valid
  identity, so only `errSecItemNotFound` means `keyInvalidated`; other
  statuses throw `keychainError(OSStatus)` and change nothing.

### Fixed — log privacy

- The README promised privacy-annotated logs, but `AuthLogger` logged every
  message with `privacy: .public`, so app ids, key tags, challenges, the
  debug public key, server error bodies and error descriptions reached the
  unified log unredacted. Call sites now log through `os.Logger` directly
  with a privacy level per value: identifiers `.private(mask: .hash)`,
  challenges / key material / server bodies / error descriptions `.private`,
  status text, counts, HTTP and `OSStatus` codes `.public`. The FFI bridge's
  device ids, Keychain account names and Secure Enclave error descriptions
  are `.private` too. The network client logs the URL path rather than the
  full URL.

### Changed

- `rotateKey` called while a registration for the same app id is running in
  this process now throws `registrationInProgress` (was `notRegistered`).

### Tests
- `RegistrationRecoveryTests`: recovery from each intermediate state (with and
  without the pending marker), a registration parked in `registering` whose
  process dies, concurrent registrations in one process, the three
  interrupted-rotation outcomes, an unreadable Keychain during recovery,
  re-registration after key loss (via `signRequest` and via `rotateKey`), and
  an unreadable key that must not invalidate the identity.
- Test challenges expired on 2026-12-31; they now expire in 2099.

### Known, not changed here
- The signed message is `METHOD\nPATH\nTIMESTAMP\nBODY`: the nonce,
  `X-App-ID`, `X-Device-ID` and the query string are not covered by the
  signature. Changing that is a protocol change that needs the server.
- CocoaPods trunk has only `0.1.0`; `0.1.1` and `0.1.2` were tagged but not
  pushed. The podspec already matches `Package.swift` (iOS 15, macOS 13,
  Swift 5.9).

## [0.1.2] - 2026-09-24

### Fixed — Keychain reads no longer report a failed read as "no such item"

- **FFI: `synheart_native_secure_load` returned NULL for every Keychain status
  other than success** — including `errSecInteractionNotAllowed` (device
  locked / before first unlock) and `errSecNotAvailable` (`securityd` not
  ready right after boot). The runtime reads NULL as "absent", so one such
  launch minted a new storage master key over the existing one and orphaned
  every sealed blob. Absence (`errSecItemNotFound`) is now the only immediate
  NULL; transient statuses are retried with a bounded ~1.5 s backoff; other
  failures are logged with their `OSStatus`. A non-UTF-8 item is reported as
  unavailable, not absent. The callback still has to return NULL when the
  Keychain is genuinely unavailable — the C signature has no error channel.
  On runtime ≥ 0.31.1 the provisioning marker turns that into
  `ERR_SECURE_STORAGE_UNAVAILABLE` (retryable) rather than a re-mint; older
  runtimes keep the re-mint exposure.
- **FFI: `synheart_native_key_exists` and `synheart_native_sign_bytes` read
  the Secure Enclave key handle through the same three-way classification.**
  Before, a locked or not-yet-ready Keychain made `key_exists` answer `0`,
  which the runtime's identity restore reads as "platform key missing" and
  reports the device as unregistered — the next registration then mints a
  fresh identity. The retry covers the transient statuses and the failure is
  logged; `0` is still the only thing the callback can say when the Keychain
  stays unavailable. The cached App Attest key id is read the same way.

### Documentation
- README: version badge and the SwiftPM coordinate now match the released
  version (they still said `0.1.0` against a `0.1.1` podspec).

## [0.1.1] - 2026-06-28

### Fixed
- App Attest attestation is now bounded by a 30-second timeout on both paths.
  The FFI bridge (`synheart_native_get_attestation`) replaced its unbounded
  `DispatchSemaphore.wait()` with `wait(timeout:)`, and `DeviceRegistrar`'s
  `fetchAttestation` wraps its `generateKey`/`attestKey` calls in a task-group
  timeout. App Attest normally returns an error rather than hanging, but the
  network-backed calls can stall on a degraded connection or an unresponsive
  attestation service; without a cap the calling thread (FFI) or the
  registration task (`DeviceRegistrar`) could block indefinitely instead of
  failing fast. A timeout is now treated as "attestation unavailable" (returns
  `nil`).
- FFI: the attestation result is now held in a reference-counted box instead of
  a manually managed `UnsafeMutablePointer` that was deallocated on return. With
  the new timeout the detached attestation `Task` can outlive the call; the
  ref-counted box keeps a late write landing on a live object rather than freed
  memory.

## [0.1.0] - 2026-03-04

### Added

- **SynheartAuth** singleton facade — thread-safe with NSLock, `@unchecked Sendable`
- **Secure Enclave key management** — ECDSA P-256 non-exportable keys with software fallback on Simulator
- **Request signing** — `signRequest()` constructs `METHOD\nPATH\nTIMESTAMP\nBODY` message and signs with ECDSA
- **Device registration** — challenge-response flow with `DeviceRegistrar`
- **Key rotation** — old key signs new public key as proof of possession
- **Keychain storage** — persistent device ID, auth state, and metadata via `StorageManager`
- **Clock skew correction** — `ClockSkewTracker` with server timestamp alignment
- **Network client** — URLSession-based `AuthNetworkClient` for auth service API
- **Privacy-protected logging** — Apple `os.Logger` with privacy annotations
- **Error types** — `SynheartAuthError` enum with `LocalizedError`, `Equatable`, `Sendable` conformance
- **State machine** — `DeviceAuthState` with `RawRepresentable` for Keychain persistence
- **Unit tests** — 7 test files covering all components
- **Mock implementations** — `MockKeyManager`, `MockAuthNetworkClient` for testing
