# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
