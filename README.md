🌐 [synheart.ai](https://synheart.ai) — Human State Interface (HSI) infrastructure for developers and AI systems.

# SynheartAuth (Swift)

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/synheart-ai/synheart-auth-swift)
[![Swift](https://img.shields.io/badge/swift-5.9+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-iOS%2015%2B%20%7C%20macOS%2013%2B-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)


> **Source-available.** This repository is open for reading, auditing, and
> filing issues. We do **not** accept pull requests — see
> [CONTRIBUTING.md](CONTRIBUTING.md) for the rationale and how to contribute
> via issues. Security reports go through [SECURITY.md](SECURITY.md).
Hardware-backed device authentication SDK for iOS and macOS. Uses Secure Enclave for non-exportable ECDSA P-256 key storage and request signing.

> See [RFC-AUTH-MOBILE-0001](https://github.com/synheart-ai/synheart-auth/blob/main/docs/RFC-AUTH-MOBILE-0001.md) for the full specification.

## Repository Structure

| Repository | Purpose |
|------------|---------|
| [synheart-auth](https://github.com/synheart-ai/synheart-auth) | RFC and specification |
| [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) | iOS/Swift native SDK (this repository) |
| [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) | Android/Kotlin native SDK |
| [synheart-auth-flutter](https://github.com/synheart-ai/synheart-auth-flutter) | Flutter plugin |

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/synheart-ai/synheart-auth-swift.git", from: "0.1.0"),
]
```

Or in Xcode: File > Add Package Dependencies, enter the repository URL.

## Quick Start

```swift
import SynheartAuth

// 1. Configure once at app launch
SynheartAuth.shared.configure(baseUrl: "https://api.synheart.ai/auth")

// 2. Register device (one-time)
let result = try await SynheartAuth.shared.registerDevice(appId: "com.myapp")
print("Device ID: \(result.deviceId ?? "N/A")")

// 3. Sign every HTTP request
let headers = try SynheartAuth.shared.signRequest(
    appId: "com.myapp",
    method: "POST",
    path: "/ingest/v1/hsi",
    bodyBytes: bodyData
)
// Apply headers.appId, headers.deviceId, headers.signature, etc.
```

## API Reference

### `SynheartAuth`

| Method | Description |
|--------|-------------|
| `configure(baseUrl:)` | Set the auth service URL. Must be called first. |
| `isRegistered(appId:)` | Check if device is registered for this app. |
| `registerDevice(appId:)` | Register device with auth service. Idempotent. |
| `signRequest(...)` | Sign an HTTP request. Returns `SignedHeaders`. |
| `getDeviceId(appId:)` | Get the device ID, or nil if not registered. |
| `rotateKey(appId:)` | Rotate the device key. Old key signs new key. |
| `resetDeviceIdentity(appId:)` | Delete all local auth state. |
| `correctClockSkew(serverTimestamp:)` | Correct clock offset using server timestamp. |

### Security Architecture

- **Key Storage**: Secure Enclave (hardware) on device, software fallback on Simulator
- **Algorithm**: ECDSA P-256 (secp256r1) with SHA-256
- **Persistence**: Keychain (device ID, state, metadata)
- **Thread Safety**: NSLock + `@unchecked Sendable` for async contexts
- **Logging**: Apple `os.Logger` with privacy annotations

### Error Handling

All errors are cases of `SynheartAuthError`:

| Error | Description |
|-------|-------------|
| `.networkError(String)` | Network connectivity failure |
| `.challengeExpired` | Registration challenge timed out |
| `.attestationUnavailable` | Platform attestation not available |
| `.keyInvalidated` | Key invalidated (biometric change, etc.) |
| `.clockSkew` | Client/server clock difference too large |
| `.alreadyRegistered` | Device already registered |
| `.notRegistered` | Device not yet registered |
| `.notConfigured` | `configure()` not called |
| `.keychainError(OSStatus)` | Keychain operation failed |
| `.cryptoError(String)` | Cryptographic operation failed |
| `.serverError(code:message:)` | Server returned an error |

## Testing

```bash
swift test
```

Mock implementations (`MockKeyManager`, `MockAuthNetworkClient`) are included for testing.

## Not a Medical Device

This SDK is intended for wellness and research use only. It is not a medical device, is not intended to diagnose, treat, cure, or prevent any disease or condition, and has not been evaluated by the FDA or any other regulatory body.

## License

Apache License 2.0 — see [LICENSE](LICENSE).