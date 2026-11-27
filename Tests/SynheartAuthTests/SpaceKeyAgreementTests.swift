import XCTest
import CryptoKit
@testable import SynheartAuth

/// Space sharing: the `*.space.agreement` alias and the P-256 ECDH the
/// runtime asks for through `synheart_native_key_agreement`. The Secure
/// Enclave is not available under `swift test`, so the agreement itself is
/// checked with software P-256 keys through the same helpers.
final class SpaceKeyAgreementTests: XCTestCase {

    func testOnlyTheAgreementAliasIsAnAgreementKey() {
        XCTAssertTrue(isAgreementAlias("3f2a9c1e-5b7d.space.agreement"))
        XCTAssertFalse(isAgreementAlias("3f2a9c1e-5b7d"))
        XCTAssertFalse(isAgreementAlias("3f2a9c1e-5b7d.space.content"))
        XCTAssertFalse(isAgreementAlias("3f2a9c1e-5b7d.space.agreement.old"))
    }

    func testPeerMustBeAnUncompressedPoint() {
        let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        XCTAssertNotNil(agreementPeerKey(point))

        XCTAssertNil(agreementPeerKey(Data(point.dropLast())), "64 bytes")
        var compressedPrefix = point
        compressedPrefix[0] = 0x02
        XCTAssertNil(agreementPeerKey(compressedPrefix), "not 0x04")
        var offCurve = point
        offCurve[64] ^= 0x01
        XCTAssertNil(agreementPeerKey(offCurve), "not on the curve")
    }

    func testBothSidesWriteTheSame32ByteSecret() throws {
        let a = P256.KeyAgreement.PrivateKey()
        let b = P256.KeyAgreement.PrivateKey()
        let peerOfA = try XCTUnwrap(agreementPeerKey(b.publicKey.x963Representation))
        let peerOfB = try XCTUnwrap(agreementPeerKey(a.publicKey.x963Representation))

        var outA = [UInt8](repeating: 0, count: 32)
        var outB = [UInt8](repeating: 0, count: 32)
        XCTAssertTrue(writeSharedSecret(try a.sharedSecretFromKeyAgreement(with: peerOfA), to: &outA))
        XCTAssertTrue(writeSharedSecret(try b.sharedSecretFromKeyAgreement(with: peerOfB), to: &outB))

        XCTAssertEqual(outA, outB)
        XCTAssertNotEqual(outA, [UInt8](repeating: 0, count: 32))
    }

    func testInvalidPeerFailsBeforeAnyKeyLookup() {
        let alias = "test-device.space.agreement"
        var peer = [UInt8](repeating: 0, count: 65)  // 0x00 first: not a point
        var out = [UInt8](repeating: 0xAA, count: 32)
        let rc = alias.withCString { aliasPtr in
            synheart_native_key_agreement(aliasPtr, &peer, peer.count, &out)
        }
        XCTAssertEqual(rc, 1)
        XCTAssertEqual(out, [UInt8](repeating: 0xAA, count: 32), "out untouched on failure")
    }

    func testMissingKeyFails() {
        let alias = "no-such-device-\(UUID().uuidString).space.agreement"
        var peer = [UInt8](P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        var out = [UInt8](repeating: 0, count: 32)
        let rc = alias.withCString { aliasPtr in
            synheart_native_key_agreement(aliasPtr, &peer, peer.count, &out)
        }
        XCTAssertEqual(rc, 1)
    }
}
