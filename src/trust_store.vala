namespace Voboost {
// Embedded public key is the only trust anchor (EMBEDDED_PUBKEY, generated
// at build time from the PEM). No key is ever read from disk. ed25519
// detached-signature verify via Monocypher's RFC 8032 crypto_ed25519_check
// (the monocypher meson subproject, bound by src/ed25519.vapi); no external
// system crypto library. sha256 via GLib.Checksum. Verification is always
// on; there is no skip-verify path (D4, D9, D9b, D9d).
public class TrustStore : Object {
public bool verify_signature(uint8[] data, uint8[] signature) {
    if (signature.length != 64 || EMBEDDED_PUBKEY.length != 32) {
        return false;
    }
    // Monocypher RFC 8032 Ed25519 (SHA-512) detached verify; returns 0
    // for a valid signature. Arg order: signature, public key, message.
    return Ed25519.check(signature, EMBEDDED_PUBKEY, data,
                         data.length) == 0;
}

public string sha256_file(string path) throws Error {
    uint8[] data;
    FileUtils.get_data(path, out data);
    return Checksum.compute_for_data(ChecksumType.SHA256, data);
}

public bool verify_agent(string path, string expected_sha256) {
    try {
        return sha256_file(path) == expected_sha256.down();
    } catch (Error e) {
        return false;
    }
}
}
}
