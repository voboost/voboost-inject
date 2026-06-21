// Minimal vapi binding Monocypher's RFC 8032 Ed25519 (SHA-512) detached verify.
// crypto_ed25519_check returns 0 for a valid signature, -1 for a forgery; it is
// the SHA-512 variant compatible with the OpenSSL-produced manifest signature.
// Provided by the monocypher meson subproject (subprojects/monocypher.wrap);
// no external system crypto library. See trust-verification spec (D4, D9b, D9d).
[CCode (cheader_filename = "monocypher-ed25519.h")]
namespace Ed25519 {
    // signature: 64 bytes; public_key: 32 bytes; message + its length. Returns
    // 0 on success (valid), -1 on failure (forgery).
    [CCode (cname = "crypto_ed25519_check")]
    public int check ([CCode (array_length = false)] uint8[] signature,
                      [CCode (array_length = false)] uint8[] public_key,
                      [CCode (array_length = false)] uint8[] message,
                      size_t message_size);
}
