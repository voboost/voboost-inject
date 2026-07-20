## MODIFIED Requirements

### Requirement: Streaming APK entry inflate
The daemon's inject-payload reader SHALL verify an appended ed25519 signature
over the ELF bytes of the staged inject file (trailing `VOBSIG1` block), not
inflate a ZIP entry. There is no APK ZIP reader, no central-directory walk, no
deflate/inflate path, and no per-entry uncompressed-size handling in the
trusted code path. The trailing 64-byte raw ed25519 signature is verified via
Monocypher's `Ed25519.check` (detached, over the raw ELF bytes — the library
hashes internally with SHA-512); the daemon does not compute a separate sha256
for signature verification.

#### Scenario: Appended signature over the ELF bytes
- **WHEN** the daemon reads the staged inject file
- **THEN** it locates the trailing block by the `VOBSIG1` magic, reads
  `SIG_OFFSET`, slices the ELF bytes `[0..SIG_OFFSET)`, and verifies the
  64-byte signature over those bytes against `EMBEDDED_PUBKEY` — no ZIP
  parsing and no inflate step is involved
