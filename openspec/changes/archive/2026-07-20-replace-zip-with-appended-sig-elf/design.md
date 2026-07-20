## Context

The daemon self-update consumes a single artifact: the new daemon ELF. Today
that ELF is wrapped in a ZIP named `voboost-inject.apk` alongside two more
entries (`assets/manifest.json`, `assets/manifest.sig`) carrying the daemon's
per-agent manifest. The architectural shift puts the per-agent manifest inside
the **app** APK (`docs/17-ota-architecture.md` §4.1), leaving the daemon
self-update payload as one thing: the ELF. Carrying a single ELF inside a ZIP
wrapper — and naming the wrapper `.apk` — is misleading (it is not
Android-signed) and forces the daemon's trusted code path to carry a ~200-line
minimal ZIP central-directory reader with its own inflate path. That reader is
attack surface that exists only to undo a packaging decision.

This change replaces the ZIP wrapper with a single ELF file carrying an
appended ed25519 signature in trailing bytes (`docs/17-ota-architecture.md`
§4.2). The kernel loads the ELF by its header and ignores trailing bytes at
exec; the daemon's self-update reads the trailing block, re-verifies the
ed25519 signature over the ELF bytes against `EMBEDDED_PUBKEY`, and installs
only the ELF portion. One file, no ZIP, no embedded manifest in the daemon
payload.

## Goals / Non-Goals

**Goals:**
- One staged artifact (`voboost-inject`), no ZIP, no embedded manifest.
- The daemon's trusted code path sheds the ZIP reader entirely.
- The ed25519 trust model is unchanged (still `EMBEDDED_PUBKEY`, still
  re-verified on apply).
- The atomic self-replace + `.prev` rollback flow is unchanged.

**Non-Goals:**
- Changing the signature algorithm or the key family (ed25519, key-root).
- Changing the single-use `voboost-inject-update-ready` marker contract.
- Delivering the per-agent manifest via the inject payload (it rides in the
  app APK now; agent delivery is Step 4).
- Keeping backward compatibility with the old ZIP payload — this is a clean
  break, gated by a coordinated release.

## Decisions

### D1. Appended signature, not a sidecar `.sig`
The signature rides in trailing bytes of the same file, not in a separate
`.sig` file. Reasons: (a) one file to stage, download, and verify — no
"half-staged set" failure mode where the ELF lands but the `.sig` does not;
(b) the kernel ignores ELF trailing bytes at exec, so the file is both
runnable (post-install) and self-describing (pre-install); (c) the producer
contract simplifies to "write one file then create the marker". A sidecar
`.sig` would reintroduce the multi-file staging race the single-use marker
exists to prevent.

### D2. The trailing block format
```
[ ELF bytes, length = SIG_OFFSET ]
[ MAGIC      "VOBSIG1\0"   8 bytes  (ASCII, NUL-padded to 8) ]
[ SIG_OFFSET                8 bytes  (LE uint64) ]
[ SIGNATURE                64 bytes  (ed25519 over ELF bytes) ]
```
Total trailing = 80 bytes (already 16-byte aligned; no padding needed for
v1). The daemon reads the last 80 bytes, checks the magic, reads
`SIG_OFFSET`, slices `[0..SIG_OFFSET)` as the ELF, reads the 64-byte
signature, and verifies `trust.verify_signature(elf_bytes, signature)`. The
magic is the version tag: `VOBSIG1` is v1; a future v2 bumps the digit
without breaking the v1 reader's magic-length assumption.

### D3. SIG_OFFSET is authoritative, not "file size minus 80"
`SIG_OFFSET` names the exact end of the ELF part. This is robust to a
future format that appends more than the 80-byte block (e.g. a v2 with a
certificate chain after the signature). The daemon does NOT compute the
ELF length as `file_size - 80`; it trusts `SIG_OFFSET` but bounds-checks
it (`0 < SIG_OFFSET < file_size - 80` and `SIG_OFFSET` leaves room for the
trailing block). A lying `SIG_OFFSET` fails the bounds check and is
rejected.

### D4. ed25519 over raw ELF bytes, not over a sha256
`trust.verify_signature(data, signature)` is Monocyphyper RFC 8032 ed25519
detached verify, which takes the raw message (it hashes internally with
SHA-512). So `verify_appended_sig` passes the ELF byte slice directly as
`data`; there is no separate sha256 step. This matches how the existing
manifest signature verification works (`Manifest.load_verified` →
`verify_signature(json_bytes, sig_bytes)`).

### D5. REJECTED_BAD_MANIFEST is removed
The current `InjectApplyOutcome` has `REJECTED_BAD_MANIFEST` for the case
where the embedded `manifest.json`/`.sig` fail re-verification. With the
manifest gone from the payload, this outcome is unreachable and is removed.
The remaining outcomes: `APPLIED`, `REJECTED_NO_APK` (no staged file /
oversize / unreadable), `REJECTED_BAD_BINARY` (bad magic, bad signature,
truncated, lying offset, empty ELF), `REJECTED_NO_ROLLBACK` (cannot
preserve the previous binary). The supervisor's log string mapping is
updated to drop the manifest case.

### D6. `MAX_APK_BYTES` stays; `MAX_APK_ENTRIES` goes
The DoS size bound `MAX_APK_BYTES` (64 MiB) is kept — it bounds the staged
file read regardless of format. The entry-count bound `MAX_APK_ENTRIES`
existed only for the ZIP central directory and is removed with the reader.
The constant is renamed `MAX_INJECT_BYTES` for accuracy (it bounds the
staged inject payload, which is no longer an APK).

### D7. Makefile `sign-elf` — openssl + a small append
`openssl pkeyutl -sign -rawin -inkey $KEY -in $BINARY -out $SIGFILE`
produces a raw 64-byte ed25519 signature over the ELF bytes. The Makefile
target then concatenates `BINARY + "VOBSIG1\0" + LE_uint64(file_size) +
SIGFILE` to produce `build/voboost-inject`. A 10-line Python helper (stdlib
`struct` for the LE uint64) does the append; no third-party tooling. This
mirrors how `gen-fixtures.sh` will produce the signed-ELF test fixture.

## Renaming table

| Old | New |
|---|---|
| staged file `voboost-inject.apk` | `voboost-inject` (no extension) |
| `extract_apk_entry` + helpers (~200 lines) | `verify_appended_sig` (~40 lines) |
| `APK_BINARY_ENTRY` / `APK_MANIFEST_ENTRY` / `APK_MANIFEST_SIG_ENTRY` | (removed — single ELF) |
| `MAX_APK_ENTRIES` | (removed) |
| `MAX_APK_BYTES` | `MAX_INJECT_BYTES` (value unchanged: 64 MiB) |
| `InjectApplyOutcome.REJECTED_BAD_MANIFEST` | (removed) |
| Makefile `inject-apk` (ZIP) | `sign-elf` (append sig) |
| CI artifact `voboost-inject.apk` | `voboost-inject` |
| `ApkStager.INJECT_APK_NAME = "voboost-inject.apk"` | `INJECT_FILE_NAME = "voboost-inject"` |

## verify_appended_sig sketch

```vala
public static bool verify_appended_sig(
    uint8[] bytes, TrustStore trust, out uint8[] elf_bytes
) {
    elf_bytes = new uint8[0];
    const int TRAILING = 80;  // 8 magic + 8 offset + 64 signature
    if (bytes.length < TRAILING + 1) return false;  // need at least 1 ELF byte
    int trailing_start = bytes.length - TRAILING;
    // Magic: "VOBSIG1\0"
    const uint8[8] MAGIC = {'V','O','B','S','I','G','1',0};
    if (Posix.memcmp(&bytes[trailing_start], MAGIC, 8) != 0) return false;
    // SIG_OFFSET (LE uint64) — authoritative ELF length.
    uint64 sig_offset = read_le64(bytes, trailing_start + 8);
    if (sig_offset < 1 || sig_offset > trailing_start) return false;
    // Signature (64 bytes immediately after the offset).
    uint8[] sig = bytes[trailing_start + 16 : trailing_start + 16 + 64];
    // Slice the ELF part and verify.
    elf_bytes = bytes[0 : (int) sig_offset];
    return trust.verify_signature(elf_bytes, sig);
}
```

(`read_le8` is a new tiny helper next to the existing `read_le16`/`read_le32`
pattern — but those ZIP helpers are being removed, so `read_le64` is the only
LE reader left.)
