## Why

The staged daemon artifact is currently a ZIP named `voboost-inject.apk`
packaging three entries (`assets/manifest.json`, `assets/manifest.sig`,
`assets/voboost-inject`). The ZIP existed only because the daemon's per-agent
manifest used to ride inside the daemon payload. After the architectural shift
that puts the per-agent manifest inside the **app** APK next to the agents
themselves (`docs/17-ota-architecture.md` §4.1), the daemon self-update payload
is just one thing: the daemon ELF. Wrapping a single ELF in a ZIP — and naming
the wrapper `.apk` to look like an Android package — is misleading (it is not
Android-signed) and adds a ~200-line minimal ZIP central-directory reader
(`extract_apk_entry`, `read_local_entry`, `inflate_raw`, `read_le16`,
`read_le32`) to the daemon's trusted code path, where every line is attack
surface.

Replace the ZIP wrapper with a single ELF file carrying an appended ed25519
signature in trailing bytes (`docs/17-ota-architecture.md` §4.2). The Linux/
Android kernel loads the ELF by its header and ignores trailing bytes at
exec; the daemon's self-update reads the trailing block, re-verifies the
ed25519 signature over the ELF bytes against `EMBEDDED_PUBKEY`, and installs
only the ELF portion. One file, no ZIP, no embedded manifest in the daemon
payload.

## What Changes

- **New inject payload format**: one file `voboost-inject` = ELF bytes
  followed by a trailing signature block:
  - `MAGIC` = `"VOBSIG1"` (8 bytes ASCII, NUL-terminated for an 8-byte
    aligned, memcmp-able constant)
  - `SIG_OFFSET` (8 bytes, LE uint64) = byte offset where the ELF part ends
    (i.e. start of the trailing block)
  - `SIGNATURE` (64 bytes ed25519) = detached signature over bytes
    `[0 .. SIG_OFFSET)` (the ELF part) verified against `EMBEDDED_PUBKEY`
  - padding to 16-byte alignment (the block is 8 + 8 + 64 = 80 bytes, already
    16-aligned; padding reserved for future extension)
- **`src/ota.vala`**:
  - **Remove** the minimal ZIP reader: `extract_apk_entry`,
    `read_local_entry`, `inflate_raw`, `read_le16`, `read_le32` (~200 lines)
    and the constants `APK_BINARY_ENTRY`, `APK_MANIFEST_ENTRY`,
    `APK_MANIFEST_SIG_ENTRY`, `MAX_APK_ENTRIES`. (`MAX_APK_BYTES` stays as
    the DoS guard for the staged file size.)
  - **Remove** the embedded-manifest re-verify from `apply_inject_update`:
    the per-agent manifest no longer rides in the inject payload, so the
    `Manifest.load_verified(...)` step and the `REJECTED_BAD_MANIFEST`
    outcome are gone. (Agent manifest delivery is a separate plane — see
    Step 4 `ScriptExtractor`.)
  - **Add** `verify_appended_sig(bytes) → (elf_bytes, ok)`: static, pure.
    Reads the trailing block from the end of `bytes`, checks `VOBSIG1`,
    reads `SIG_OFFSET`, slices `[0..SIG_OFFSET)` as the ELF part, reads the
    64-byte `SIGNATURE`, and verifies via `this.trust.verify_signature(elf_part,
    signature)`. Returns the ELF bytes on success, null/false on any
    structural or signature failure.
  - **Simplify** `apply_inject_update`: read the staged file → bound-check
    → `verify_appended_sig` → install the returned ELF bytes via
    `write_bytes_exec` (the existing atomic self-replace + `.prev` rollback
    flow is unchanged).
  - **Rename** `find_staged_inject` to look for the bare `voboost-inject`
    filename (no `.apk`).
  - **Simplify** `InjectApplyOutcome`: drop `REJECTED_BAD_MANIFEST`; keep
    `APPLIED`, `REJECTED_NO_APK` (rename semantically: no staged inject
    file), `REJECTED_BAD_BINARY` (sig/truncated/missing magic), and
    `REJECTED_NO_ROLLBACK`.
- **Makefile**:
  - **Replace** the `inject-apk` target (ZIP packaging) with a `sign-elf`
    target: reads `BINARY` (the stripped daemon ELF) and signs it with
    `KEY` (ed25519 private key) by appending the `VOBSIG1` magic + LE
    uint64 offset + 64-byte raw signature to produce `build/voboost-inject`
    (a single signed file).
- **`.github/workflows/release.yml`**: `make inject-apk` → `make sign-elf`;
  the published artifact is `voboost-inject` (no `.apk` extension).
- **`voboost-install/releases/manifest.json`**: the inject entry's
  `downloadUrl` points at `.../voboost-inject` (no `.apk` extension).
- **`voboost-app`**: `ApkStager.INJECT_APK_NAME` value changes from
  `"voboost-inject.apk"` to `"voboost-inject"` (the staged filename the
  daemon looks for); the field name is renamed `INJECT_FILE_NAME` for
  accuracy (it is no longer an APK).

## What Does NOT Change

- **The ed25519 trust model**: the daemon still re-verifies every byte it
  installs against `EMBEDDED_PUBKEY` (key-root family). Only the on-disk
  container changes (ZIP → appended-sig ELF), not the signature algorithm
  or the key.
- **The atomic self-replace + `.prev` rollback flow** in `apply_inject_update`
  (write temp → fsync → fchmod → preserve previous → write marker → atomic
  rename → self-shutdown). Only the "where do the install bytes come from"
  step changes.
- **The single-use `voboost-inject-update-ready` marker contract** (producer
  creates it last; daemon consumes it before apply).
- **The release manifest** (`release-manifest.json` + detached `.sig`) — its
  per-entry sha256/size now describe the single `voboost-inject` file (not
  the `.apk`); the manifest schema itself is unchanged.
- **The agent manifest** (`manifest.json`/`.sig`) — it already does not ride
  in the inject payload in the new architecture; it rides in the app APK.

## Capabilities

### Modified Capabilities
- `ota`: the inject self-update consumes a single appended-sig ELF (no ZIP);
  `verify_appended_sig` replaces `extract_apk_entry`; the
  embedded-manifest re-verify step is removed (manifest rides in app APK
  now); `InjectApplyOutcome` loses `REJECTED_BAD_MANIFEST`.
- `build-and-signing`: the release artifact is a single appended-sig ELF
  (`make sign-elf`), not a ZIP APK; `MAX_APK_ENTRIES` is gone.
- `release-manifest`: the inject entry's path is `voboost-inject` (no
  extension), matching the new artifact name.

## Impact

- **This repo (voboost-inject):** ~200 lines of ZIP reader removed from
  `src/ota.vala`; replaced with ~40 lines of `verify_appended_sig`. Tests
  rewritten: `test/ota_test.vala` drops the APK-extract tests and gains
  appended-sig tests (valid sig, bad sig, missing magic, truncated,
  lying SIG_OFFSET); `test/fixtures/gen-fixtures.sh` produces a signed
  ELF fixture instead of the four APK fixtures. Makefile `sign-elf`
  target; CI workflow updated.
- **voboost app:** `ApkStager.INJECT_APK_NAME` → `INJECT_FILE_NAME` with
  value `"voboost-inject"` (the daemon's `find_staged_inject` looks for
  this bare name). Tests updated.
- **voboost-install:** `releases/manifest.json` inject entry `downloadUrl`
  drops the `.apk` extension.
- **Build/release/CI:** the published inject artifact is a single ELF file
  named `voboost-inject`; the release manifest lists it by that name. The
  signing step is `openssl pkeyutl -sign -rawin` (ed25519 over the ELF
  bytes) followed by an append of the magic/offset/signature — a small
  Python or shell helper in the Makefile.
- **On-device upgrade path:** a device running the old ZIP-based daemon
  cannot consume the new appended-sig payload (it will look for
  `voboost-inject.apk` and not find it). This is a coordinated release:
  the new daemon (which reads the new format) ships via an earlier
  transitional mechanism (manual provisioning or the last ZIP release),
  after which all subsequent OTAs use the new format. There is no
  mixed-format window within the OTA flow because the daemon only ever
  consumes its own channel's payload.
