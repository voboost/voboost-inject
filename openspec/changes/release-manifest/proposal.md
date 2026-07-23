## Why

The `release-manifest` spec lists each release component with its sha256 and
channel, but it knows only the daemon ELF as the `inject` channel: a single
appended-sig binary. The ptrace migration (see `native-payload`) adds a whole
native payload that is *not* a single ELF — `libimplant.so`, `liblsplant.so`,
`liblsplt.so`, and `libdobby.a`, each shipped per-ABI (`arm64-v8a` and
`armeabi-v7a`). A single ELF's appended signature cannot cover multiple files,
so the multi-file native payload needs its own integrity envelope.

The model is already half-built: `release-manifest.json` already lists files
with `path`/`channel`/`sha256`/`size`/`version`. The missing piece is that the
native payload's multiple per-ABI `.so`/`.a` files must each appear as
release-manifest entries under the `inject` channel, and the daemon must treat
the release manifest as the authoritative hash source for the native payload —
not a loose directory of files it trusts by name. Without this, a tampered or
truncated `libimplant.so` could be loaded into a target with no verification,
and the OTA pipeline would have no single document proving the payload's
integrity.

## What Changes

- **MODIFIED**:
  - "Signed release manifest, distinct from the daemon manifest" — the
    release manifest now covers *all* `inject`-channel files: the daemon ELF
    *and* every native payload file (`libimplant`, `liblsplant`, `liblsplt`,
    `libdobby`) per ABI. The native payload is a set of files, not a single
    ELF, so the manifest — not an appended signature — is their trust anchor.
    The daemon ELF keeps its appended signature for self-verification.
  - "Per-file metadata with change-frequency channels" — an `abi` field is
    added to entries that are per-ABI (`arm64-v8a` | `armeabi-v7a`), so the
    manifest can group and validate the payload by ABI. The daemon must find
    every required payload file for the ABI it detected before injecting.
  - "Release-manifest size and entry bounds" — the entry count grows (the
    payload adds ~8 per-ABI files); the bound stays but the rationale updates.
- **Unchanged**: the `agents` and `app` channels (owned by the voboost app
  repo); the OTA client's verify-before-trust flow; `size` as a DoS guard and
  `sha256` as the authoritative check.

## Capabilities

### Modified Capabilities

- `release-manifest`: the release manifest is extended from a single daemon
  ELF to also cover the multi-file native payload (`libimplant.so`,
  `liblsplant.so`, `liblsplt.so`, `libdobby.a`) per ABI, each with sha256 and
  an `abi` tag, all under the `inject` channel. The manifest is the
  authoritative integrity source for the payload; the daemon ELF retains its
  appended signature for self-verification.
