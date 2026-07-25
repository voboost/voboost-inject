## Why

The `trust-verification` spec locks trust to agents: an embedded public key,
a signed per-agent manifest, per-agent sha256, and the manifest as the source
of the target process. The daemon only ever verified agent files. The ptrace
migration introduces a native payload (`libimplant.so`, `liblsplant.so`,
`liblsplt.so`, `libdobby.a` per ABI — see `native-payload`) that the daemon
hands to targets by path. These files are root-owned and arrive with the
daemon release, not as app-signed agents — so they fall outside the existing
per-agent manifest. Without trust coverage, a tampered or replaced
`libimplant.so` would be injected with no verification: the most privileged
code path (arbitrary native code inside every target process) would have no
integrity check.

The release manifest already lists each payload file with its sha256 and is
signed by the same key family as the embedded key (see `release-manifest`).
This change extends trust verification from "verify agent files against the
agent manifest" to also "verify native payload files against the release
manifest," using the same embedded key anchor and the same sha256-before-use
principle. The daemon ELF's self-verification (appended signature) is already
in `ota` and is not re-specified here.

## What Changes

- **ADDED**:
  - "Native payload verification via the release manifest" — before using any
    native payload file, the daemon SHALL verify its sha256 against the
    verified release manifest (signed by the key-root family). A payload file
    whose hash does not match SHALL NOT be injected.
- **MODIFIED**:
  - "Embedded public-key trust anchor" — the embedded key is now the trust
    anchor for *both* the agent manifest and the release manifest (which
    covers the native payload). The principle (one compiled-in key, never read
    from disk) is unchanged; its coverage widens.
  - "Per-agent hash verification" — the per-agent sha256 check is restated to
    clarify it covers the agent `.dex` files against the agent manifest, and
    is now one of two hash-verification paths (agents vs payload), not the
    only one.
- **Unchanged**: "Signed manifest verification" (the agent manifest's ed25519
  detached-signature check — the release manifest's signature is verified by
  the OTA client and re-verified by the daemon at apply time, already in
  `release-manifest`); "Manifest is the source of target process" (the agent
  manifest remains the source of each agent's target process).

## Capabilities

### Modified Capabilities

- `trust-verification`: the embedded public key is the trust anchor for both
  the agent manifest and the release manifest (native payload). A new
  requirement verifies each native payload file's sha256 against the verified
  release manifest before the daemon uses it. The per-agent hash check and
  the embedded-key principle are restated to cover both paths.
