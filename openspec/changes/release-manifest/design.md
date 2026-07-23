# Design — release-manifest (native payload multi-file)

<!-- Date: 2026-07-23. Records why the release manifest now covers per-ABI
     native payload .so/.a files, why the ELF appended signature is not
     enough, and why an abi field is added. -->

## D1 — Why the release manifest, not an appended signature, covers the payload

**Choice:** every native payload file (`libimplant.so`, `liblsplant.so`,
`liblsplt.so`, `libdobby.a`) per ABI is listed as a release-manifest entry
under the `inject` channel, and the daemon verifies each file's sha256 against
the manifest before use. The daemon ELF alone keeps its appended ed25519
signature.

**Reasoning:** the release manifest already exists as the signed document that
lists component files with their sha256 — it is the natural envelope for a
multi-file payload. An appended signature (`VOBSIG1` block) works for one ELF
because the trailing bytes are ignored by the kernel at exec; it does not
extend to a *set* of files (you cannot append a signature to a `.so` that
`dlopen` will load, and certainly not to a static archive). Forcing one file
per signature would create N independent trust anchors instead of one signed
manifest. The manifest model is already the trust source for the OTA client
(the app verifies the release manifest signature, then trusts each listed
file's sha256); extending it to the payload keeps a single trust root
(`key-root`, the same key family) for the whole `inject` channel. The daemon
ELF keeps its appended signature because self-verification at apply time
(before the manifest is parsed) must work from the file alone — that is the
`ota` self-update path, unchanged here.

## D2 — Why an abi field is needed

**Choice:** each per-ABI payload entry carries an `abi` field
(`arm64-v8a` | `armeabi-v7a`); single-ABI entries (the daemon ELF, agent dex)
omit it.

**Reasoning:** the daemon carries both ABIs and selects the payload matching
the runtime-detected target bitness (see `native-payload`). The manifest must
express "this file is the arm64 libimplant" vs "this is the armv7 libimplant"
so the daemon can (a) verify it has all files for the ABI it needs and (b)
detect a manifest that lists arm64 but not armv7 (or vice versa) — a
deployment gap that would cause an injection to fail or crash the target at
runtime. Without an `abi` field the only option is encoding it in the `path`,
which is fragile (path parsing as trust logic). Making `abi` a first-class,
required field on per-ABI entries lets the parser reject a manifest missing
one ABI's payload before the daemon ever tries to inject.

## D3 — What stays unchanged and why

The `agents` and `app` channels, the OTA client's verify-before-trust flow,
`size` as a DoS guard, and `sha256` as the authoritative integrity check are
unchanged — they are channel-agnostic and already correct for multi-file
lists. The release-manifest size/entry bounds stay; only the *typical* entry
count grows (≈4 payload files × 2 ABIs + the daemon ELF), well within a bound
meant to reject a pathologically large manifest, not a normal multi-file one.
