# Design — incremental-delta (multi-file payload in the diff)

<!-- Date: 2026-07-23. The diff and re-verify widen to cover the payload
     files; the mechanism is unchanged. -->

## D1 — Why the diff widens but the mechanism does not

**Choice:** the OTA client diffs all `inject`-channel files (daemon ELF + per-ABI
payload) by sha256 and downloads only changed ones; the daemon re-verifies staged
payload files against the release manifest.

**Reasoning:** the inject update is now a set of files (see `ota`,
`release-manifest`), not one binary. The diff mechanism (compare per-file sha256
between the current and new release manifest, download only changed files whole)
is already file-set-agnostic — it was designed for the multi-channel manifest
(`agents`, `inject`, `app`). Widening it to the payload files is not a mechanism
change; it is the same loop over more entries. The practical benefit: a
payload-only fix (e.g. a new `libimplant.so`) downloads only the changed `.so`
files, not the whole daemon ELF. The re-verify path gains the payload sha256
check (see `trust-verification`), which is the same sha256-before-use principle
applied to one more file class.
