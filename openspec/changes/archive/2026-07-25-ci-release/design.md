# Design — ci-release (payload files as release artifacts)

<!-- Date: 2026-07-23. The payload files must be published because the OTA
     client stages them as part of the inject update. -->

## D1 — Why payload files are release artifacts

**Choice:** CI publishes the per-ABI native payload files as release artifacts
alongside the daemon ELF and the release manifest.

**Reasoning:** the inject update is now multi-file (ELF + payload — see `ota`,
`release-manifest`). If CI published only the ELF, the OTA client would have
no source for the payload files and could not stage a complete update. The
payload files are release artifacts (they ship to devices), not build
intermediates (the raw `build-android/` objects that are not published). The
release manifest already lists them with sha256; publishing them makes that
list actionable. The "no daemon manifest step" invariant is unchanged — the
per-agent manifest is still app-owned and not produced by this repo.
