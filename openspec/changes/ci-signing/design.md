# Design — ci-signing (cargo-ndk + NDK r29 cross-build)

<!-- Date: 2026-07-23. The cross-build follows the build system; signing is
     unchanged. -->

## D1 — Why the cross-build description changes but signing does not

**Choice:** the release cross-build is restated as `cargo-ndk` (aarch64) +
NDK r29 `ndk-build`/CMake, with LTO disabled for the native artifacts; the
release-manifest signing step is unchanged.

**Reasoning:** the cross-build is a build-system detail (owned by
`build-and-signing`); when the build system changes, the CI step that invokes
it must describe the new invocation. LTO is disabled because
`build-and-signing` proves it must be (LSPlant C++23 modules + `-flto` is
broken), so the release build must not re-enable it. Signing, by contrast, is
independent of the build system: the release manifest is signed with the
ed25519 key from CI secrets regardless of how the binaries were built. The
manifest now lists more files (the payload), but the signing act — one
detached signature over `release-manifest.json` — is identical, so the signing
requirement needs no change.
