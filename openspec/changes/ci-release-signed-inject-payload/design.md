# Design: CI publishes the signed inject payload

## D1. The published binary is the appended-sig ELF
`make sign-elf` reads the stripped daemon ELF (`build-android/voboost-inject`)
and the release private key, and writes `build/voboost-inject` — the ELF with a
trailing `VOBSIG1\0` magic, a LE uint64 `SIG_OFFSET`, and a 64-byte ed25519
signature over the ELF bytes (the format defined by the `ota` change
`replace-zip-with-appended-sig-elf`). CI publishes `build/voboost-inject`; the
raw `build-android/voboost-inject` is an intermediate, not a release artifact.

The `ci-release` spec's `Publish signed release artifacts` requirement is
MODIFIED to name `build/voboost-inject` instead of `build-android/voboost-inject`.
The rest of the requirement (signing the OTA release manifest, staging all
three artifacts, nothing on earlier failure) is unchanged.

## D2. No per-agent daemon manifest is produced by this repo's CI
The per-agent `manifest.json` is carried by the app APK (docs/17-ota-architecture.md
§4.1). The inject payload is a single appended-sig ELF and carries no manifest.
The old `Build and sign daemon manifest` step produced `build/manifest.json`
with an empty `agents` list and signed it, but the outputs were never embedded
into the payload and never published — they were dead from the moment the
per-agent manifest moved to the app APK.

That step had no spec coverage (the `ci-release` spec only described the publish
step). Deleting it does not contradict a requirement, but ADDED requirement
`No CI daemon manifest step` makes the absence explicit so the step cannot
silently return.

## D3. Makefile `sign` / `verify-sig` stay
`make sign` and `make verify-sig` are still used to sign and verify the OTA
release manifest (`build/release-manifest.json`). Only the per-call arguments
for the dead daemon-manifest step go away; the targets themselves are shared
with the release-manifest signing and are kept.

## D4. Publish list after the change
```
build/voboost-inject              # appended-sig ELF (the inject payload)
build/release-manifest.json       # OTA release manifest
build/release-manifest.json.sig   # detached ed25519 signature over the manifest
```
`build/manifest.json` and `build/manifest.json.sig` are no longer produced and
are not in the list.
