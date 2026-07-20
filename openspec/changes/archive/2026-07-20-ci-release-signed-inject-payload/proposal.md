# Proposal: CI publishes the signed inject payload, not the raw binary or a daemon manifest

## Why
After the inject payload became a single appended-sig ELF (`ota` change
`replace-zip-with-appended-sig-elf`, archived), the `ci-release` spec is stale
in two ways:

1. Its `Publish signed release artifacts` requirement still lists
   `build-android/voboost-inject` (the stripped raw daemon ELF) as the published
   binary. The release workflow now publishes `build/voboost-inject` — the same
   ELF with an appended ed25519 signature — produced by `make sign-elf`. The
   raw ELF is not published (it is not a trust unit; the appended signature is).
2. The release workflow has a `Build and sign daemon manifest` step that
   generates `build/manifest.json` + `.sig` with an empty `agents` list. The
   per-agent manifest rides inside the app APK (docs/17-ota-architecture.md
   §4.1); it is not embedded in the inject payload (which carries no manifest)
   and is not published. The step is dead: its outputs are consumed by nothing
   downstream and are absent from the publish list. The `ci-release` spec never
   covered this step, so removing it does not contradict a requirement — but
   the spec should say CI does NOT produce the daemon manifest, so it cannot
   quietly reappear.

## What
- MODIFIED `Publish signed release artifacts`: the staged binary is
  `build/voboost-inject` (the appended-sig ELF from `make sign-elf`), not
  `build-android/voboost-inject`. The OTA release manifest and its signature are
  unchanged.
- ADDED `No CI daemon manifest step`: CI SHALL NOT generate or sign a
  per-agent daemon manifest; the per-agent manifest is produced and carried by
  the app APK, not by this repo's release.
- Delete the `Build and sign daemon manifest` step from
  `.github/workflows/release.yml` (the dead step described above).

## Impact
- `ci-release` spec: one MODIFIED requirement, one ADDED requirement.
- No runtime/trust/OTA contract change — the published trust unit was already
  the appended-sig payload after `replace-zip-with-appended-sig-elf`; this
  change only makes the spec match the workflow and removes a dead step.

## Non-goals
- Changing the OTA release manifest schema or signing (that is the `ota` /
  `release-manifest` specs).
- Producing the per-agent manifest here (it is the app APK's job).
- Durable hosting of the artifacts (still a deferred design Open Question).
