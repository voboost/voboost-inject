## ADDED Requirements

### Requirement: Publish signed release artifacts
On a release, CI SHALL stage the signed OTA release manifest, its detached signature, and the
signed binary as release artifacts so they are available for hand-off to the OTA transport. The OTA
release manifest (defined by the `ota` change) already groups files logically by channel
(`agents`, `core`, `app`) via its `channel` field; CI signs the manifest and stages the three
artifacts. The delta/apply mechanics remain the `ota` change's concern. Durable publication/hosting
for the OTA fetch transport is out of scope for this step and is deferred (a design Open Question);
this step stages the signed artifacts as a workflow-run artifact, which also proves the build and
sign pipeline end-to-end.

#### Scenario: Release publishes artifacts
- **WHEN** a release build completes successfully
- **THEN** CI stages `build-android/voboost-inject`, `build/release-manifest.json`, and
  `build/release-manifest.json.sig` as release artifacts (a workflow-run artifact; durable hosting
  is deferred)

#### Scenario: Build fails before publish
- **WHEN** any earlier pipeline step fails
- **THEN** no release artifacts are published
