## ADDED Requirements

NOTE: the OTA client (fetch/diff/download/staging-writer) is owned by the voboost
app repo; this capability defines the contract that client SHALL satisfy. The
daemon side (re-verification of staged material before trusting it) is owned by
this repo and is normative here.

### Requirement: Diff by hash and download only changed files
The OTA client SHALL keep its current release manifest, fetch the new signed
manifest, diff the two by per-file `sha256`, and download only files whose hash
changed. Unchanged files SHALL NOT be re-downloaded. The stored "current
manifest" used as the diff base SHALL itself be the last successfully verified
manifest; a manifest that failed signature or schema verification SHALL NOT be
persisted as the current manifest.

#### Scenario: One file changed
- **WHEN** exactly one file's sha256 differs between the current and new release
  manifests
- **THEN** the client downloads only that file and fetches nothing else

#### Scenario: Nothing changed
- **WHEN** no file's sha256 differs
- **THEN** the client downloads no component files

### Requirement: Download changed files whole
The client SHALL download each changed file in full (no binary diffing or
patching). Agents are small; the core binary is large but rarely updated, so
whole-file download is preferred over binary-delta tooling.

#### Scenario: Changed file downloaded whole
- **WHEN** a file's sha256 differs between the current and new release manifests
- **THEN** the client downloads that file in full

### Requirement: Reject downloads whose size disagrees with the manifest
Before hashing, the client SHALL reject a downloaded file whose byte size differs
from the manifest `size`, as a DoS guard against truncated or oversized payloads.
A size match does not imply integrity — the sha256 check below is authoritative.

#### Scenario: Download size matches
- **WHEN** a downloaded file's size equals the manifest value
- **THEN** it proceeds to sha256 verification

#### Scenario: Download size disagrees (negative)
- **WHEN** a downloaded file's size differs from the manifest value
- **THEN** the client discards it without hashing and keeps the current set

### Requirement: Verify every fetched artifact and re-verify staged material
The client SHALL verify each downloaded file against the `sha256` in the signed
release manifest. A mismatch SHALL abort the update with the current set left
intact. The daemon SHALL NOT trust the app's verification for material it
installs into the trusted zone: it SHALL re-verify any staged daemon manifest
(signature + per-agent sha256) with its embedded key before applying.

#### Scenario: Downloaded file matches
- **WHEN** a downloaded file's sha256 equals the signed manifest value
- **THEN** it is accepted for staging

#### Scenario: Downloaded file mismatches
- **WHEN** a downloaded file's sha256 differs from the signed manifest value
- **THEN** the client discards it, aborts the update, and keeps the current set

#### Scenario: Daemon re-verifies staged material
- **WHEN** the daemon consumes a staged update from `staging/`
- **THEN** it re-verifies the staged daemon manifest signature and every staged
  agent sha256 with its embedded key before applying, regardless of any app-side
  verification
