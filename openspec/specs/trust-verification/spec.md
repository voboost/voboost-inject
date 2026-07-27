## Purpose
Specify the trust model: embedded public-key anchor, signed manifest verification, per-agent hash
verification, and manifest as authoritative source of agent metadata.
## Requirements
### Requirement: Embedded public-key trust anchor

The daemon SHALL use a public key compiled into the binary (`EMBEDDED_PUBKEY`)
as its only trust anchor. It SHALL be the trust anchor for both the per-agent
manifest (agent `.dex` integrity and metadata) and the release manifest (native
payload file integrity — see `release-manifest`). It SHALL NOT read a trust
anchor (`key.pub` or equivalent) from disk.

#### Scenario: Verification uses the embedded key

- **WHEN** the daemon verifies any signed material (the agent manifest or the
  release manifest)
- **THEN** it uses the compiled-in public key and never loads a key from the
  filesystem

### Requirement: Signed manifest verification
The daemon SHALL verify the signed manifest's ed25519 detached signature (`manifest.sig`)
against the embedded public key before trusting any manifest content. A manifest that fails
signature verification SHALL NOT be used.

#### Scenario: Valid manifest signature
- **WHEN** the manifest's detached signature verifies against the embedded key
- **THEN** the manifest is parsed and held as the verified source of agent metadata

#### Scenario: Invalid or missing manifest signature
- **WHEN** the manifest signature is missing or fails verification
- **THEN** the daemon rejects the manifest and does not inject any agent from it

### Requirement: Per-agent hash verification

Before injecting an agent the daemon SHALL verify the agent file's sha256
matches the value recorded in the verified agent manifest. The daemon SHALL
resolve the agent file's path as `PAYLOAD_DIR/<agent.file>` (the manifest's
`file` field is a bare relative name), the same payload directory used to
resolve native-payload files — NOT the root zone. This is the agent-file
verification path; it is distinct from the native-payload verification path
(see "Native payload verification via the release manifest"), which checks
payload `.so`/`.a` files against the release manifest. An agent whose bytes
do not match SHALL NOT be injected.

#### Scenario: Agent hash matches

- **WHEN** an agent file's sha256 equals the agent-manifest value
- **THEN** the agent is eligible for injection

#### Scenario: Agent hash mismatch

- **WHEN** an agent file's sha256 differs from the agent-manifest value
- **THEN** the daemon refuses to inject it and reports the failure in status

#### Scenario: Agent file resolved under the payload directory

- **WHEN** the daemon builds the on-disk path for a manifest agent's `file`
  entry to compute its sha256
- **THEN** it joins the file name under `PAYLOAD_DIR`
  (`/data/voboost-inject/payload/<file>`), not the root zone
  (`/data/voboost-inject/<file>`), because that is where the file is actually
  deployed and where the implant reads it from

### Requirement: Manifest is the source of target process
The daemon SHALL take each agent's target `process` exclusively from the
verified manifest, never from the app-written injection plan. (The `kind`
field is removed: every agent is JavaScript.)

#### Scenario: Plan attempts to override target
- **WHEN** the injection plan references an agent
- **THEN** the daemon resolves that agent's target process from the manifest
  and ignores any such field in the plan

### Requirement: Native payload verification via the release manifest

The daemon SHALL verify the sha256 of each native payload file
(`libimplant.so`, `liblsplant.so`, `liblsplt.so`, `libdobby.a` — see
`native-payload`) against the release manifest that the daemon verified with
`EMBEDDED_PUBKEY`, before using that file. The release manifest is the
authoritative hash source for the native payload (see `release-manifest`); a
payload file whose bytes do not match the manifest value SHALL NOT be handed
to the injector or loaded into a target. The daemon SHALL verify the file
matching the ABI the injector detected at runtime and SHALL reject the
injection if that ABI's file is absent from the manifest or fails
verification. The daemon ELF's own integrity is verified separately via its
appended ed25519 signature at apply time (see `ota`); this requirement covers
only the payload files.

#### Scenario: Payload file hash matches

- **WHEN** a native payload file's sha256 equals the release-manifest value
  for the detected ABI
- **THEN** the daemon proceeds to use that file for injection

#### Scenario: Payload file hash mismatch

- **WHEN** a native payload file's sha256 differs from the release-manifest
  value
- **THEN** the daemon refuses to inject it, reports the failure in status, and
  does not hand the file to the injector

#### Scenario: Required ABI absent from the manifest

- **WHEN** the injector detects a target ABI whose payload file is not listed
  in the verified release manifest
- **THEN** the daemon rejects the injection and reports the missing-ABI
  failure

