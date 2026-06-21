## Purpose
Specify the trust model: embedded public-key anchor, signed manifest verification, per-agent hash
verification, and manifest as authoritative source of agent metadata.

## Requirements

### Requirement: Embedded public-key trust anchor
The daemon SHALL use a public key compiled into the binary as its only trust anchor.
It SHALL NOT read a trust anchor (`key.pub` or equivalent) from disk.

#### Scenario: Verification uses the embedded key
- **WHEN** the daemon verifies any signed material
- **THEN** it uses the compiled-in public key and never loads a key from the filesystem

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
Before injecting an agent the daemon SHALL verify the agent file's sha256 matches the value
recorded in the verified manifest. An agent whose bytes do not match SHALL NOT be injected.

#### Scenario: Agent hash matches
- **WHEN** an agent file's sha256 equals the manifest value
- **THEN** the agent is eligible for injection

#### Scenario: Agent hash mismatch
- **WHEN** an agent file's sha256 differs from the manifest value
- **THEN** the daemon refuses to inject it and reports the failure in status

### Requirement: Manifest is the source of target process and kind
The daemon SHALL take each agent's target `process` and `kind` (`js` or `native`) exclusively
from the verified manifest, never from the app-written injection plan.

#### Scenario: Plan attempts to override target
- **WHEN** the injection plan references an agent
- **THEN** the daemon resolves that agent's target process and kind from the
  manifest and ignores any such fields in the plan
