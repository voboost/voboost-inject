## MODIFIED Requirements

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
