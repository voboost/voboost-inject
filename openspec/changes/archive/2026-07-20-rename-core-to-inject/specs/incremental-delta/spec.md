## MODIFIED Requirements

### Requirement: Download changed files whole
The client SHALL download each changed file in full (no binary diffing or
patching). Agents are small; the inject binary is large but rarely updated,
so whole-file download is preferred over binary-delta tooling.

#### Scenario: Changed file downloaded whole
- **WHEN** a file's sha256 differs between the current and new release
  manifests
- **THEN** the client downloads that file in full
