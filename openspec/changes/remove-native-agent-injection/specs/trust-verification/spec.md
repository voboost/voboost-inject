## MODIFIED Requirements

### Requirement: Manifest is the source of target process
The daemon SHALL take each agent's target `process` exclusively from the
verified manifest, never from the app-written injection plan. (The `kind`
field is removed: every agent is JavaScript.)

#### Scenario: Plan attempts to override target
- **WHEN** the injection plan references an agent
- **THEN** the daemon resolves that agent's target process from the manifest
  and ignores any such field in the plan
