## MODIFIED Requirements

### Requirement: Resource variants are selected independently for exact owners

The daemon SHALL admit only Setting, Launcher and VehicleSetting exact target packages and their six declared resource tuples. Each owner's preflight batch SHALL contain at most two variants and SHALL match the authenticated endpoint process. Every candidate acknowledgement SHALL be current before exactly one compatible variant can be selected. A foreign process, duplicate or stale ticket, zero matches or ambiguous matches SHALL NOT yield a compatibility proof.

#### Scenario: Independent owner batches cannot consume one another's proofs

- **WHEN** Setting, Launcher and VehicleSetting each have two candidate variants
- **THEN** their current acknowledgements select independently and foreign, incomplete, duplicated, replayed or ambiguous candidate collections produce no successful proof

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::i18n_resource_events::tests::three_owner_batches_require_current_complete_unique_results -- --exact

Gate contract: Owner-bound host verification.
Maps: Requirement `Resource variants are selected independently for exact owners`; Scenario `Independent owner batches cannot consume one another's proofs`.
Preconditions: authenticated synthetic endpoint identities and root-issued owner batches.
Observable result: only a complete unique current owner batch yields its own proof.
Evidence boundary: host protocol state, not actual Android Resources.

### Requirement: Cleanup proves absence for the complete owned resource collection

Cleanup SHALL authenticate all owned profiles before mutation, restore the native locale once, remove up to six exact profiles before one resource-only reboot and collect every new-boot file/package absence proof before any final commit. No-resource cleanup SHALL request no resource reboot.

#### Scenario: A later owner prevents premature cleanup completion

- **WHEN** a fifth or sixth profile remains registered after removal
- **THEN** no final receipt is committed and replay cannot issue another reboot request

# Unverified: Six-profile runtime cleanup


## Unverified

### Unverified: Six-profile runtime cleanup

Maps: Requirement `Cleanup proves absence for the complete owned resource collection`; Scenario `A later owner prevents premature cleanup completion`.
Unavailable observation: Actual six-package absence after an Android reboot.
Reason: Host collection tests cannot observe Android PackageManager or OEM resource state.
Required environment or artifact: A separately owned emulator or device run with all six installed owned overlays.
