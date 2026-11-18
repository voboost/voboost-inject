## MODIFIED Requirements

### Requirement: Resource variants are selected independently for exact owners

The daemon SHALL recognize only the seven exact Setting, Launcher, VehicleSetting, SettingNetwork, SystemUI, BluetoothPhone and Media target packages and their fourteen closed A9/A11 resource tuples. The signed catalog declaration SHALL continue to determine the delivered owner scope; recognizing a tuple SHALL NOT declare or publish that owner. Each owner's preflight batch SHALL contain at most two variants and SHALL match the authenticated endpoint process. Every candidate acknowledgement SHALL be current before exactly one compatible variant can be selected. A foreign process, undeclared payload owner, duplicate or stale ticket, zero matches or ambiguous matches SHALL NOT yield a compatibility proof.

#### Scenario: Independent owner batches cannot consume one another's proofs

- **WHEN** each of the seven exact owners has two candidate variants
- **THEN** their current acknowledgements select independently and foreign, incomplete, duplicated, replayed or ambiguous candidate collections produce no successful proof

#### Scenario: New capabilities do not publish undeclared owners

- **WHEN** the signed catalog still declares the existing three owners
- **THEN** the original complete declared inventory remains admissible and an extra payload for a newly recognized but undeclared owner is rejected

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::i18n_resource_events::tests::seven_owner_batches_require_current_complete_unique_results -- --exact

Gate contract: Owner-bound host verification.
Maps: Requirement `Resource variants are selected independently for exact owners`; Scenario `Independent owner batches cannot consume one another's proofs`.
Preconditions: Authenticated synthetic endpoint identities and root-issued batches for all seven owners.
Observable result: Only a complete unique current owner batch yields its own proof.
Evidence boundary: Host protocol state, not actual Android Resources or delivered datasets.

# Gate: cargo test --manifest-path daemon/Cargo.toml i18n_resources::tests::closed_capabilities_do_not_expand_signed_declaration -- --exact

Gate contract: Signed declaration remains the publication boundary.
Maps: Requirement `Resource variants are selected independently for exact owners`; Scenario `New capabilities do not publish undeclared owners`.
Preconditions: The original three-owner signed declaration and its complete candidate inventory.
Observable result: Recognition of additional capabilities does not reject the existing scope or admit an undeclared payload.
Evidence boundary: Host signed-inventory classification, not product metadata publication.

### Requirement: Cleanup proves absence for the complete owned resource collection

Cleanup SHALL authenticate all owned profiles before mutation, restore the native locale once per collection pass, remove up to fourteen exact profiles before one resource-only reboot and collect every new-boot file/package absence proof before any final commit. No-resource cleanup SHALL request no resource reboot.

#### Scenario: A later owner prevents premature cleanup completion

- **WHEN** a thirteenth or fourteenth profile remains registered after removal
- **THEN** no final receipt is committed and replay cannot issue another reboot request

# Unverified: Fourteen-profile runtime cleanup
