# Resource owner delivery

## Purpose

Bound resource admission to its actual Android owner and retain complete cleanup proof.

## Requirements

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
Observable result: only a complete unique current owner batch yields its own proof.
Evidence boundary: Host protocol state, not actual Android Resources or delivered datasets.

# Gate: cargo test --manifest-path daemon/Cargo.toml i18n_resources::tests::closed_capabilities_do_not_expand_signed_declaration -- --exact

Gate contract: Signed declaration remains the publication boundary.
Maps: Requirement `Resource variants are selected independently for exact owners`; Scenario `New capabilities do not publish undeclared owners`.
Preconditions: The original three-owner signed declaration and its complete candidate inventory.
Observable result: Recognition of additional capabilities does not reject the existing scope or admit an undeclared payload.
Evidence boundary: Host signed-inventory classification, not product metadata publication.

### Requirement: Resource admission requires its own current owner readback

Every owner admission SHALL require the complete signed declared payload inventory and that owner's current authenticated resource readback. Configuration SHALL be projected only to its actual target process. A valid Setting admission SHALL remain available while another declared owner is nonrunning, pending or unsupported. Global locale production and language picker installation SHALL remain Setting-owned. The daemon SHALL NOT launch an unrelated process to obtain its readback.

#### Scenario: A lazy owner does not block the available Setting controls

- **WHEN** signed inventory is complete, Setting has current readback and another declared owner lacks a running compatible endpoint
- **THEN** Setting receives only its own admission while the other owner receives no successful admission

# Gate: cargo test --manifest-path daemon/Cargo.toml i18n_resources::tests::settings_admission_survives_other_declared_owner_waiting -- --exact
Gate contract: Independent own-resource admission.
Maps: Requirement `Resource admission requires its own current owner readback`; Scenario `A lazy owner does not block the available Setting controls`.
Preconditions: Complete authenticated inventory is represented by the admitted worker result and independent owner endpoint identities.
Observable result: The Setting configuration remains available without another owner's ready result; missing own proof is rejected.
Evidence boundary: Host projection state, not OEM language UI or guaranteed English fallback.

### Requirement: Complete-scope observation never substitutes one owner's readiness

The daemon SHALL observe the complete set of signed-declared Android owners separately from individual admission. Complete SHALL require every declared owner to have current own readback. Waiting-process, preflight, readback-pending, unsupported, failed, disabled or stale owner states SHALL remain incomplete. Repeated unchanged scope observations SHALL NOT repeat the readiness log; changes and recovery SHALL remain observable through the existing logger.

#### Scenario: Pending and unsupported owners remain incomplete

- **WHEN** another declared owner is pending, unsupported or stale while Setting is ready
- **THEN** the scope remains incomplete and only every current owner readback can make it complete

# Gate: cargo test --manifest-path daemon/Cargo.toml i18n_resources::tests::owner_scope_distinguishes_pending_unsupported_and_complete -- --exact
Gate contract: Separate complete-scope observation.
Maps: Requirement `Complete-scope observation never substitutes one owner's readiness`; Scenario `Pending and unsupported owners remain incomplete`.
Preconditions: Two declared owner snapshots with distinct current phases.
Observable result: Incomplete phases never become complete, and duplicate/change/recovery publication decisions are distinct.
Evidence boundary: Host volatile observation and log-decision logic.

### Requirement: Inventory failure revokes every cached resource admission

A missing declared payload or invalid signed inventory SHALL fail before owner filtering. A current inventory failure SHALL invalidate cached admissions and observations for every owner and prevent pending cancelled job results from restoring them. A successful new complete inventory check SHALL NOT restore an old owner proof without new readback.

#### Scenario: Cached readiness cannot survive a declared payload failure

- **WHEN** owners have cached readiness and a declared owner payload is missing or invalid
- **THEN** all cached admissions are rejected and cancelled prior results cannot resurrect readiness

# Gate: cargo test --manifest-path daemon/Cargo.toml i18n_resources::tests::inventory_failure_revokes_cached_admissions_and_cancelled_results -- --exact
Gate contract: Complete-inventory authority retention.
Maps: Requirement `Inventory failure revokes every cached resource admission`; Scenario `Cached readiness cannot survive a declared payload failure`.
Preconditions: Current cached own proofs and a declared signed owner set.
Observable result: Missing or foreign inventory fails, all cached configurations are revoked, and recovery requires fresh proofs.
Evidence boundary: Host coordinator and signed-inventory classification; not Android PackageManager.

### Requirement: Cleanup proves absence for the complete owned resource collection

Cleanup SHALL authenticate all owned profiles before mutation, restore the native locale once per collection pass, remove up to fourteen exact profiles before one resource-only reboot and collect every new-boot file/package absence proof before any final commit. No-resource cleanup SHALL request no resource reboot.

#### Scenario: A later owner prevents premature cleanup completion

- **WHEN** a thirteenth or fourteenth profile remains registered after removal
- **THEN** no final receipt is committed and replay cannot issue another reboot request

# Unverified: Fourteen-profile runtime cleanup

## Unverified

### Unverified: Fourteen-profile runtime cleanup

Maps: Requirement `Cleanup proves absence for the complete owned resource collection`; Scenario `A later owner prevents premature cleanup completion`.
Unavailable observation: Actual fourteen-package absence after an Android reboot.
Reason: Host collection tests cannot observe Android PackageManager or OEM resource state.
Required environment or artifact: A separately owned emulator or device run with all fourteen installed owned overlays.
