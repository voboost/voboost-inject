## REMOVED Requirements

### Requirement: Translation admission requires every declared resource owner's readback

**Reason**: A lazy unrelated process must not block Setting's own verified language controls.
**Migration**: No persisted schema changes; replace the volatile aggregate gate with independent owner admission and separate complete-scope observation.

## ADDED Requirements

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
