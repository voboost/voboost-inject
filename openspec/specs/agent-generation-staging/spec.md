# Agent generation staging specification

## Purpose

Define hostile app staging and exact operation-correlated completion.

## Requirements

### Requirement: App staging is hostile and complete

The daemon SHALL consume only `/data/voboost/generations/next` after `ready` exists. After authenticating the exact signed schema-1 `agents.json`, it SHALL require an unsigned app-authored canonical schema-1 `agents-selected.json` bound to that catalog's SHA-256. It SHALL verify the receipt with root-owned `vehicle.json` through the same exact facts, catalog order, complete agent set, applicability results and ordered `unknownReasons` contract, and SHALL reject any mismatch rather than trusting app selection. Staging and the immutable generation SHALL contain exactly the catalog, signature, receipt, core and the complete signed target DEX closure, including modules currently classified `unsupported`. Applicability SHALL control only which agents may be loaded/injected; it SHALL NOT delete signed release bytes. Missing or extra payloads SHALL reject the transaction.

#### Scenario: Staging contains an unsupported module

- **WHEN** a signed catalog module is excluded by the verified selection receipt
- **THEN** the daemon retains its DEX in the immutable generation but never selects or injects that agent

#### Scenario: Root applicability changes without a catalog download

- **WHEN** the same signed catalog is evaluated against different root-owned facts
- **THEN** both selections use the same complete catalog DEX inventory while only selected agent IDs differ

#### Scenario: Selection facts are forged

- **WHEN** the unsigned receipt differs from root-owned facts while referencing an authentic catalog
- **THEN** the daemon rejects the receipt and every staged payload without publishing a generation

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::unsupported_module_is_retained_but_never_selected_for_injection -- --exact
Gate contract: Exact named verification for App staging is hostile and complete.
Maps: Requirement `App staging is hostile and complete`; Scenarios `Staging contains an unsupported module`, `Selection facts are forged`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::later_applicability_selection_reuses_the_same_complete_signed_dex_closure -- --exact
Gate contract: Full signed DEX closure survives applicability changes.
Maps: Requirement `App staging is hostile and complete`; Scenario `Root applicability changes without a catalog download`.
Preconditions: The exact Rust test computes two selections for one signed catalog and compares their generation inventories.
Observable result: Selection identities differ while core and target DEX identities remain identical and locally reusable.
Evidence boundary: Host catalog/selection/inventory model; later device activation is not exercised.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::forged_app_written_selection_document_is_rejected -- --exact
Gate contract: Exact named verification for App staging is hostile and complete.
Maps: Requirement `App staging is hostile and complete`; Scenarios `Staging contains an unsupported module`, `Selection facts are forged`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Staging claim authority is exact

The activation journal SHALL use strict schema 1 and bind the exact selection SHA-256, staging owner and group and durable claim phase in addition to the catalog identity. The staging owner SHALL be an unprivileged app identity distinct from root and the daemon identity; a daemon-owned, root-owned or root-group offer SHALL be rejected. Completion SHALL claim the staging directory by ownership through one retained descriptor and repeat stable reads under the journaled app owner. Recovery SHALL accept only the adjacent owner/phase cuts omitted by interruption: phase `none` with daemon ownership advances to `owned`, while phase `snapshotsRemoved` with the journaled app owner advances to `restored`. Every foreign or non-adjacent owner state SHALL fail closed.

#### Scenario: A claim observes a privileged staging owner

- **WHEN** the ready directory is owned by root, the daemon or the root group
- **THEN** completion rejects the offer without creating claim authority

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::staging_owner_must_be_unprivileged_and_distinct_from_daemon -- --exact
Gate contract: Exact named verification for Staging claim authority is exact.
Maps: Requirement `Staging claim authority is exact`; Scenario `A claim observes a privileged staging owner`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Frozen completion snapshots are immutable authority

Completion SHALL freeze trusted catalog and selection snapshots in order, then restore app ownership after acknowledgement and marker removal. Once published, each root-owned snapshot SHALL be recovery authority for that member and SHALL NOT be replaced by rereading an app-owned original. After both snapshots are durable, pre-opened app descriptors SHALL NOT change completion identity. Acknowledgement and marker cleanup SHALL consume `next` only while its catalog and selection digest pair matches the journal. Phase `snapshotsRemoved` SHALL prove that the old snapshots and marker were removed before handback. After observing the journaled app owner, recovery SHALL clear only the old journal and SHALL NOT inspect, rewrite or delete current entries. App-created `.claim-*` entries after handback SHALL be hostile new-offer inventory and SHALL fail exact inventory validation. Recovery SHALL finish every snapshot, acknowledgement, marker-removal, snapshot-cleanup and owner-restoration cut before uninstall freeze. A same-catalog replacement with different selection SHALL remain pending byte for byte without an acknowledgement or claim residue.

#### Scenario: Staging ownership changes during claim

- **WHEN** staging ownership or either frozen catalog-selection snapshot changes outside the adjacent journaled claim cuts
- **THEN** completion fails closed without replacing snapshot authority from app-owned bytes

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::frozen_pair_snapshots_survive_mutation_through_preopened_app_fds -- --exact
Gate contract: Exact named verification for Frozen completion snapshots are immutable authority.
Maps: Requirement `Frozen completion snapshots are immutable authority`; Scenario `Staging ownership changes during claim`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Activation pointer and plan recovery are one transaction

After preparing and reverifying the immutable generation, the daemon SHALL persist a root-owned activation journal before the pointer switch. The strict bounded schema-1 journal SHALL contain only state, exact old/new generation identity, catalog and selection SHA-256, the unprivileged staging UID/GID, durable claim phase, and old/new canonical-plan digests; journal-controlled paths are forbidden, and bounded old/new plan snapshots use fixed daemon-owned names. The daemon SHALL advance durable `prepared`, `activated`, `planPublished` and `verified` states around pointer replacement and atomic canonical-plan publication. Startup recovery SHALL idempotently finish or exactly roll back the pointer and canonical plan from every crash window before accepting another staging transaction or reporting READY.

#### Scenario: Activation stops after pointer replacement before plan publication

- **WHEN** startup finds the root activation journal and exact prepared plan snapshot
- **THEN** it republishes and verifies the new canonical plan, acknowledges the exact generation and clears the transaction before READY

#### Scenario: A prepared plan snapshot is corrupted

- **WHEN** recovery cannot match its journaled SHA-256
- **THEN** it restores the exact prior pointer and canonical plan and publishes only a correlated rejection

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::every_activation_crash_window_recovers_exact_pointer_plan_and_ack -- --exact
Gate contract: Exact named verification for Activation pointer and plan recovery are one transaction.
Maps: Requirement `Activation pointer and plan recovery are one transaction`; Scenarios `Activation stops after pointer replacement before plan publication`, `A prepared plan snapshot is corrupted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::corrupted_prepared_plan_rolls_back_exact_previous_generation_and_plan -- --exact
Gate contract: Exact named verification for Activation pointer and plan recovery are one transaction.
Maps: Requirement `Activation pointer and plan recovery are one transaction`; Scenarios `Activation stops after pointer replacement before plan publication`, `A prepared plan snapshot is corrupted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Accepted generation commit is operation-correlated

Only after the pointer, immutable generation and canonical plan all reverify SHALL the daemon durably journal terminal `accepted`. It SHALL then publish schema-1 `generation-ack.json`, remove the correlated marker and clear the transaction. Before terminal `accepted`, a publication or recovery failure SHALL restore the exact prior pointer and plan before publishing rejection. At or after terminal `accepted`, recovery SHALL only repeat matching acknowledgement and cleanup; it SHALL never roll back the accepted generation. The accepted acknowledgement SHALL bind the exact catalog SHA-256, selection SHA-256 and generation ID, including when the same signed catalog is replayed after root facts change.

#### Scenario: Accepted commit cleanup is interrupted

- **WHEN** restart observes a terminal accepted journal before acknowledgement cleanup finishes
- **THEN** it republishes only the correlated accepted acknowledgement and completes cleanup without rolling back the generation

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::every_activation_crash_window_recovers_exact_pointer_plan_and_ack -- --exact
Gate contract: Exact named verification for Accepted generation commit is operation-correlated.
Maps: Requirement `Accepted generation commit is operation-correlated`; Scenario `Accepted commit cleanup is interrupted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::same_catalog_new_root_selection_activates_and_retains_prior_generation -- --exact
Gate contract: Exact named verification for Accepted generation commit is operation-correlated.
Maps: Requirement `Accepted generation commit is operation-correlated`; Scenario `Accepted commit cleanup is interrupted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Rejected acknowledgement identity comes from frozen snapshots

Every rejected acknowledgement SHALL omit `generationId`. Its catalog and selection identities SHALL come only from fresh daemon-owned no-replace snapshots created after the entire rejected directory is atomically quarantined and claimed by the daemon. App-owned originals SHALL NOT be reread for acknowledgement identity. If selection is unavailable or unsafe, a catalog-only acknowledgement MAY be published only from a successfully frozen catalog snapshot. If the catalog cannot be safely read and snapshotted, no acknowledgement SHALL be published. Marker disappearance alone SHALL not represent acceptance.

#### Scenario: A rejected receipt cannot be frozen safely

- **WHEN** quarantine freezes the signed catalog but cannot freeze a trustworthy selection receipt
- **THEN** any acknowledgement contains only the frozen catalog identity and no generation ID

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::reject_incoming_quarantines_payload_and_reason -- --exact
Gate contract: Exact named verification for Rejected acknowledgement identity comes from frozen snapshots.
Maps: Requirement `Rejected acknowledgement identity comes from frozen snapshots`; Scenario `A rejected receipt cannot be frozen safely`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Rejected offers use one journaled quarantine slot

Rejection SHALL use the fixed `generations/rejecting` slot and a strict root-owned schema-1 journal published before claiming `next`. The journal SHALL bind the original UID/GID, bounded reason, canonical archive name and one of the phases `prepared`, `claimed`, `snapshotted`, `nextReady` or `acked`. It SHALL record frozen identities only after they become authoritative. Recovery SHALL run before inspecting a ready marker or accepting new staging. It SHALL reconcile rename, partial snapshot, next recreation, acknowledgement and archive cuts idempotently, without deriving ownership authority from attacker-mutable metadata. Missing or unsafe catalog SHALL follow a durable no-ack archive path instead of blocking staging forever.

#### Scenario: A generation is quarantined

- **WHEN** the signed transaction fails validation
- **THEN** the daemon recreates staging and publishes a rejection acknowledgement correlated to the exact readable catalog/selection pair, or only the catalog when the receipt was unreadable

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::reject_incoming_quarantines_payload_and_reason -- --exact
Gate contract: Exact named verification for Rejected offers use one journaled quarantine slot.
Maps: Requirement `Rejected offers use one journaled quarantine slot`; Scenario `A generation is quarantined`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::rejection_recovery_reconciles_rename_next_creation_ack_and_archive_cuts -- --exact
Gate contract: Exact named verification for Rejected offers use one journaled quarantine slot.
Maps: Requirement `Rejected offers use one journaled quarantine slot`; Scenario `A generation is quarantined`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Rejection handback preserves hostile new input

The recreated `next` SHALL remain exact-empty and daemon-owned while the old rejection acknowledgement is atomically published and fsynced and while archive/history cleanup completes. App ownership SHALL be a distinct final `handedOff` journal phase. Recovery that observes the journaled app owner after durable `acked` SHALL treat every entry as possible new staging, mutate none of them, and advance only the handoff journal. Rejection owner authority SHALL pass the same production unprivileged, non-root, non-root-group and daemon-distinct validation on initial observation and journal recovery; test fixtures MAY use the host daemon identity without weakening production validation.

#### Scenario: New staging appears after rejection handback

- **WHEN** recovery observes the journaled app owner after durable acknowledgement
- **THEN** it advances only handback authority and leaves every new staging entry untouched for the next exact inventory validation

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::handback_recovery_treats_app_claim_names_as_hostile_new_inventory -- --exact
Gate contract: Exact named verification for Rejection handback preserves hostile new input.
Maps: Requirement `Rejection handback preserves hostile new input`; Scenario `New staging appears after rejection handback`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Rejected history deletion freezes the complete bounded tree

Archive and history cleanup SHALL begin only after durable acknowledgement or durable no-ack completion. Cleanup SHALL freeze the complete tree through retained directory descriptors before the first unlink. Every directory SHALL be opened with `O_DIRECTORY|O_NOFOLLOW`, then chowned and chmodded through that descriptor before streaming entries. Metadata SHALL use `fstatat(AT_SYMLINK_NOFOLLOW)` and removal SHALL use `unlinkat` relative to retained parents. The preflight SHALL stop at 1024 nodes, depth 16 or 64 MiB; exceeding any bound SHALL preserve the diagnostic and block the fixed slot. Exact inventory enumeration SHALL fail while streaming at the expected-entry bound without accumulating attacker-controlled names. Pathname recursion and `remove_dir_all` are forbidden.

#### Scenario: Rejected history exceeds a deletion bound

- **WHEN** the frozen rejected tree exceeds its node, depth or byte limit
- **THEN** cleanup preserves the complete diagnostic tree and performs no unlink

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::rejection_cleanup_preserves_tree_when_node_bound_is_exceeded -- --exact
Gate contract: Exact named verification for Rejected history deletion freezes the complete bounded tree.
Maps: Requirement `Rejected history deletion freezes the complete bounded tree`; Scenario `Rejected history exceeds a deletion bound`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
