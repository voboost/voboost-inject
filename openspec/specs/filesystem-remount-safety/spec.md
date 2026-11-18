# Filesystem remount safety specification

## Purpose

Define exact protected-file mount boundaries and fail-closed remount recovery.

## Requirements

### Requirement: Protected-file remounts follow the exact runtime mount boundary

Before mutating a fixed system or vendor-policy artifact, the uninstall component SHALL select its target through a closed operation-to-path mapping and resolve only the exact affected boundary through the existing parent directory and a bounded read of `/proc/self/mountinfo`. Exact identity SHALL include mount ID, parent ID, major:minor, root, mount point, filesystem type and source. The fixed parent SHALL be canonicalized again and the complete target-to-mount binding revalidated before every syscall. Alias rejection SHALL compare each selected boundary with every parsed mountinfo record, including records not selected by the current one-target operation, and SHALL reject missing, duplicate, overlay, non-canonical, subtree/bind or ambiguous same-superblock aliases.

#### Scenario: System-as-root aliases vendor into system

- **WHEN** both fixed protected paths resolve beneath the same unique root mount
- **THEN** that boundary is remounted exactly once

#### Scenario: Android 11 exposes separate system and vendor mounts

- **WHEN** the fixed paths resolve beneath unique separate `/system` and `/vendor` records
- **THEN** only those two exact boundaries are remounted

#### Scenario: Runtime mount evidence is ambiguous or foreign

- **WHEN** a required boundary is missing, duplicated, overlay-backed, malformed or has a non-block-device source
- **THEN** protected-file mutation fails before any remount

#### Scenario: One-target operation has an unselected full-root alias

- **WHEN** the selected fixed target and any other parsed mountinfo record expose the same full-root superblock through different mount points
- **THEN** protected-file mutation fails before journal publication or remount

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::a9_scoped_remount_executes_one_revalidated_rw_and_ro_for_shared_boundary -- --exact
Gate contract: Shared system-as-root remount boundary.
Maps: Requirement `Protected-file remounts follow the exact runtime mount boundary`; Scenario `System-as-root aliases vendor into system`.
Preconditions: The exact Rust test supplies A9 mountinfo where both fixed paths resolve under one verified root boundary.
Observable result: The boundary receives exactly one revalidated RW and one RO remount.
Evidence boundary: Host mount syscall seam; target mount namespace is not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::a11_scoped_remount_executes_each_revalidated_boundary_once_rw_and_ro -- --exact
Gate contract: Separate A11 system and vendor boundaries.
Maps: Requirement `Protected-file remounts follow the exact runtime mount boundary`; Scenario `Android 11 exposes separate system and vendor mounts`.
Preconditions: The exact Rust test supplies unique separate system and vendor mount records.
Observable result: Each exact boundary receives one revalidated RW and one RO remount.
Evidence boundary: Host mount resolver and syscall seam; target A11 mounts are not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::mount_resolver_rejects_subtree_bind_and_ambiguous_superblock_aliases -- --exact
Gate contract: Ambiguous mount evidence rejection.
Maps: Requirement `Protected-file remounts follow the exact runtime mount boundary`; Scenario `Runtime mount evidence is ambiguous or foreign`.
Preconditions: The exact Rust test supplies subtree binds, duplicate and ambiguous same-superblock aliases and invalid records.
Observable result: Resolution fails before any remount authority is returned.
Evidence boundary: Host mountinfo parsing; live mount namespace races are simulated only.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::one_target_mount_resolver_rejects_unselected_full_root_superblock_alias -- --exact
Gate contract: Unselected full-root alias rejection.
Maps: Requirement `Protected-file remounts follow the exact runtime mount boundary`; Scenario `One-target operation has an unselected full-root alias`.
Preconditions: The exact Rust test includes an unselected mount record sharing the selected full-root superblock.
Observable result: One-target resolution rejects the alias before journal or remount.
Evidence boundary: Host mountinfo resolver; target alias creation is not exercised.

### Requirement: Durable remount journal grants only exact RO recovery

Before the first RW syscall, the component SHALL durably publish one bounded schema-v2 root-owned mode `0600` journal under its fixed uninstall authority. Every journal entry SHALL bind one closed operation target to its exact selected boundary, capture its original block-device read-only flag when backed by a block device, and grant only RO remount followed by restoration of that original flag. Schema-v1 journals retain their earlier RO-only recovery contract. Every later authorized invocation SHALL recover a present journal before advancing any requested operation: for each entry independently, canonicalize its own closed fixed target and resolve it against a fresh bounded full mountinfo snapshot whose alias check still covers every parsed record, then attempt RO restoration when that entry remains exact. A resolver error, foreign or ambiguous peer, peer identity drift or peer RO failure SHALL be retained as a combined error but SHALL NOT block attempts for other entries. The journal SHALL remain unless every restore and its durable removal succeed. This recovery is a one-shot retry contract and does not claim a resident supervisor.

#### Scenario: A one-shot process dies while a protected boundary may be RW

- **WHEN** a durable remount journal remains after failure, panic or process death
- **THEN** the next authorized invocation attempts every exact journaled boundary RO before advancing and retains the journal on incomplete recovery

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::scoped_remount_fault_matrix_always_attempts_reverse_ro_restore -- --exact
Gate contract: Journaled reverse-order RO recovery.
Maps: Requirement `Durable remount journal grants only exact RO recovery`; Scenario `A one-shot process dies while a protected boundary may be RW`.
Preconditions: The exact Rust test injects each modeled RW, mutation and RO failure cut.
Observable result: Recovery attempts every still-safe changed boundary in reverse order and retains incomplete journal authority.
Evidence boundary: Host fault-injection model; physical process death and storage durability are not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::scoped_remount_restores_each_changed_boundary_despite_peer_drift -- --exact
Gate contract: Independent journal-entry recovery.
Maps: Requirement `Durable remount journal grants only exact RO recovery`; Scenario `A one-shot process dies while a protected boundary may be RW`.
Preconditions: The exact Rust test changes one peer boundary identity while another journaled boundary remains exact.
Observable result: Peer drift is retained as error without blocking the exact boundary's RO attempt.
Evidence boundary: Host mount resolver and syscall seam; live target peer drift is not exercised.

### Requirement: Protected mutation is scoped RW and restores every boundary RO

Every mutation SHALL be scoped and least-privilege: remount only its affected boundary RW, run the mutation, then revalidate and remount every changed boundary RO in reverse order. Partial RW, mutation and individual RO failures SHALL still attempt all safe remaining restores and return combined errors. The fixed patched-policy install temporary SHALL be verified before entering the vendor-policy closure and deleted only inside that closure. After the complete target-to-mount binding is revalidated, RW and RO SHALL use the recorded source, exact target mount point and recorded filesystem type in `mount(source, target, filesystem_type, MS_REMOUNT | preserved_flags [| MS_RDONLY], NULL)`, preserving exactly the recorded `nosuid`, `nodev` and `noexec` flags and passing `data = NULL`. Caller-controlled paths and shell construction SHALL NOT participate.

#### Scenario: A scoped mutation fails after one boundary becomes RW

- **WHEN** a protected mutation or peer restoration fails after a verified boundary is remounted RW
- **THEN** cleanup attempts every still-safe changed boundary RO in reverse order and returns the combined error

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::remount_abi_uses_recorded_source_fstype_and_exact_flags -- --exact
Gate contract: Exact remount syscall ABI.
Maps: Requirement `Protected mutation is scoped RW and restores every boundary RO`; Scenario `A scoped mutation fails after one boundary becomes RW`.
Preconditions: The exact Rust test resolves a boundary from mountinfo with a recorded source, filesystem type, target mount point and security flags, then records RW and RO mount syscall arguments through the production seam used after target-to-mount revalidation.
Observable result: Both calls use the recorded source and filesystem type, the exact target mount point, `data = NULL`, and exactly `MS_REMOUNT | preserved_flags` for RW or `MS_REMOUNT | preserved_flags | MS_RDONLY` for RO.
Evidence boundary: Host syscall seam; target kernel acceptance is not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::remount_preserves_nosuid_nodev_and_noexec_security_flags -- --exact
Gate contract: Security-flag-preserving remount.
Maps: Requirement `Protected mutation is scoped RW and restores every boundary RO`; Scenario `A scoped mutation fails after one boundary becomes RW`.
Preconditions: The exact Rust test starts with every combination of `nosuid`, `nodev` and `noexec` security flags.
Observable result: RW and RO requests preserve each present security flag through cleanup.
Evidence boundary: Host flag construction; target mount options are not observed after syscall.

### Requirement: Scoped block protection precedes native remount

For a block-backed protected boundary, the uninstaller SHALL open a root-owned block node without following its final symlink and verify its device major:minor against the selected mount before any block ioctl. The original `BLKROGET` result SHALL be journaled before clearing protection with `BLKROSET`. The RW remount SHALL follow removal of block protection; the RO remount SHALL precede restoration of the original block flag. RW failure SHALL attempt RO recovery and restoration of the original block flag, retaining both primary and recovery errors. When `/dev/root` is absent, a bounded kernel-owned uevent SHALL supply one path-free `DEVNAME`, and the opened node SHALL still match the selected mount identity.

#### Scenario: A protected block device starts read-only

- **WHEN** the selected block device starts read-only
- **THEN** the write window clears its protection before RW remount and restores the original protection after RO remount

#### Scenario: RW remount fails

- **WHEN** RW remount fails after block protection is cleared
- **THEN** recovery remounts RO before restoring the original block flag and retains any recovery failure alongside the primary failure

#### Scenario: Root device identity supplies an unsafe name

- **WHEN** root-device uevent supplies a missing, repeated, path-bearing or malformed DEVNAME
- **THEN** device resolution rejects it before opening a block node or issuing an ioctl

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::mounts::block::tests::readonly_block_is_unlocked_before_rw_and_restored_after_ro -- --exact
Gate contract: Block protection ordering.
Maps: Requirement `Scoped block protection precedes native remount`; Scenario `A protected block device starts read-only`.
Preconditions: The production ordering seam operates on a model that rejects RW remount while the block flag is read-only.
Observable result: The RW window opens successfully and its RO close restores the original block flag.
Evidence boundary: Host ordering seam; actual block ioctls and kernel mount identity are not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::mounts::block::tests::failed_rw_restores_original_block_flag_and_preserves_both_errors -- --exact
Gate contract: Failed block write-window recovery.
Maps: Requirement `Scoped block protection precedes native remount`; Scenario `RW remount fails`.
Preconditions: The production seam receives RW failure for each original block flag and a separate RO failure case.
Observable result: Recovery preserves original protection and both failures remain observable.
Evidence boundary: Host syscall model; device crash durability is not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::mounts::block::tests::root_block_name_cannot_supply_paths_or_ambiguous_identity -- --exact
Gate contract: Closed root-device name resolution.
Maps: Requirement `Scoped block protection precedes native remount`; Scenario `Root device identity supplies an unsafe name`.
Preconditions: The bounded uevent parser receives valid and adversarial DEVNAME records.
Observable result: One path-free name is accepted; unsafe and ambiguous names are rejected.
Evidence boundary: Host parser; live block-node identity and crash recovery require target evidence.

# Unverified: Android block identity and interrupted protection recovery

## Unverified

### Unverified: Android block identity and interrupted protection recovery

Maps: Requirement `Scoped block protection precedes native remount`; Scenarios `A protected block device starts read-only`, `RW remount fails`, `Root device identity supplies an unsafe name`.
Unavailable observation: Real BLKROGET/BLKROSET on every supported Android layout, rejection of a substituted block node with another major:minor, and persisted original-flag restoration across every actual process-death cut.
Reason: Host ordering and parser tests do not execute Android ioctls, substitute device nodes, or kill the worker at each durable-journal boundary.
Required environment or artifact: Supported Enforcing Android integration fixtures with controlled device identity substitution and process-death cuts, plus the complete packaged CLI and Settings-button uninstall run.
