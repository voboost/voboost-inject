# Install and update recovery specification

## Purpose

Define one-root, transaction-correlated recovery for installation and update.

## Requirements

### Requirement: Schema-one operation phases match the architecture

The schema-version-1 WAL vocabularies SHALL be exact and monotonic. Install SHALL use `install-prepare`, `install-policy-backup`, `install-runtime-apply`, `install-app`, `install-policy-apply`, `install-reboot-first`, `install-agents`, `install-reboot-second`, `install-runtime-verify`, `install-inventory-commit`, `install-cleanup`, `install-complete`. Restore SHALL use `restore-prepare`, `restore-firmware-verify`, `restore-policy-backup`, `restore-policy-apply`, `restore-reboot-first`, `restore-runtime-apply`, `restore-reboot-second`, `restore-runtime-verify`, `restore-inventory-commit`, `restore-cleanup`, `restore-complete`. Neither reader SHALL accept aliases or migrate another vocabulary.

`install-agents` SHALL wait for the correlated daemon-authored generation acknowledgement. The daemon SHALL build the initial generation only from the root-owned frozen full product closure, the independently signed external `agents.json`, and root-owned `vehicle.json`; it SHALL compute the selection itself and include every `supported` or `unknown` agent target plus its cataloged host. The app SHALL NOT author the receipt or stage embedded agents. Absence or correlation failure SHALL prevent the second reboot and completion.

`install-runtime-apply` SHALL publish versionless flat native files, the verified product manifest pair and init definition before the first reboot. `install-app` SHALL install staged `voboost-app.apk` and twice re-observe the PackageManager-owned `/data/app/.../base.apk`, grant the fixed AppOp and derive one canonical user-0 application UID from bounded exact PackageManager output. First-boot relabel SHALL correlate the same UID with exact device-encrypted app data and preserve its MLS range. Only then may `install-policy-apply` publish the verified policy and request the first reboot. The app SHALL NOT create a root-zone generation directory.

Post-reboot installed-APK verification SHALL tolerate Package Manager service startup latency without weakening identity acceptance. It SHALL retry only the bounded fixed `pm path ru.voboost` observation, beginning at 50 milliseconds and capping delay at one second for at most 60 attempts. Only exit success with empty stderr proceeds to the existing exact one-row path, inode, size and SHA-256 checks. Command errors, unsuccessful exits and stderr are never accepted; exhaustion fails closed without advancing the install WAL.

#### Scenario: A persisted phase is advanced

- **WHEN** install or restore completes one durable step
- **THEN** the WAL contains only its exact immediate successor and preserves two reboot phases

#### Scenario: Package Manager is not ready after the second reboot

- **WHEN** early init observations fail before one exact successful package-path result
- **THEN** installer waits with bounded backoff, accepts only the existing exact APK identity checks and does not mark cleanup failed solely because Package Manager started later than the init service

# Gate: cargo test --manifest-path install/Cargo.toml tests::phases_are_operation_first_and_have_two_reboots -- --exact
Gate contract: Schema-one install phase vocabulary.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: The exact Rust phase test serializes the complete installer sequence.
Observable result: Every canonical install phase round-trips in order without an alias and preserves the two reboot positions.
Evidence boundary: Host WAL vocabulary and order only; target reboot and SELinux loading are not exercised.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::schema_one_restore_phases_match_architecture_exactly -- --exact
Gate contract: Schema-one restore phase vocabulary and state-machine order.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: The dedicated Rust test enumerates every exact restore phase and advances through every immediate successor.
Observable result: Every canonical restore phase is present once, serializes and round-trips under its exact kebab-case name, aliases are rejected, and no phase is skipped.
Evidence boundary: Host WAL vocabulary, serialization and order only; target reboot and SELinux loading are not exercised.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::production_restore_driver_crosses_two_boots_and_completes_exact_order -- --exact

Gate contract: Production restore phase-driver composition.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: The production restore driver runs with strict fake policy, init, native, inventory, cleanup, boot and reboot actions.
Observable result: Every mutating action runs once in exact order, same-boot invocations repeat each reboot without advancing, two distinct boot identities are required, and terminal cleanup finishes only after runtime verification and inventory commit.
Evidence boundary: Host execution of the production orchestration with strict platform actions; Android mounts, SELinux load, init and physical reboot are not executed.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::production_restore_driver_retries_every_failed_mutating_phase -- --exact

Gate contract: Production restore mutation failure restart.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: Each production restore action fails once before its successor is persisted.
Observable result: The phase does not advance on failure and a restarted invocation executes that exact action again before continuing.
Evidence boundary: Host orchestration and strict failure injection; target syscall side effects remain separate evidence.

# Gate: cargo test --manifest-path install/Cargo.toml tests::production_install_driver_crosses_two_boots_and_executes_every_phase_once -- --exact

Gate contract: Production install phase-driver composition.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: The production driver runs with one real `OperationLease`, a durable install WAL and strict scripted platform actions across three distinct host boot identities.
Observable result: Every mutating phase executes once in exact order, each reboot phase is durably projected only after its boot ID is appended, same-boot retry repeats the reboot without advancing, and the persisted WAL reaches cleanup without a projection-digest gap.
Evidence boundary: Host execution of the production phase driver with strict fake phase/platform operations; Android PackageManager, init, SELinux and physical reboot are not exercised.

# Gate: cargo test --manifest-path install/Cargo.toml tests::production_install_driver_restarts_at_every_failed_mutation_phase -- --exact

Gate contract: Production install mutation failure restart.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: Each non-reboot production phase action fails once while the real driver owns its operation lease and durable WAL.
Observable result: The failed action does not advance the WAL; a second invocation resumes from the same phase and executes that phase again before any successor.
Evidence boundary: Host phase/action and WAL/lease composition; individual Android syscall side effects require separate adapter and target gates.

# Gate: cargo test --manifest-path shared/Cargo.toml installed_apk::tests::package_manager_startup_retry_accepts_only_success_without_stderr -- --exact
Gate contract: Post-reboot Package Manager readiness retry.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `Package Manager is not ready after the second reboot`.
Preconditions: The shared installed-APK seam receives success-with-stderr, silent failure and then exact success.
Observable result: The first two results are never accepted, delays are 50 and 100 milliseconds, and only the exact successful result proceeds.
Evidence boundary: Host retry classification and schedule; Android Package Manager startup latency remains target evidence.

# Gate: cargo test --manifest-path shared/Cargo.toml installed_apk::tests::package_manager_startup_retry_is_bounded_and_never_accepts_failure -- --exact
Gate contract: Package Manager retry exhaustion.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `Package Manager is not ready after the second reboot`.
Preconditions: Every bounded package observation returns an error.
Observable result: The configured attempt count is exhausted with one fewer waits and no result is accepted.
Evidence boundary: Host bound and fail-closed result; Android command timeout behavior is covered separately.

### Requirement: Emulator install acceptance separates staging admission from postboot decisions

An explicit `emulator_acceptance` staging descriptor SHALL require actual Android QEMU and effective UID/GID 0. Admission before reboot1 SHALL allow the installer's intentional permissive preparation. The observer acceptance wait and STATUS/ACCEPT/REJECT consumption SHALL require root Android QEMU with actual SELinux Enforcing, `install-agents`, exactly one original boot ID and a different current boot. The same platform and boot fences SHALL be rechecked before consuming a bounded request. Observer acceptance SHALL remain separate from the daemon-authored generation acknowledgement; descriptors without `emulator_acceptance` SHALL retain ordinary installation semantics.

#### Scenario: Armed installation crosses the first reboot

- **WHEN** a root Android QEMU install is armed while boot0 is Permissive and resumes in Enforcing boot1
- **THEN** staging admission permits boot0, the driver requests reboot1 without acceptance, and acceptance at `install-agents` permits advancement to reboot2 with both boot IDs recorded

#### Scenario: Staging admission receives foreign platform authority

- **WHEN** an armed staging descriptor is presented outside Android QEMU or with nonroot effective UID or GID
- **THEN** staging admission fails

#### Scenario: Intermediate acceptance remains Permissive

- **WHEN** an armed transaction reaches boot1 with SELinux still Permissive
- **THEN** acceptance fails while the WAL remains `install-agents` with one recorded reboot and no reboot2 request

#### Scenario: A live acceptance request loses its platform or correlation fence

- **WHEN** root, QEMU, Enforcing, exact intermediate WAL, boot, transaction, manifest, token or deadline authority is absent or changes before a STATUS/ACCEPT/REJECT request is consumed
- **THEN** no observer decision authorizes reboot2

# Gate: cargo test --manifest-path install/Cargo.toml tests::armed_install_crosses_permissive_boot0_to_enforcing_boot1 -- --exact

Gate contract: Distinct preboot admission and intermediate acceptance in the production transaction driver.
Maps: Requirement `Emulator install acceptance separates staging admission from postboot decisions`; Scenarios `Armed installation crosses the first reboot`, `Staging admission receives foreign platform authority`, `Intermediate acceptance remains Permissive` (host predicate and phase-driver subsets).
Preconditions: A real operation lease and durable WAL drive `install-prepare` with scripted boot/platform actions; the production admission and strict platform predicates receive Permissive boot0, Enforcing or Permissive boot1, and foreign Android/QEMU/UID/GID facts.
Observable result: Permissive boot0 reaches only reboot1 without acceptance; Enforcing boot1 reaches reboot2 with two boot IDs; Permissive boot1 retains `install-agents`, one boot ID and one reboot request; foreign admission fails.
Evidence boundary: Host platform predicates and production phase orchestration with scripted phase actions only; actual Android properties, SELinux, sockets, relabel, init and reboots remain unverified. The complete 45-test host installer suite is supporting evidence, not this gate's selector.

# Unverified: Packaged Android install acceptance lifecycle

### Requirement: The intermediate install boot reaches readiness before reboot2

After the first reboot the installer SHALL retain `install-agents` until boot completion and observer acceptance, when armed, finish in the same exact intermediate boot. Boot readiness SHALL be bounded to 120 seconds; timeout, boot drift or uninstall SHALL prevent reboot2 without advancing the WAL. The correlated generation acknowledgement SHALL still be required independently.

#### Scenario: Intermediate boot readiness succeeds or expires

- **WHEN** boot completion becomes ready within the bound or remains unavailable until the deadline
- **THEN** readiness either permits the remaining intermediate checks or fails with `install-agents` and one recorded boot preserved

#### Scenario: Intermediate boot changes or uninstall supersedes installation

- **WHEN** the intermediate boot ID changes or an explicit uninstall arrives during readiness polling
- **THEN** the installer requests no second reboot and retains the intermediate WAL

# Gate: cargo test --manifest-path install/Cargo.toml tests::intermediate_readiness_waits_without_advancing_wal_and_times_out_closed -- --exact

Gate contract: Bounded intermediate readiness preserves the WAL.
Maps: Requirement `The intermediate install boot reaches readiness before reboot2`; Scenario `Intermediate boot readiness succeeds or expires`.
Preconditions: The production driver receives a durable `install-agents` WAL, one original boot ID and scripted readiness before or at the deadline.
Observable result: Readiness within the bound reaches reboot2; deadline failure retains `install-agents`, one boot ID and no reboot request.
Evidence boundary: Host phase driver and scripted clock/readiness; actual Android boot completion remains unverified.

# Gate: cargo test --manifest-path install/Cargo.toml tests::intermediate_readiness_rejects_uuid_drift_and_original_boot -- --exact

Gate contract: Intermediate readiness rejects changed and original boots.
Maps: Requirement `The intermediate install boot reaches readiness before reboot2`; Scenario `Intermediate boot changes or uninstall supersedes installation` (boot branch).
Preconditions: The production driver receives an original boot or a boot identity that changes during readiness polling.
Observable result: Both fail with `install-agents` and no second reboot request.
Evidence boundary: Host boot-identity injection only.

# Gate: cargo test --manifest-path install/Cargo.toml tests::intermediate_readiness_honors_uninstall_during_poll -- --exact

Gate contract: Explicit uninstall interrupts intermediate readiness.
Maps: Requirement `The intermediate install boot reaches readiness before reboot2`; Scenario `Intermediate boot changes or uninstall supersedes installation` (uninstall branch).
Preconditions: The production driver receives an uninstall fence during scripted readiness polling.
Observable result: Uninstall fails installation while preserving `install-agents` and requesting no second reboot.
Evidence boundary: Host polling and injected uninstall fence; Android request transport remains unverified.

# Unverified: Packaged Android install acceptance lifecycle

### Requirement: Install commits one shared uninstall authority

The fixed-path no-argument installer SHALL authenticate canonical `staging.json`, signed `voboost.json` and the exact flat staging tree before mutation. `staging.json` SHALL contain only schema version, canonical 64-lowercase-hex transaction ID, product release identity and SHA-256 of exact `voboost.json`; the directory name and all three identities SHALL agree. The signed closure SHALL contain exactly the artifact rows of the validated product manifest plus `voboost.json` and `voboost.json.sig`; `staging.json` is transaction control and is not an artifact row. The installer SHALL retain one no-follow root directory descriptor, enumerate exactly the manifest-derived immediate entry set with a hard MAX_ARTIFACTS+3 entry bound and no recursive traversal, and require every entry to be an expected root-owned mode-`0600` single-link regular file before capture. Any empty or nonempty directory, depth, an entry beyond the manifest-derived set or hard bound, symlink, hard link, special file, foreign ownership, wrong mode or root pathname replacement SHALL fail before product mutation. `install.json`, `install.json.sig`, release-artifact `base.apk`, nested payload paths and embedded APK agents SHALL be rejected.

`voboost.json` SHALL be verified by a mandatory embedded `release-catalog` public key distinct from `agent-catalog`, `native-executable` and `restore`. The product-derived restore authority SHALL use the same embedded restore public root in install, daemon inventory, restore and uninstall; installation SHALL NOT require a separate install-authorization or native-manifest public root. The installer SHALL verify every declared size and SHA-256, native executable role signatures, APK Signing Block certificate identity, raw `agents.json` signature, exact catalog/product DEX identity and product-derived restore authority before creating `root.json`. It SHALL publish the product manifest pair, init continuation and versionless stable members transactionally, archive the init bytes and metadata, publish the pristine policy and uninstall documents, then publish `install-inventory.json` last.

The fresh Package Manager probe SHALL classify absence only from the exact `/system/bin/pm path ru.voboost` result tuples observed across supported Android revisions: exit 1 with both streams empty, or exit 1 with empty stdout and exact `Error: package ru.voboost was not found\n` stderr. Canonical exit-0 `package:/absolute/path\n` output is presence. Every other exit, signal, stdout or stderr combination is ambiguous and SHALL fail closed.

#### Scenario: Inventory publication is interrupted

- **WHEN** a crash occurs before or during one document rename
- **THEN** no unverified inventory is accepted and retry publishes the inventory only after all five referenced documents are durable

#### Scenario: A fresh-install object collides

- **WHEN** the product root, init hook, package, package data or AppOp contains existing or partial state
- **THEN** installation fails before recovery, policy or package mutation and never requests package replacement

#### Scenario: The product and agent catalogs disagree

- **WHEN** one target DEX filename, size or SHA-256 differs between signed `agents.json` and signed `voboost.json`
- **THEN** install rejects the complete product authority before mutation

#### Scenario: Staging contains a non-flat or excessive entry

- **WHEN** the transaction root contains an empty directory, a deep directory tree, an entry beyond the manifest-derived set or hard bound, symlink, hard link, FIFO, wrong-mode file or replaced root pathname
- **THEN** immediate descriptor-relative enumeration rejects before artifact capture or product mutation

#### Scenario: A manifest expands to its exact flat staging inventory

- **WHEN** a validated product manifest is expanded into signed closure and staging member names
- **THEN** only its flat artifact basenames, the manifest pair and separate staging.json are present

# Gate: cargo test --manifest-path install/Cargo.toml --bin voboost-install tests::installer_shared_module_inventory_rejects_conflicts_and_duplicate_product_rows -- --exact

Gate contract: Product and agent catalog identity disagreement.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `The product and agent catalogs disagree`.
Preconditions: The actual installer inventory verifier receives canonical catalog fixtures with size, digest, entry, process, filename collision, duplicate and missing product-row mutations.
Observable result: Every contradictory identity or missing/duplicate closure member is rejected.
Evidence boundary: Host verifier semantics only; real signed artifact bytes and Android installation remain separate gates.

# Gate: cargo test --manifest-path install/Cargo.toml tests::host_staging_is_exact_flat_artifact_closure -- --exact
Gate contract: Exact initial-install product closure.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `A manifest expands to its exact flat staging inventory`.
Preconditions: The host fixture expands a validated synthetic product manifest to 73 ordered artifact rows.
Observable result: Exactly 75 signed closure names and 76 staging names include both owner and injection executables; all names are flat, and base.apk and install.json are absent.
Evidence boundary: Host typed inventory only; artifact bytes, signatures, ADB upload and Android mutation are separate evidence.

# Gate: cargo test --manifest-path install/Cargo.toml tests::staging_root_rejects_empty_deep_wide_link_and_special_entries_before_capture -- --exact
Gate contract: Bounded immediate staging enumeration.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `Staging contains a non-flat or excessive entry`.
Preconditions: The host fixture opens one mode-0700 transaction root, creates exactly MAX_ARTIFACTS+3 immediate mode-0600 files, then independently substitutes each hostile entry class.
Observable result: Exact N passes; an empty directory, 128-level deep tree, N+1 empty file, symlink, hard link, FIFO, wrong mode and named-root replacement each fail while the retained original descriptor remains readable.
Evidence boundary: Host descriptor, fstatat, openat and filesystem identity semantics; Android root UID and SELinux labels require device evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::initial_install_builds_exact_root_owned_generation_after_every_file_cut -- --exact
Gate contract: Root-owned initial generation interruption matrix.
Maps: Requirement `Schema-one operation phases match the architecture`; Scenario `A persisted phase is advanced`.
Preconditions: A root-owned frozen manifest-derived signed product closure contains the declared common and target DEX files, an install WAL and root-owned vehicle facts.
Observable result: Daemon selection includes all supported targets, writes its own receipt and converges to the same exact ready generation after every file-prefix interruption cut.
Evidence boundary: Host filesystem, Ed25519 fixture keys and generation state machine; Android init, reboot, SELinux Enforcing and live injection are not exercised.

# Gate: cargo test --manifest-path install/Cargo.toml fresh::tests::every_fresh_collision_fails_before_mutation -- --exact
Gate contract: Fresh-only install collision fence.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `A fresh-install object collides`.
Preconditions: The focused test supplies each production observation class independently to the common fail-closed decision.
Observable result: Every collision returns an error before the mutation continuation, while exact absence produces the canonical observed-facts receipt.
Evidence boundary: Host decision and receipt serialization; Android Package Manager and AppOps command behavior remains target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml fresh::tests::package_probe_accepts_only_documented_absence_or_canonical_presence -- --exact
Gate contract: Fresh package probe exact-result parser fence.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `A fresh-install object collides`.
Preconditions: Production parser inputs cover API 28 silent absence, diagnostic absence, canonical presence, near-miss output, other nonzero exits, contradictory and abnormal-termination results.
Observable result: Only the two exact status/stdout/stderr absence tuples are accepted as absence, canonical package paths are classified as presence, and every near miss fails closed.
Evidence boundary: Host parser behavior only; the target firmware's actual Package Manager output remains target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml fresh::tests::package_probe_command_preserves_api28_silent_absence_tuple -- --exact
Gate contract: Fresh package probe bounded-command fence.
Maps: Requirement `Install commits one shared uninstall authority`; Scenario `A fresh-install object collides`.
Preconditions: The bounded production runner is exercised with a real child process that returns a silent nonzero status and one that exceeds its deadline.
Observable result: Exact exit-1 empty streams reach the strict parser without normalization and classify as the API 28 absence tuple, while timeout remains a command error.
Evidence boundary: Host command behavior only; the target firmware's actual Package Manager output remains target evidence.

# Unverified: Install inventory publication crash recovery

### Requirement: One transaction has one temporary authority

Every install or update SHALL create exactly one `/data/voboost/install/<tx>` directory. Recovery SHALL use only the correlated `/data/voboost/recovery/<tx>` directory and SHALL resume that same transaction. A second transaction, hidden top-level path, or duplicate recovery executable SHALL NOT be used.

#### Scenario: Execution is interrupted

- **WHEN** publication stops at any durable cut
- **THEN** retry resumes the same transaction from its authenticated journal

# Unverified: Installer early partial-recovery publication

### Requirement: Transaction directories are transient

Successful install, update, rollback, or recovery SHALL prove both correlated transaction directories absent. Neither transaction directory is steady-state inventory.

#### Scenario: Transaction completes

- **WHEN** the final durable state is accepted
- **THEN** both correlated transaction directories are absent

# Unverified: Transaction cleanup host proof

### Requirement: Terminal install cleanup retains recovery authority

The correlated terminal intent SHALL remain durable while the install lease owns `operation.json`. It SHALL bind the transaction, install descriptor and exact installed-APK observation needed to finish after staging is removed. During `install-cleanup`, the owner SHALL remove staging, rollback bytes and every transaction member except the WAL, then durably advance the WAL to `install-complete` and publish the complete document. It SHALL remove the WAL and empty transaction directory next, unlink the terminal intent last, fsync its parent and retain `operation.json`. Recovery with a nonterminal cleanup document, WAL and intent SHALL finish payload cleanup before publishing complete. Recovery with complete plus WAL SHALL finish control cleanup. Recovery with complete plus intent but no transaction directory SHALL verify committed inventory and exact absence before removing the intent. An intent without operation authority SHALL fail closed.

Payload cleanup SHALL admit only the exact transaction-owned recovery files, the canonical `generation-ack.json` and one optional mode-`0700` `frozen` directory containing exactly the manifest-derived root-owned mode-`0600` single-link regular closure members. The directory is optional only for crash replay after its verified removal. Cleanup SHALL remove the frozen closure and generation acknowledgement before control cleanup. Any other directory, symlink, non-file member, wrong owner, wrong mode, extra link or additional recovery member SHALL stop cleanup before staged product deletion.

#### Scenario: Restart occurs at a terminal cleanup boundary

- **WHEN** restart occurs before intent publication, after payload cleanup, after complete publication or after WAL cleanup
- **THEN** the same install authority resumes the exact remaining step, retains the complete operation document, removes the terminal intent last and admits no different operation while residue remains

# Gate: cargo test --manifest-path install/Cargo.toml tests::completed_install_is_retained_across_every_terminal_cleanup_cut -- --exact
Gate contract: Terminal install pointer and intent crash matrix.
Maps: Requirement `Terminal install cleanup retains recovery authority`; Scenario `Restart occurs at a terminal cleanup boundary`.
Preconditions: The focused test uses the production operation lease, split payload/control cleanup and recovery dispatcher before intent, before payload cleanup, after payload cleanup and after control cleanup.
Observable result: Every cut converges to absent transaction directories and intent while retaining the exact complete operation document.
Evidence boundary: Host filesystem unlink and fsync behavior; Android power-loss durability remains target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml transaction::tests::terminal_cleanup_is_exact_and_foreign_residue_is_non_mutating -- --exact
Gate contract: Exact frozen closure and generation-ack cleanup ownership.
Maps: Requirement `Terminal install cleanup retains recovery authority`; Scenario `Restart occurs at a terminal cleanup boundary`.
Preconditions: A terminal transaction contains staging, the 70-member frozen closure, generation acknowledgement, WAL and one hostile recovery member.
Observable result: The hostile member blocks all cleanup; after its removal, staging, frozen closure and acknowledgement are removed while the WAL remains for control cleanup.
Evidence boundary: Host recovery inventory and unlink behavior; Android crash durability remains target evidence.

### Requirement: Update publishes the daemon last

Update SHALL authenticate the complete native set, publish every non-daemon member first, and publish `/data/voboost/voboost-daemon` last. It SHALL use exactly one transaction from staging through cleanup.

#### Scenario: Publication stops before daemon replacement

- **WHEN** all other members are durable but the daemon is not
- **THEN** recovery resumes the same transaction and does not expose a mixed committed generation

# Unverified: Update transaction host proof

### Requirement: Restore is one authenticated two-reboot transaction

Before `restore-inventory-commit`, Restore SHALL authenticate the exact active `voboost.json` bytes with its embedded `release-catalog` root and authenticate exact canonical `restore.json` bytes with the shared embedded restore root and a raw 64-byte Ed25519 signature. `restore.json` SHALL be the shared `RestoreDocument` schema containing only `schemaVersion`, canonical product `releaseIdentity`, `sourceDefinitionSha256` and `restorableClosureSha256`; Restore SHALL reject the retired install-authorization transcript, extended restore descriptor, native release manifest and component release identity. It SHALL require the same release identity as `voboost.json`, recompute the restorable-rows digest and verify both manifest artifact rows for the restore pair before mutation.

Inventory commit recovery SHALL treat a stable member already equal to its target as a completed rename cut. If its transaction-local temporary still exists, Restore SHALL authenticate the temporary as the same exact target bytes, unlink it and fsync its parent before cleanup; an absent temporary is an already completed cut, while different, linked or otherwise foreign residue fails closed. Successful replay SHALL leave `inventory-commit` empty before removing that directory.

Restore SHALL construct one transaction-qualified flat target from every restorable artifact row in the active product manifest. It SHALL read the APK through the exact PackageManager-observed base path, the complete immutable active generation through its canonical root-owned pointer and every other artifact through its canonical flat `/data/voboost/<basename>` authority. It SHALL stage every member under `/data/voboost/recovery/<transaction-id>/product-target/<basename>`, verify every staged byte count and SHA-256, republish every root-flat runtime/init member after the first reboot and reverify the complete installed restorable closure after publication and after the second reboot. The active restore pair SHALL remain installed and manifest-bound. One corrupt, missing, linked, noncanonical, unknown or mismatched member SHALL fail before inventory commit. Restore SHALL use no shell cryptography.

Every restore WAL, authorization document, commit descriptor, temporary and rollback member SHALL live only beneath `/data/voboost/recovery/<transaction-id>/`. The canonical lowercase 64-hex transaction ID SHALL qualify protected-target temporary names; no fixed cross-transaction restore sidecar is authoritative.

The stock-labeled, separately signed `voboost-restore` SHALL accept only its fixed stable path, root execution, its own valid appended role signature, the fixed active product manifest pair and the fixed restore pair. The restore WAL SHALL bind the exact restore document and signature bytes, exact active manifest digest, product release identity, restorable closure digest, current committed inventory, the actually observed stock policy, patched policy, flat product target and boot IDs. Its transaction ID SHALL be the SHA-256 of the exact restore document bytes, raw signature, active manifest SHA-256 and starting boot ID. It SHALL never reconstruct a release channel, base version or beta number from the product identity. Unknown, reordered, substituted, linked, oversized, non-root-owned, or mismatched input SHALL fail before mutation.

Before the first reboot, the bootstrap SHALL parse a bounded `/proc/self/mountinfo`, select one unambiguous ext4 or f2fs boundary for the fixed policy path, reject aliases and topology drift, and preserve `nosuid`, `nodev`, and `noexec` on every remount. Policy transformation SHALL execute the already-published live `voboost-selinux` program only through one retained `/proc/self/fd/<n>` descriptor after requiring root ownership, single link, mode `0700`, exact signed frozen bytes and stable opened/named identity before and after execution. The mode-`0600` frozen closure member SHALL never be chmodded or executed, and pathname fallback is forbidden. Policy publication SHALL use a root-owned no-follow temporary, preserve the exact policy owner, mode and SELinux xattr, fsync before and after rename, and run under a child watchdog that restores the pristine bytes and read-only boundary after EOF or an unclean parent result. The same transaction SHALL atomically publish the digest sidecar `/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256` with the exact bytes of `/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256` in the same writable window, because init ignores the precompiled policy and recompiles the stock CIL sources whenever the sidecar digest diverges; every recovery path SHALL restore both the pristine policy bytes and the pristine sidecar bytes with their exact owner, mode and SELinux xattr. A successful first reboot SHALL be recognized only by a changed canonical boot ID.

Install and restore SHALL use one shared mount-policy transaction before changing protected policy bytes or mount state. Its canonical journal SHALL bind the operation, transaction, boot ID, pristine policy identity and exact selected boundaries. The journal SHALL be durable and the exact pristine policy SHALL be open through a verified descriptor before the first protected mutation. An independent child SHALL treat parent death, timeout and explicit error as abort, atomically restore the exact pristine bytes, restore every changed boundary read-only in reverse order with its preserved security flags, restore SELinux Enforcing and fsync the result. The parent SHALL disarm the child only after a durable loaded-policy or reboot-transfer milestone gives startup recovery sole authority.

Install and restore startup SHALL consume a surviving correlated mount-policy journal before advancing. A failed boot milestone SHALL restore the pristine policy and request a recovery reboot. Mount boundaries SHALL be derived from the fixed protected target and current bounded mountinfo, including Android 9 system-as-root and Android 11 split topology, without assuming a fixed vendor mount.

The mount-policy journal uses schema 4 and SHALL durably record each block-backed boundary's original read-only flag before fork or unlock. RW remount SHALL follow verified block unlock; RO remount SHALL precede restoration and readback of the original flag. Recovery after reboot SHALL use the current validated device identity with the journaled original flag for the same logical boundary. Failed mount or protection recovery SHALL retain the journal. Legacy schema 3 remains readable with its original canonical bytes and grants no block ioctl authority; an attempt to reopen a block filesystem writable without its journaled original flag SHALL fail and retain recovery authority.

Before creating product ownership or recovery state, the installer SHALL parse staged `voboost-app.apk` with the bounded APK Signing Block v2/v3 reader, require the standard outer length-prefixed signer sequence containing exactly one length-prefixed signer per supported scheme, require one certificate authority across supported signer records and bind it to the signed app row in `voboost.json`. A v2 signed-data record MAY carry the exact empty compatibility extension emitted by current Android `apksig`; no other trailing signer or signed-data bytes are accepted. Unknown signing-block pairs are ignored only when at least one supported v2/v3 pair independently establishes the one-signer authority. The APK SHALL contain no agent catalog, DEX or catalog-key asset consumed by installation. The installer SHALL instead read flat external `agents.json`, raw 64-byte `agents.json.sig`, `agent-common.dex` and every cataloged target DEX, verify the signature with its embedded agent-catalog authority and require exact filename, size and SHA-256 equality with all agent rows in `voboost.json`. Installer and daemon SHALL use the same shared typed schema-one parser and canonical serializer for producer field order, compact spelling, terminal LF and ASCII Unicode escapes; generic JSON map ordering is not an authority.

Bootstrap staging MAY exist before the global install lease. Before creating a transaction member, the installer SHALL atomically create `/data/voboost/recovery` descriptor-relatively with mode `0700`, or open an existing name with `O_NOFOLLOW` and require exact root ownership and mode `0700`; it SHALL never chmod-adopt a preexisting foreign identity. The transaction directory SHALL likewise be created descriptor-relatively at mode `0700` and revalidated. The installer SHALL durably publish the correlated install WAL, acquire and revalidate the verified install descriptor and only then publish `/data/voboost/root.json` or any persistent root authority. It SHALL assign correlated failure-publication identity only after that verified lease exists. Every earlier authenticated failure SHALL emit one bounded canonical pre-transaction failure result and SHALL NOT attempt publication into absent or unowned recovery state. A competing operation or injected failure before lease acquisition SHALL leave `root.json` absent.

The root-only fixed-path no-argument restore bootstrap SHALL publish or resume the WAL-correlated global restore lease before any mutation or reboot. The same bootstrap SHALL adopt the current firmware policy as the new pristine baseline, restore and revalidate the committed init bytes before the first reboot so Android init owns continuation, request the second reboot only after the manifest-derived root-flat target is applied, verify the complete post-second-boot restorable closure, atomically rotate the five uninstall documents with the inventory last and the digest-addressed baseline, retire the prior baseline after the new inventory is durable, remove every restore transient, and retain the verified terminal operation result. The stable restore executable and product restore pair SHALL remain installed. The terminal uninstall state machine remains separate and SHALL retain one terminal reboot owner.

Android init SHALL invoke Restore only with `--init-continuation`. That mode SHALL never create a Restore transaction: an absent operation or an Install, Update, Uninstall, or failed Restore operation is a no-op; a running or reboot-required Restore resumes only its exact verified transaction and fixed WAL; and a complete Restore performs only correlated terminal cleanup. Malformed, missing, or cross-linked Restore authority SHALL fail closed. A no-argument root fixed-path request SHALL remain the only transaction creator, including after it finishes cleanup for a prior complete Restore. `--product-system-update` retains its separate init-only contract, and every other argument is rejected.

Live init-hook and transaction-qualified temporary observation SHALL classify only an exact `ENOENT` from the no-follow open as absent. Symlinks, hardlinks, wrong owner, group, mode or SELinux context, oversized content, read or metadata I/O failure, and identity change during or after reading SHALL fail closed without selecting create or removing either object. Publication SHALL use the opened fixed parent directory, `O_NOFOLLOW`, transaction-qualified names and atomic no-replace or exchange rename; it SHALL reobserve both names before the first rename and after every crash-resumable transition until the target is committed and the temporary is absent.

#### Scenario: Signed product target or one restorable member is substituted

- **WHEN** the product manifest, release identity, APK, any generation member, daemon, privileged executable, either library for either ABI, init, restore document or detached signature differs from the signed target
- **THEN** restore fails before persistent inventory publication

#### Scenario: Restore stops at any durable policy or inventory cut

- **WHEN** the process restarts before or after policy publication, either reboot request, or one correlated inventory rename
- **THEN** the same signed transaction resumes from its canonical WAL or commit journal and either reaches one complete new authority set or fails closed without accepting caller-selected recovery data

#### Scenario: Init restore observes a hostile or unstable member

- **WHEN** the live hook or transaction temporary is linked, has foreign metadata or context, exceeds its bound, returns an error other than exact `ENOENT`, or changes around publication
- **THEN** restore fails closed, preserves the observed objects, and never converts that observation into absent/create authority

#### Scenario: Parent dies at any protected mutation cut

- **WHEN** install or restore stops during a policy write, rename, fsync, mount or Enforcing transition
- **THEN** the child or next startup idempotently restores the exact pristine policy, every still-exact changed boundary read-only and SELinux Enforcing before another protected operation advances

#### Scenario: Installer APK signer authority is substituted

- **WHEN** the staged APK signer or external signed catalog authority differs from `voboost.json`
- **THEN** installation fails before product ownership, recovery state, remount or policy mutation

#### Scenario: Platform-valid v2 signer framing is presented

- **WHEN** a one-signer v2 APK contains the standard signer-sequence wrapper and the exact empty `apksig` compatibility extension
- **THEN** the installer extracts the certificate bound by `voboost.json`; malformed lengths, duplicate signers, duplicate supported pairs, unsupported-only blocks and arbitrary trailing data fail before mutation

#### Scenario: Authentication fails before a durable install authority exists

- **WHEN** staging, manifest, inventory or APK authentication fails before the operation lease is acquired and revalidated
- **THEN** the installer emits one bounded pre-transaction failure result without claiming a correlated transaction or silently writing to absent recovery state

#### Scenario: The signed producer catalog uses canonical schema order

- **WHEN** `agents.json` uses `schemaVersion`, `supportedAbis`, `agentEntryAbi`, `core`, `agents` order and ASCII-escaped localized text
- **THEN** both installer inventory admission and daemon catalog admission accept the exact signed bytes; reordered, duplicate, unknown, pretty-printed or non-terminated variants fail closed

# Gate: cargo test --manifest-path shared/Cargo.toml mount_policy_transaction::tests::enforcing_restore_uses_the_production_callback_path_and_rechecks -- --exact
Gate contract: Supervised mount-policy recovery across every modeled cut.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Parent dies at any protected mutation cut`.
Preconditions: The exact host model injects failure after every journal, write, rename, fsync, mount and Enforcing operation for shared-root and split topologies.
Observable result: Recovery restores exact pristine bytes, reverse-order read-only boundaries with preserved flags and a repeated recovery is a no-op.
Evidence boundary: Host state-machine and syscall-seam evidence; Android storage durability, init process ownership, loaded policy, Enforcing and reboot behavior are not exercised.

# Gate: cargo test --manifest-path shared/Cargo.toml mount_policy_transaction::tests::forked_watchdog_survives_parent_sigkill_and_recovers -- --exact
Gate contract: Watchdog lifetime is independent of the mutating parent.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Parent dies at any protected mutation cut`.
Preconditions: A host subprocess forks the production lifetime protocol, kills the mutating parent and observes the child-owned completion record.
Observable result: The child survives parent SIGKILL and completes its recovery record before exiting.
Evidence boundary: Host process and pipe semantics; Android mount and SELinux syscalls use the separate fault model.

# Gate: cargo test --manifest-path install/Cargo.toml policy::tests::signed_frozen_and_live_executable_identity_are_bound_to_one_open_descriptor -- --exact
Gate contract: Signed policy transformer authority is the retained live executable descriptor.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Parent dies at any protected mutation cut`.
Preconditions: Frozen mode-0600 and live mode-0700 files contain the same manifest-bound bytes; the live pathname is then replaced after descriptor verification.
Observable result: The executable name is only `/proc/self/fd/<n>`, the original descriptor remains bound, and named identity substitution is rejected before candidate use.
Evidence boundary: Host descriptor, byte and metadata binding; Android execution and policy mutation require target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml policy::tests::live_selinux_program_rejects_mode_link_and_signed_identity_substitution -- --exact
Gate contract: Live policy transformer admission fails closed.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Parent dies at any protected mutation cut`.
Preconditions: The live program is independently replaced by mode-0600, symlink and wrong-byte variants while frozen signed authority remains exact.
Observable result: Every hostile live identity is rejected and no staging chmod or pathname fallback is available.
Evidence boundary: Host no-follow/opened-file checks; Android SELinux domain execution is separate target evidence.

# Gate: cargo test -p voboost-contract apk::tests::rejects_malformed_authority_inputs -- --exact
Gate contract: APK signer identity verification precedes privileged mutation.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Installer APK signer authority is substituted`.
Preconditions: The exact host test parses bounded APK Signing Block v2/v3 structures and substitutes signer identity.
Observable result: Only one correlated signer certificate is accepted and malformed or substituted inputs are rejected.
Evidence boundary: Host APK parser and cryptographic identity model; Android Package Manager, protected mutation and device storage are not exercised.

# Gate: cargo test -p voboost-contract apk::tests::whole_apk_v2_signer_matches_certificate_and_unknown_pairs_are_ignored -- --exact
Gate contract: Standards-framed v2 APK signer extraction.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Platform-valid v2 signer framing is presented`.
Preconditions: The deterministic whole-APK fixture contains the outer signer sequence, one signer, the exact v2 empty compatibility extension and an unrelated signing-block pair.
Observable result: The production parser returns the fixture certificate while retaining strict bounds and ignoring only the unrelated pair.
Evidence boundary: Host byte-layout and certificate-extraction evidence; Android Package Manager acceptance remains target evidence.

# Gate: cargo test -p voboost-contract apk::tests::one_signer_and_scheme_lengths_are_strict -- --exact
Gate contract: APK signer framing and cardinality fail closed.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Platform-valid v2 signer framing is presented`.
Preconditions: The hostile fixtures corrupt pair lengths, remove all supported schemes, duplicate a supported scheme and add a second signer.
Observable result: Every malformed, unsupported-only, duplicate-scheme and multi-signer input is rejected.
Evidence boundary: Host parser rejection evidence; Android Package Manager and filesystem TOCTOU are separate gates.

# Gate: cargo test -p voboost-contract apk::tests::v2_accepts_documented_and_apksig_empty_forms_but_rejects_other_trailing_data -- --exact
Gate contract: The v2 compatibility extension is exact rather than a trailing-data bypass.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Platform-valid v2 signer framing is presented`.
Preconditions: The production parser receives the documented three-field v2 signed data, the current `apksig` form with one empty compatibility element and a hostile nonempty extension.
Observable result: Both platform-valid forms bind the same certificate and every other trailing value is rejected.
Evidence boundary: Host signed-data parser evidence; acceptance of a release APK is additionally checked by the exact-artifact closure gate and on target.

# Gate: cargo test --manifest-path install/Cargo.toml tests::pre_freeze_failure_is_observable_without_fake_durable_transaction_authority -- --exact
Gate contract: Pre-lease install failures remain observable without fabricated transaction authority.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Authentication fails before a durable install authority exists`.
Preconditions: The production failure dispatcher receives one failure without a transaction identity and one after durable identity assignment.
Observable result: The first emits bounded canonical pre-transaction output without calling the durable publisher; the second uses only the correlated publisher.
Evidence boundary: Host dispatch and serialization evidence; Android caller capture and persistent filesystem behavior require target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml tests::recovery_root_is_created_privately_and_hostile_existing_identity_is_never_chmod_adopted -- --exact
Gate contract: Installer recovery-root creation is private and fail-closed.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Authentication fails before a durable install authority exists`.
Preconditions: The production descriptor-relative creator receives an absent recovery root, a mode-0777 root and a symlink to an outside directory.
Observable result: Absence produces exact mode-0700 recovery and transaction directories; hostile existing identities are unchanged and no transaction is created through them.
Evidence boundary: Host mkdirat/openat identity behavior; Android SELinux labeling and persistence require target evidence.

### Requirement: AVD validation uses the production SELinux path

AVD validation SHALL compile the ordinary privileged programs and production init definition with the same SELinux policy transformation, labeling, publication and remount paths as the product build. The native exporter SHALL reject retired emulator markers and SHALL not accept a runtime or build-time policy-skip selection.

#### Scenario: Production privileged closure is built for an AVD

- **WHEN** the AVD builder compiles and exports the native closure
- **THEN** the ordinary production path is selected and no retired emulator marker is present

# Gate: node tools/test-prepare-beta1-unsigned.ts
Gate contract: The native exporter accepts the production input set and rejects a retired emulator marker.
Maps: Requirement `AVD validation uses the production SELinux path`; Scenario `Production privileged closure is built for an AVD`.
Preconditions: Exact native build outputs and the NDK readelf tool are available.
Observable result: The production export has ten canonical files; injected retired marker bytes are rejected.
Evidence boundary: Host artifact selection and ELF validation; SELinux enforcement requires the AVD runtime gate.

# Gate: cargo test --manifest-path contract/Cargo.toml agent_catalog::tests::producer_field_order_ascii_escaping_and_terminal_lf_are_exact -- --exact
Gate contract: Shared typed producer catalog framing.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `The signed producer catalog uses canonical schema order`.
Preconditions: Deterministic typed fixtures contain producer root/nested field order, Cyrillic text and terminal LF.
Observable result: Exact compact ASCII-escaped bytes round-trip without representation drift.
Evidence boundary: Host shared contract parser/serializer; detached signature and exact external producer artifact are covered by the release-agent-trust gate.

# Gate: cargo test --manifest-path contract/Cargo.toml agent_catalog::tests::reordered_unknown_duplicate_and_noncanonical_catalogs_fail_closed -- --exact
Gate contract: Shared catalog rejects every noncanonical structural mutation.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `The signed producer catalog uses canonical schema order`.
Preconditions: The canonical catalog receives reordered, duplicate, unknown, whitespace and missing-terminal-LF mutations.
Observable result: Every noncanonical mutation is rejected before it can become install authority.
Evidence boundary: Host strict parser evidence; external producer signature binding is a separate release-agent-trust gate.

# Gate: cargo test --manifest-path install/Cargo.toml tests::installer_uses_shared_producer_catalog_order_and_ascii_escaping -- --exact
Gate contract: Installer consumes the shared catalog contract before product inventory comparison.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `The signed producer catalog uses canonical schema order`.
Preconditions: The deterministic catalog matches the signed product core/module rows and is then root-reordered without changing its JSON values.
Observable result: Exact producer order is accepted and the value-equivalent reordered document is rejected.
Evidence boundary: Host installer contract composition; Android staging descriptors, ownership and target mutation remain separate evidence.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::reborn_authority_requires_raw_restore_and_active_product_binding -- --exact
Gate contract: Restore consumes only active product authority and raw restore signatures.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Signed product target or one restorable member is substituted`.
Preconditions: The deterministic host fixture signs one shared `RestoreDocument` as raw bytes and one active `voboost.json` with distinct embedded fixture roots, then substitutes the signature and product identity.
Observable result: Exact paired authority passes; a transcript-style signature, corrupted raw signature and mismatched active manifest all fail closed.
Evidence boundary: Host typed parsing, digest binding and Ed25519 evidence; Android installed-path identity and durable operation admission remain unverified.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::committed_inventory_replay_retires_only_exact_duplicate_temporaries -- --exact
Gate contract: Restore commit replay retires exact post-rename residue.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Restore stops at any durable policy or inventory cut`.
Preconditions: The production replay helper receives an absent, exact-target or foreign transaction-local temporary after the stable member already equals its target.
Observable result: Absence is accepted, exact target residue is removed and parent-fsynced exactly once, and foreign bytes fail before either action.
Evidence boundary: Host replay ordering and identity predicate; the reproduced Android failure and successful AVD retry are separate integration evidence.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::every_reborn_restorable_row_is_flat_and_exactly_verified -- --exact
Gate contract: The Reborn restore target is the complete flat manifest-derived closure.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Signed product target or one restorable member is substituted`.
Preconditions: The product fixture supplies exact bytes for every non-restore-pair artifact row and independently corrupts each row.
Observable result: Every target name is one basename, the complete exact closure passes and corruption of each APK, executable, init, ABI library or generation member fails.
Evidence boundary: Host manifest-to-flat-target and byte-identity evidence; PackageManager, immutable generation directories and Android publication require target evidence.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::crash_cut_sidecars_are_transaction_namespaced_without_collision -- --exact
Gate contract: Restore sidecar namespaces do not collide across transactions.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Restore stops at any durable policy or inventory cut`.
Preconditions: The exact Rust test derives all recovery and trust paths for two distinct canonical transaction identifiers.
Observable result: Every WAL, commit member, snapshot and trust input belongs only to its transaction namespace and the two namespaces do not collide.
Evidence boundary: Host path derivation only; Android filesystem durability remains unverified.

# Gate: cargo test --manifest-path shared/Cargo.toml protected_system_transaction::tests::member_reader_rejects_non_enoent_and_foreign_identity -- --exact
Gate contract: Fixed init target and temporary observation distinguishes exact absence from every unsafe identity or read failure.
Maps: Requirement `Restore is one authenticated two-reboot transaction`; Scenario `Init restore observes a hostile or unstable member`.
Preconditions: The host filesystem supplies missing, symlinked, hardlinked, wrong-mode, oversized, directory and wrong-context members; the error seam supplies non-`ENOENT` I/O results and the crash model covers every accepted target/temporary pair.
Observable result: Only exact `ENOENT` becomes absent; every hostile identity and simulated I/O or replacement result fails before create, exchange, unlink or replacement authority.
Evidence boundary: Host filesystem and syscall/error model only; Android SELinux xattr enforcement, protected mount durability and power loss remain unverified.

### Requirement: Beta1 has no implicit compatibility promise for legacy installed state

No product beta1 release has been published, so the installer SHALL NOT promise in-place compatibility with a development installation whose authority is `install.json`, `voboost-inject.json`, `update-ready.json`, `update-ack.json`, or a legacy `update-journal.json`. A detected active legacy operation SHALL remain observable to its existing recovery consumer and SHALL block beta1 installation or product-update admission without deleting, reinterpreting, or adopting its members.

Before beta1 installation, legacy installed state SHALL either be completed or rolled back by its existing signed recovery path and then removed by the clean uninstall contract, or be converted by a separately specified, explicitly invoked and signed migration transaction. Mere presence of flat-looking legacy bytes, a legacy terminal marker, or a matching version string SHALL NOT authorize conversion. The beta1 fresh installer SHALL admit only its exact absence/fresh-state contract and SHALL fail before mutation on every residual legacy root, operation, manifest, staging, recovery, package, init or policy collision.

This requirement is a pre-release operational boundary, not a compatibility guarantee and not permission to delete legacy source. Legacy producer and consumer removal requires a later coordinated change after all external producers are migrated and every retained legacy recovery phase has an explicit completion, rollback, uninstall or signed-conversion disposition.

#### Scenario: Active legacy operation exists before beta1 installation

- **WHEN** the installer observes a canonical nonterminal legacy operation or its recovery members
- **THEN** beta1 installation remains blocked while the existing legacy consumer alone owns completion or rollback

#### Scenario: Legacy development installation is retired before beta1

- **WHEN** no separately signed converter has been specified
- **THEN** the supported path is existing recovery to a terminal state followed by clean uninstall and only then a fresh beta1 installation

# Gate: cargo test --manifest-path install/Cargo.toml fresh::tests::every_fresh_collision_fails_before_mutation -- --exact
Gate contract: Pre-beta1 legacy state is never implicitly adopted.
Maps: Requirement `Beta1 has no implicit compatibility promise for legacy installed state`; Scenarios `Active legacy operation exists before beta1 installation`, `Legacy development installation is retired before beta1`.
Preconditions: The fresh-install host driver independently presents root, marker, operation, recovery, manifest, package, init and policy collision classes.
Observable result: Every collision fails before product mutation; none is interpreted as an in-place beta1 migration.
Evidence boundary: Host collision and mutation-order evidence; clean uninstall or a future signed converter must be validated by their own transaction gates.

### Requirement: Package installation uses a verified stream

The installer SHALL pass the verified staged APK as stdin to the fixed PackageManager install command with its signed size. It SHALL retain no-follow file identity, verify the size and digest before execution, and SHALL NOT make the private recovery tree readable by system_server.

#### Scenario: The private staged APK is not readable by system_server

- **WHEN** APK installation runs from private frozen recovery storage
- **THEN** PackageManager receives the APK through stdin and no source path is passed for system_server to reopen

# Gate: cargo test --manifest-path install/Cargo.toml runtime::apk_stream_tests::verified_stream_rewinds_and_rejects_links_size_and_digest_changes -- --exact

Gate contract: Verified private APK stream.
Maps: Requirement `Package installation uses a verified stream` (host stream validation subset).
Preconditions: The production stream opener receives an isolated APK file, signed size and digest, and hostile symlink/size/digest alternatives.
Observable result: Accepted bytes are rewound for stdin; each hostile input is rejected before handing off the stream.
Evidence boundary: Host stream identity and validation only; the actual PackageManager command and system_server access are not exercised.

# Unverified: Target PackageManager stream handoff

### Requirement: Restore commit over installed state is idempotent and verifies existing baselines

The restore program's runtime-verify commit SHALL be idempotent for this transaction's own already-committed members: when a crash occurs after the inventory member rename but before the phase advances, the resumed commit replays the durable commit journal of this exact transaction, retires exact-duplicate temporaries, and accepts the committed target documents instead of re-checking the install inventory this transaction already replaced. A commit journal of a foreign transaction SHALL be rejected before any member is touched.

An existing digest-path baseline backup SHALL be trusted only after proving its exact pristine bytes and a trusted regular-file identity: residue or corruption from an interrupted earlier attempt SHALL fail closed instead of silently tying the uninstall inventory to a bad baseline.

#### Scenario: Commit resumes after the inventory member cut

- **WHEN** the durable commit journal of this transaction exists and the live install inventory is the committed target
- **THEN** the resumed commit replays the journal, retires exact duplicate temporaries and completes without rewinding any member

#### Scenario: Existing baseline residue at the digest path

- **WHEN** the digest-path backup target already exists with non-pristine bytes or a foreign identity
- **THEN** the commit fails closed before inventory mutation

# Gate: cargo test --manifest-path restore/Cargo.toml tests::committed_inventory_replay_rejects_a_foreign_transaction -- --exact

Gate contract: Restore commit replay rejects foreign transactions.
Maps: Requirement `Restore commit over installed state is idempotent and verifies existing baselines`; Scenario `Commit resumes after the inventory member cut`.
Preconditions: A durable commit journal naming another transaction and a corrupt journal are compiled.
Observable result: Both are rejected before any member is touched.
Evidence boundary: Host decision-path evidence only; the full filesystem commit replay requires the Linux root harness.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::existing_digest_path_baseline_backup_is_verified_by_exact_bytes -- --exact

Gate contract: Existing baseline backup verification.
Maps: Requirement `Restore commit over installed state is idempotent and verifies existing baselines`; Scenario `Existing baseline residue at the digest path`.
Preconditions: Absent, exact and corrupted digest-path backup targets with trusted and foreign identities are compiled.
Observable result: Only exact pristine bytes with a trusted 0600 identity are adopted; residue fails closed.
Evidence boundary: Host filesystem evidence with the trusted-owner host policy; Android root-owned publication is not exercised.


### Requirement: Emulator first boot acceptance has one immutable native expiry

The native emulator-only prearmed install acceptance actor SHALL publish one positive guest-monotonic absolute expiry 900000 milliseconds after initial receipt creation. This finite maximum covers 600 seconds of observer readiness, 180 seconds of UI capture and 120 seconds of discovery and correlated decision overhead; it SHALL NOT introduce a wait or delay successful acceptance. Restart and status SHALL retain the original canonical expiry without renewal. Every decision SHALL be correlated to the exact transaction, manifest, attempt token, boot and reboot count, and SHALL be rejected at or beyond the original guest-monotonic expiry. A rejected decision SHALL remain terminal across restart; a different boot SHALL NOT reopen the receipt. This lifetime SHALL NOT change the distinct cache-recovery acceptance lifetime.

#### Scenario: Restart keeps the original deadline and expired acceptance fails

- **WHEN** the same armed receipt is reopened later and an exact correlated accept arrives at its original expiry
- **THEN** the expiry remains unchanged, expired acceptance fails, foreign identities fail, and only an unexpired correlated decision can become accepted

#### Scenario: Rejection survives restart without reopening acceptance

- **WHEN** a rejected receipt is reopened on the same boot or requested by a different boot
- **THEN** its rejection remains terminal and neither a subsequent accept nor a different boot creates another acceptance lifetime

# Gate: cargo test --manifest-path install/Cargo.toml acceptance::tests::restart_preserves_deadline_and_acceptance_is_correlated_terminal -- --exact

Gate contract: Immutable first-boot acceptance deadline and exact correlation.
Maps: Requirement `Emulator first boot acceptance has one immutable native expiry`; Scenario `Restart keeps the original deadline and expired acceptance fails`.
Preconditions: Production initial receipt and transition functions execute against isolated private host storage with initial monotonic time100 and later reopen time10000.
Observable result: Both receipts retain expiry900100; acceptance at900100 and foreign transaction, manifest, token, boot or reboot count fail; unexpired exact acceptance becomes terminal.
Evidence boundary: Host native receipt creation and transition only; Android QEMU platform guards, socket lifetime and packaged observer timing remain unverified.

# Gate: cargo test --manifest-path install/Cargo.toml acceptance::tests::rejection_and_restart_never_renew_or_accept -- --exact

Gate contract: Rejected acceptance cannot be reopened or renewed.
Maps: Requirement `Emulator first boot acceptance has one immutable native expiry`; Scenario `Rejection survives restart without reopening acceptance`.
Preconditions: Production receipt is rejected, durably written and reopened using isolated host storage.
Observable result: Reopened state remains rejected, a subsequent accept fails and changed boot identity cannot reopen the receipt.
Evidence boundary: Host native state transition and persistence only; real Android socket, reboot and observer consumption remain unverified.


# Unverified: Packaged immutable first-boot acceptance expiry

### Requirement: Installer correlates shared modules by logical owner

Fresh installation SHALL accept schema-1 target rows sharing one exact-case module filename within one logical agent only when size, SHA-256 and entry class agree. Duplicate processes, cross-agent aliases, case-folded names, core or reserved filename collisions and duplicate product module artifact rows SHALL be rejected. Product correlation SHALL compare the exact unique module filename, size and SHA-256 set. Legacy distinct-file target rows SHALL remain accepted. This admission contract does not establish an OTA transition from a native verifier that rejects shared module filenames.

#### Scenario: A logical agent shares one installed module

- **WHEN** a canonical catalog repeats one exact module identity across distinct processes of the same agent
- **THEN** the installer accepts one matching product artifact row
- **AND** it continues to accept older distinct-file targets

#### Scenario: Shared install closure is ambiguous

- **WHEN** a target alias conflicts, belongs to another agent, repeats a process, uses a case-folded or reserved filename, or product module rows are duplicated or missing
- **THEN** installer inventory verification rejects the closure

# Gate: cargo test --manifest-path install/Cargo.toml tests::installer_shared_module_inventory_accepts_exact_aliases_and_legacy_files -- --exact
Gate contract: Fresh installer shared and legacy module admission.
Maps: Requirement `Installer correlates shared modules by logical owner`; Scenario `A logical agent shares one installed module`.
Preconditions: A canonical two-process catalog shares one module and then uses two legacy module filenames with matching product rows.
Observable result: Both exact unique inventories pass.
Evidence boundary: Host installer inventory verification; signatures, Android installation and older-native OTA transition are separate evidence.

# Gate: cargo test --manifest-path install/Cargo.toml tests::installer_shared_module_inventory_rejects_conflicts_and_duplicate_product_rows -- --exact
Gate contract: Ambiguous shared install inventories fail closed.
Maps: Requirement `Installer correlates shared modules by logical owner`; Scenario `Shared install closure is ambiguous`.
Preconditions: Alias size, SHA-256, entry class, filename case, process or logical owner is changed, reserved filenames are supplied, or product rows are duplicated or missing.
Observable result: Every ambiguous closure is rejected.
Evidence boundary: Host installer inventory verification only.

## Unverified

### Unverified: Install inventory publication crash recovery

Maps: Requirement `Install commits one shared uninstall authority`; Scenario `Inventory publication is interrupted`.
Unavailable observation: production inventory publication interrupted and retried at every document write, rename and fsync cut.
Reason: the available focused gate validates the strict parser but does not inject faults through production publication.
Required environment or artifact: a production-path fault-injection harness covering each inventory commit cut and retry.

### Unverified: Installer early partial-recovery publication

Maps: Requirement `One transaction has one temporary authority`; Scenario `Execution is interrupted`.
Unavailable observation: the sibling installer publishing and recovering the exact correlated transaction before its first protected mutation.
Reason: this repository's host model does not execute the packaged installer.
Required environment or artifact: a cross-repository packaged-installer fault-injection test over every durable cut.

### Unverified: Transaction cleanup host proof

Maps: Requirement `Transaction directories are transient`; Scenario `Transaction completes`.
Unavailable observation: cleanup and absence of both correlated directories at every completion cut.
Reason: no focused executable test currently maps this complete contract.
Required environment or artifact: a named fault-injection test covering both directories and steady state.

### Unverified: Update transaction host proof

Maps: Requirement `Update publishes the daemon last`; Scenario `Publication stops before daemon replacement`.
Unavailable observation: the complete one-transaction update publication order with daemon last.
Reason: no focused executable test currently maps this complete contract.
Required environment or artifact: a named update fault-injection test over every publication cut.

### Unverified: Target PackageManager stream handoff

Maps: Requirement `Package installation uses a verified stream`; Scenario `The private staged APK is not readable by system_server`.
Unavailable observation: Actual PackageManager installation consumes only the validated stdin stream while system_server cannot reopen the private source path.
Reason: The host stream test executes /bin/cat and cannot execute Android PackageManager or observe its SELinux access.
Required environment or artifact: Supported Android target, exact installer binary, private APK fixture, PackageManager command/UID trace and unchanged private recovery permissions.

### Unverified: Packaged Android install acceptance lifecycle

Maps: Requirements `Emulator install acceptance separates staging admission from postboot decisions`, `The intermediate install boot reaches readiness before reboot2`; Scenarios `Armed installation crosses the first reboot`, `Staging admission receives foreign platform authority`, `Intermediate acceptance remains Permissive`, `A live acceptance request loses its platform or correlation fence`, `Intermediate boot readiness succeeds or expires`, `Intermediate boot changes or uninstall supersedes installation`.
Unavailable observation: Actual root/QEMU/SELinux admission, boot0 permissive preparation followed by Enforcing boot1, native wait/server/daemon relay STATUS/ACCEPT/REJECT fences and independent generation acknowledgement in the packaged signed installation, including ordinary installation without ARM.
Reason: Host scripted platform actions do not execute Android init, kernel properties, SELinux or the packaged relay; cycle107 stopped before reboot1 and fresh cycle108 has not run.
Required environment or artifact: Fresh cycle108 signed kit and Android QEMU evidence correlating exact artifact identities, boot IDs, WAL, root credentials, kernel Enforcing state, boot completion, generation acknowledgement and observer decision before reboot2; negative platform and fence cases need their own runtime evidence.


### Unverified: Packaged immutable first-boot acceptance expiry

Maps: Requirement `Emulator first boot acceptance has one immutable native expiry`; Scenarios `Restart keeps the original deadline and expired acceptance fails` and `Rejection survives restart without reopening acceptance`.
Unavailable observation: Packaged Android QEMU native receipt keeps the original absolute expiry across restart and consumes complete independently verified first-boot proof before expiry.
Reason: Host functions do not establish real scheduling, platform admission or socket consumption.
Required environment or artifact: A fresh immutable emulator kit with native and observer monotonic evidence, exact original and consumed receipt identities, complete prepared verification and fresh UI artifacts.
