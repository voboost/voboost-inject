# Global operation coordination

## Purpose

Define the single recovery-first lock and combined operation document shared by
install, update, restore, and uninstall.

## Requirements

### Requirement: Every root mutation has one correlated owner

Before changing live files, policy, generations, packages, mounts, init state, or persistent pointers, every privileged mutator SHALL hold an exclusive nonblocking `flock` on the fixed root-owned mode-0600 single-link `/data/voboost/operation.lock` and revalidate the canonical schema-1 root-owned mode-0600 single-link `/data/voboost/operation.json`. The root SHALL be a root-owned mode-0755 directory opened with `O_DIRECTORY|O_NOFOLLOW`; private descendants SHALL remain mode `0700`, and SELinux SHALL restrict the application's traversal to its explicit interfaces. The lock, document and every component of the journal path SHALL be opened descriptor-relatively with `O_NOFOLLOW`. A wrong uid, gid, mode, type, link count, symlink, hardlink or identity change before or after read and lock acquisition SHALL fail closed. The document SHALL contain exactly `schemaVersion`, `operation`, `transactionId`, `journal`, `phase`, `outcome`, `rebootCount`, `bootId`, `statusSequence`, `journalSha256`, `error`, and `installedApk`; its transaction and journal digest SHALL be canonical lowercase SHA-256, `bootId` SHALL be the exact lowercase UUID of the boot that published this status, and its journal SHALL be exactly `recovery/<transactionId>/<operation>-journal.json`, except that a descriptor-admitted product update SHALL use its sole pre-existing `recovery/<transactionId>/product-proposal.json` WAL instead of creating a second update journal. The operation-specific WAL SHALL be durable before document publication. Before continuation, the consumer SHALL read that bounded relative WAL through the trusted root and require its exact SHA-256 to equal `journalSha256`; the WAL phase decides continuation. A crash between the atomic WAL replacement and the following projection replacement MAY leave `operation.json` one durable step behind. Recovery MAY read that canonical document only to locate the same operation, transaction and fixed journal; under `operation.lock` it SHALL require the current trusted WAL, publish a projection whose digest matches that WAL, and refuse an operation or transaction change, a counter decrease, or terminal continuation before any further mutation. A `complete` document SHALL never authorize continuation and MAY retain the final journal digest after the journal and both transaction directories have been durably removed. Publication and transition SHALL use descriptor-relative no-follow access, atomic replacement, file fsync, and parent fsync. A non-complete document with the same operation, transaction and journal resumes recovery; a different active or failed authority returns `busy`. A verified `complete` document is atomically replaced only while admitting the next operation under the same lock. The transaction layout remains `/data/voboost/install/<tx>` and `/data/voboost/recovery/<tx>`.

#### Scenario: Product proposal sees foreign operation state

- **WHEN** a valid `install`, `restore` or `uninstall` descriptor owns the transaction while a product descriptor proposal arrives
- **THEN** product admission defers without interpreting, rolling back or deleting the foreign transaction

#### Scenario: Another operation owns the fixed lock

- **WHEN** an install lease holds `operation.lock` and a different update descriptor attempts acquisition
- **THEN** the update receives `busy`, the active install pointer remains unchanged, terminal install completion retains `operation.json`, and the next admitted operation atomically replaces that complete document while retaining `operation.lock`

#### Scenario: Terminal cleanup has not removed its transaction residue

- **WHEN** a `complete` document remains beside its transaction directory or install terminal intent
- **THEN** generation mutation and admission of a different operation both receive `busy`; only recovery of the same terminal authority may remove the exact residue and retain the completed document

#### Scenario: Operation authority has a hostile filesystem identity

- **WHEN** the root, lock or descriptor has a wrong owner, group, mode, type or link count, or is replaced while being inspected
- **THEN** acquisition and revalidation fail before the caller may mutate live state

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::uninstall_fence_requires_product_candidate_authority_to_be_idle -- --exact
Gate contract: Shared-root product and uninstall ownership.
Maps: Requirement `Every root mutation has one correlated owner`; Scenario `Product proposal sees foreign operation state`.
Preconditions: The host fixture compares an idle transaction root with one owned by a durable product proposal.
Observable result: Uninstall may proceed only when no product WAL owns shared transaction state.
Evidence boundary: Host filesystem and parser evidence only; Android ownership, SELinux and reboot behavior are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::lease_is_recovery_first_and_busy_for_another_operation -- --exact
Gate contract: Fixed global operation lock and recovery-first pointer.
Maps: Requirement `Every root mutation has one correlated owner`; Scenario `Another operation owns the fixed lock`.
Preconditions: A host temporary root contains no operation pointer and the test acquires one canonical install descriptor.
Observable result: A conflicting update lease is rejected, ownership revalidation succeeds for install, terminal completion retains the pointer, and a later update lease atomically replaces only that complete pointer while the fixed lock remains.
Evidence boundary: Host filesystem and kernel `flock` evidence only; Android root ownership, SELinux labels, process domains, reboots, and device recovery are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::descriptor_admitted_product_update_reuses_its_single_proposal_wal -- --exact
Gate contract: Product update reuse of the descriptor-admission WAL.
Maps: Requirement `Every root mutation has one correlated owner`.
Preconditions: The exact host parser receives update, install and hostile journal-path variants for one canonical transaction ID.
Observable result: Only an `update` operation accepts the exact `product-proposal.json` exception; the normal operation journal and all unrelated names retain their strict validation.
Evidence boundary: Host operation-document parsing only; descriptor admission, Android ownership and live recovery are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::stale_projection_reconciles_only_to_the_current_monotonic_wal -- --exact
Gate contract: Crash-gap reconciliation between an operation WAL and its observable projection.
Maps: Requirement `Every root mutation has one correlated owner`.
Preconditions: A host transaction first publishes one correlated restore WAL and projection, then atomically advances only the WAL to model a process crash before projection replacement.
Observable result: Reacquisition accepts only the same operation, transaction and fixed journal, publishes the current WAL digest without moving the sequence backwards, and a stale caller cannot rewind the retained projection.
Evidence boundary: Host filesystem, hashing and kernel `flock` evidence only; Android process death, fsync persistence, SELinux labels and reboot continuation are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::terminal_residue_blocks_generation_and_the_next_operation -- --exact
Gate contract: Terminal cleanup remains exclusive until transaction residue is absent.
Maps: Requirement `Every root mutation has one correlated owner`; Scenario `Terminal cleanup has not removed its transaction residue`.
Preconditions: A host fixture publishes a complete restore document and leaves its exact private recovery transaction directory.
Observable result: Both generation acquisition and a different global operation are rejected until that directory is removed; the retained complete document is not deleted to make progress.
Evidence boundary: Host filesystem and kernel `flock` evidence only; Android process restart, SELinux ownership and live cleanup are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::trusted_identity_rejects_wrong_uid_gid_mode_and_link_count -- --exact
Gate contract: Hostile operation authority identity rejection.
Maps: Requirement `Every root mutation has one correlated owner`; Scenario `Operation authority has a hostile filesystem identity`.
Preconditions: Host fixtures provide wrong file type, link count, owner, group, and mode combinations to the production identity predicate.
Observable result: Every hostile identity is rejected while the exact single-link private owner identity is accepted.
Evidence boundary: Host metadata predicate evidence only; Android uid 0, SELinux labels, and live-state mutation ordering are not exercised.

### Requirement: The combined operation document is canonical schema one

Each active or last completed global operation SHALL publish its authority and observable state in the same canonical schema-1 `/data/voboost/operation.json`; no separate status document or compatibility alias exists. Outcomes are exactly `running`, `reboot-required`, `complete`, or `failed`; a busy refusal occurs before transaction admission and is not durable operation state. `statusSequence` SHALL be positive and persisted monotonically with the WAL, and `rebootCount` SHALL never move backwards. Every completed reboot SHALL have a distinct journaled boot epoch: product forward activation reports count one and its post-forward boot, while product rollback reports count two and its post-rollback boot. Repeated observation at one sequence is valid only for byte-identical canonical state. For one-based phase `N` of every operation, running, reboot-required, and terminal failed or complete states SHALL reserve `3N-2`, `3N-1`, and `3N` respectively. Install completion SHALL bind one nested `installedApk` object with exactly `packageName`, positive `versionCode`, `certificateSha256`, a bounded canonical dynamic `/data/app/.../base.apk` path, positive `size`, and `sha256`. A `complete` document SHALL remain observable after mandatory cleanup, SHALL tolerate only the correlated journal being absent, and SHALL be replaced only by admission of the next operation. A `failed` document SHALL retain its journal and same-transaction retry authority. The combined document admits continuation only through the correlated non-complete operation and WAL; the verified WAL phase decides continuation.

#### Scenario: An observer receives a substituted or stale status

- **WHEN** the status omits its sequence or WAL digest, contains an unknown field, uses a noncanonical digest, changes operation or transaction, or moves either counter backwards
- **THEN** the observer rejects it without continuing or mutating the device operation

#### Scenario: An install reboot request fails after publication

- **WHEN** one phase has already published `reboot-required` and the reboot request returns an error
- **THEN** the failed observation advances to the terminal slot for that phase instead of changing bytes at the reboot sequence

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::schema_one_is_canonical_strict -- --exact
Gate contract: Canonical operation-status schema and WAL correlation fields.
Maps: Requirement `The combined operation document is canonical schema one`; Scenario `An observer receives a substituted or stale status`.
Preconditions: The focused host test supplies the canonical schema-1 fixture and variants with a missing sequence or noncanonical journal digest.
Observable result: The production wire parser accepts only the canonical document containing both correlation fields.
Evidence boundary: Host parser evidence only; Android file ownership, atomic publication, init continuation, reboot observation, and WAL durability are not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::completed_operation_remains_readable_after_exact_journal_cleanup -- --exact
Gate contract: Completed operation survives journal removal.
Maps: Requirement `The combined operation document is canonical schema one`; Scenario `An observer receives a substituted or stale status`.
Preconditions: A canonical completed install document retains its final journal digest after the exact transaction journal and directory are removed.
Observable result: `readCurrent` returns the complete document, `readActive` returns no active operation, and no non-complete missing-journal state is admitted.
Evidence boundary: Host descriptor-relative absence handling; Android cleanup ordering and observer startup require target evidence.

# Gate: cargo test --manifest-path install/Cargo.toml tests::status_sequence_reserves_distinct_running_reboot_and_terminal_slots -- --exact

Gate contract: Install operation sequence slots.
Maps: Requirement `The combined operation document is canonical schema one`; Scenario `An install reboot request fails after publication`.
Preconditions: The exact install phase enum and status outcome strings are compiled.
Observable result: Running, reboot-required and terminal outcomes occupy three distinct monotonic slots at representative first, middle, reboot and terminal phases; an unknown outcome is rejected.
Evidence boundary: Host sequence calculation only; Android status publication and reboot failure are not observed.

# Gate: cargo test --manifest-path restore/Cargo.toml tests::restore_status_reserves_running_reboot_and_terminal_slots -- --exact

Gate contract: Restore operation sequence slots and bounded failure projection.
Maps: Requirement `The combined operation document is canonical schema one`; Scenario `An observer receives a substituted or stale status`.
Preconditions: Representative running, reboot, cleanup and complete restore phases plus one control-character failure are compiled.
Observable result: Every phase reserves the same three sequence slots, failed uses the terminal slot and its published message contains no control character.
Evidence boundary: Host sequence and serialization evidence only; Android failure publication and reboot recovery are not observed.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::product_operation_projection_tracks_forward_and_rollback_boots -- --exact

Gate contract: Update operation sequence slots.
Maps: Requirement `The combined operation document is canonical schema one`; Scenario `An observer receives a substituted or stale status`.
Preconditions: Canonical product forward and rollback journals carry distinct boot epochs and durable phases.
Observable result: Forward activation, rollback and terminal projection use monotonic reboot counts and operation sequence slots.
Evidence boundary: Host sequence and serialization evidence only; Android update publication and reboot are not observed.

### Requirement: Install generation acknowledgement binds the complete identity

The install-only `recovery/<transactionId>/generation-ack.json` SHALL be canonical schema 1 and contain exactly `schemaVersion`, `transactionId`, `apkSha256`, `catalogSha256`, `selectionSha256`, and `generationSha256`. Every identity SHALL be lowercase SHA-256. This acknowledgement is distinct from the app-staging accepted/rejected acknowledgement and SHALL NOT define aliases for that earlier document.

Only a nonterminal `install-agents` operation and its present correlated WAL authorize initial generation staging or acknowledgement. Once the retained operation is `install-complete`, generation coordination SHALL treat it as terminal observation and SHALL NOT reopen the removed journal, recovery directory or frozen closure.

#### Scenario: One install generation identity is absent or renamed

- **WHEN** the acknowledgement omits, renames, duplicates, or adds any identity field
- **THEN** the install verifier rejects it before committing uninstall inventory

# Gate: cargo test --manifest-path contract/Cargo.toml generation::tests::acknowledgement_binds_install_identity_closure -- --exact
Gate contract: Closed install generation acknowledgement identity.
Maps: Requirement `Install generation acknowledgement binds the complete identity`; Scenario `One install generation identity is absent or renamed`.
Preconditions: The focused host test supplies one canonical acknowledgement and a legacy-style renamed APK digest.
Observable result: The production wire parser accepts the exact six-field document and rejects the alias.
Evidence boundary: Host parser evidence only; generation activation, install lifecycle continuation, inventory commit, and Android filesystem publication are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::operation_coordination::tests::completed_install_is_not_generation_activation_authority -- --exact
Gate contract: Completed install leaves generation activation authority.
Maps: Requirement `Install generation acknowledgement binds the complete identity`.
Preconditions: A canonical retained `install-complete` operation remains after its transaction directories are absent.
Observable result: Generation coordination returns no install activation context and never attempts to read the removed WAL or frozen closure.
Evidence boundary: Host terminal classification; Android daemon cold-start after terminal cleanup requires target evidence.

### Requirement: Active operation is never interrupted

An active operation SHALL NOT be interrupted mid-mutation. It SHALL first recover, roll back, or commit. A new operation SHALL receive `busy` and retry after the terminal state. An `uninstall` request SHALL prevent new work but SHALL NOT replace the active WAL. The protocol SHALL NOT define numeric priority, a `Preempted` phase, or a second copy of phases in the descriptor. The operation journal SHALL own its phases.

#### Scenario: Prepared uninstall restarts

- **WHEN** the daemon or uninstaller restarts after durable uninstall preparation
- **THEN** it validates the same uninstall descriptor and recovery journal, resumes without desktop participation, and fences install, update, restore and generation work

# Unverified: Prepared uninstall restart fences all other work
Maps: Requirement `Active operation is never interrupted`; Scenario `Prepared uninstall restarts`.
Unavailable observation: The daemon restarts after uninstall preparation and fences all other operations on the supported Android target.
Reason: Host tests do not execute the target init restart and SELinux enforcement sequence.
Required environment or artifact: A supported-target crash-cut trace covering the uninstall WAL resume and concurrent install/update/restore attempts.

### Requirement: Restore publishes intent before policy mutation

Restore SHALL acquire a `restore` descriptor correlated to the signed restore WAL before restoring an init hook, entering a writable policy window, replacing policy bytes or updating protected inventory. OTA and generation activation SHALL remain fenced until restore reaches durable completion and removes its lease.

#### Scenario: Restore resumes after a reboot

- **WHEN** the signed restore WAL survives either required reboot
- **THEN** the runner reacquires only the correlated restore lease before policy, inventory, or reboot mutation

# Unverified: Restore lease target ordering
Maps: Requirement `Restore publishes intent before policy mutation`; Scenario `Restore resumes after a reboot`.
Unavailable observation: The signed restore runner publishes and revalidates its lease before every policy mutation and both reboot requests on the supported Android target.
Reason: Host tests do not execute the target mount, SELinux policy and reboot sequence.
Required environment or artifact: A supported-target crash-cut trace covering every restore WAL phase, both reboot resumes, and concurrent OTA/generation attempts.

### Requirement: The native operation parser consumes the product-owned golden bytes

The checked-in `test/fixtures/wire` directory SHALL be a byte-identical mirror of the product repository's generated schema-1 corpus, not an independently authored example set. The shared `voboost-contract` parser SHALL consume the exact canonical complete Install document emitted by the product corpus, including product-manifest transaction identity, canonical journal path, status sequence `36`, ordered installed APK identity and one terminal LF. Product release admission SHALL reject any filename, inventory or byte drift between the authority corpus and this mirror.

#### Scenario: The complete Install document crosses the repository boundary

- **WHEN** the product-owned complete Install bytes are passed to the shared native parser
- **THEN** parsing and canonical serialization preserve every byte and the expected operation identity

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::operation_contract_consumes_the_product_wire_golden_bytes -- --exact

Gate contract: Product-owned operation wire bytes.
Maps: Requirement `The native operation parser consumes the product-owned golden bytes`; Scenario `The complete Install document crosses the repository boundary`.
Preconditions: The byte-identical product mirror is present.
Observable result: The production contract parser accepts the exact document, observes Install, the product digest transaction and sequence 36, and serializes identical bytes.
Evidence boundary: Component host interop only; product-to-mirror equality is enforced by the product orchestrator and Android persistence remains unverified.

### Requirement: Terminal WAL→projection cut reconciles through the exact predecessor

Every operation writer SHALL order the terminal WAL write before the terminal projection publish. A crash between the two leaves the shared descriptor exactly one publication behind the durable WAL; recovery SHALL reconcile only when the live descriptor is bit-identical to the publication derivable from the same durable WAL at the immediately preceding phase, and the terminal document binds the live WAL hash. The general monotonic publish guard SHALL remain untouched: the reconcile is not a publish and admits no sequence decrease, no authority change, and no predecessor that still binds the live WAL. Install and restore same-phase retry after a failed reboot publication SHALL NOT re-emit the lower reboot-required slot: the failed terminal document already observes the state, and the retry re-requests the reboot directly, preserving retry authority without moving any counter backwards.

#### Scenario: A terminal cut leaves the projection one publication behind

- **WHEN** the durable WAL names the terminal phase while the descriptor still shows the immediately preceding publication
- **THEN** the exact derived predecessor reconciles to the derived terminal document, and every other combination diverges

#### Scenario: A same-boot retry follows a failed reboot publication

- **WHEN** the live descriptor is the failed publication for the exact install phase and WAL and the driver re-enters the same boot
- **THEN** the retry does not re-emit the lower reboot-required sequence and requests the reboot directly

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::terminal_cut_reconciles_only_the_exact_predecessor_to_the_terminal_document -- --exact

Gate contract: Terminal cut reconcile proves the exact predecessor.
Maps: Requirement `Terminal WAL→projection cut reconciles through the exact predecessor`; Scenario `A terminal cut leaves the projection one publication behind`.
Preconditions: A descriptor-WAL pair at the preceding publication plus the terminal WAL mutation is compiled.
Observable result: The generic acquire rejects the terminal projection; the narrow reconcile replaces exactly the predecessor with the terminal document and hands back a verified lease; replay after the terminal document is live fails.
Evidence boundary: Host descriptor and journal evidence only; Android crash timing across the two durable steps is not exercised.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::terminal_cut_reconcile_rejects_forgeries -- --exact

Gate contract: Terminal cut reconcile rejects forgeries.
Maps: Requirement `Terminal WAL→projection cut reconciles through the exact predecessor`; Scenario `A terminal cut leaves the projection one publication behind`.
Preconditions: Forged predecessor hash, foreign terminal hash and nonterminal successor documents are compiled.
Observable result: Every forgery is rejected and the live projection survives untouched.
Evidence boundary: Host descriptor evidence only.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::generation_only_terminal_cut_between_journal_and_projection_converges -- --exact

Gate contract: Product terminal cut converges through recovery.
Maps: Requirement `Terminal WAL→projection cut reconciles through the exact predecessor`; Scenario `A terminal cut leaves the projection one publication behind`.
Preconditions: The generation-only activation matrix reaches ProductVerified; the injected cut stops between the Complete journal write and the projection publish.
Observable result: Unmodified store recovery converges to the accepted complete candidate with verified closure, uninstall inventory and terminal result.
Evidence boundary: Host filesystem evidence only; Android publication of the shared descriptor is not exercised.

# Gate: cargo test --manifest-path install/Cargo.toml tests::same_boot_retry_after_a_failed_reboot_does_not_rewind_the_sequence -- --exact

Gate contract: Install same-boot retry after failure.
Maps: Requirement `Terminal WAL→projection cut reconciles through the exact predecessor`; Scenario `A same-boot retry follows a failed reboot publication`.
Preconditions: The failed publication is live for the exact install phase and WAL; the driver re-enters the same boot.
Observable result: The retry emits nothing, requests the reboot again, and the live projection remains the terminal failed document at its published sequence.
Evidence boundary: Host driver evidence only; Android init reboot handling is not exercised.

### Requirement: Install publications retain diagnostic history

Every install operation publication SHALL retain its canonical report in ordered bounded root-owned mode-0600 `/data/voboost/logs/install-progress.jsonl`. The history SHALL survive reboot and terminal install cleanup, suppress byte-identical repeats, reject hostile filesystem identities and begin anew for a different install transaction. The exact history file SHALL use the existing operation-file SELinux type, including post-boot relabeling, so install can retain progress under Enforcing. It SHALL NOT authorize continuation or completion. Normal uninstall removes it with the product root.

#### Scenario: Install advances while the desktop is disconnected

- **WHEN** install publishes stages across two boots and reaches complete
- **THEN** a later reader can replay every retained report in publication order

#### Scenario: The progress path is a symlink

- **WHEN** a history path has a hostile identity
- **THEN** publication refuses to overwrite the foreign target

# Unverified: Android install history delivery

### Requirement: Explicit uninstall supersedes in-flight install mutations

Before each install transaction phase, including continuation after a reboot, the worker SHALL check the fixed `/data/voboost/run/desktop-uninstall-request` path. An existing entry SHALL stop the worker with `install superseded by an explicit uninstall request` before that phase mutates live state. The worker SHALL retain its journal, staging and backups for uninstall recovery. The desktop owns the durable file; a Settings request is accepted by the resident daemon without an app-owned file marker.

#### Scenario: A request exists before the first phase

- **WHEN** the install driver observes the durable request before `InstallPrepare`
- **THEN** it returns the explicit superseded error without executing an action or advancing the journal

#### Scenario: No request exists

- **WHEN** the same driver has no durable request
- **THEN** it continues through its ordinary phase actions

#### Scenario: A request arrives between Android phases

- **WHEN** a desktop request arrives during a running install or before its post-reboot continuation
- **THEN** the next phase yields without a competing live mutation and retains recovery state

# Gate: cargo test --manifest-path install/Cargo.toml tests::explicit_uninstall_request_stops_the_driver_before_any_mutation -- --exact

Gate contract: Initial install supersession and ordinary continuation.
Maps: Requirement `Explicit uninstall supersedes in-flight install mutations`; Scenarios `A request exists before the first phase`, `No request exists`.
Preconditions: A host operation lease, InstallPrepare journal and scripted actions are present; the fixture creates and then removes a request entry.
Observable result: The request branch executes no action and preserves the phase; the no-request branch reaches its normal reboot phase.
Evidence boundary: Host driver behavior with an injected request predicate; actual fixed Android path, later phase cuts and reboot continuation are not proven.

# Unverified: Android install supersession

## Unverified

### Unverified: Prepared uninstall restart fences all other work

Maps: Requirement `Active operation is never interrupted`; Scenario `Prepared uninstall restarts`.
Unavailable observation: The daemon restarts after uninstall preparation and fences all other operations on the supported Android target.
Reason: Host tests do not execute the target init restart and SELinux enforcement sequence.
Required environment or artifact: A supported-target crash-cut trace covering the uninstall WAL resume and concurrent install/update/restore attempts.

### Unverified: Restore lease target ordering

Maps: Requirement `Restore publishes intent before policy mutation`; Scenario `Restore resumes after a reboot`.
Unavailable observation: The signed restore runner publishes and revalidates its lease before every policy mutation and both reboot requests on the supported Android target.
Reason: Host tests do not execute the target mount, SELinux policy and reboot sequence.
Required environment or artifact: A supported-target crash-cut trace covering every restore WAL phase, both reboot resumes, and concurrent OTA/generation attempts.



### Unverified: Android install history delivery

Maps: Requirement `Install publications retain diagnostic history`; Scenarios `Install advances while the desktop is disconnected` and `The progress path is a symlink`.
Unavailable observation: Android SELinux labels, writes under init-owned install and complete console replay across two physical boots.
Reason: Host filesystem tests prove retained event order, partial-append repair and hostile path refusal, but do not execute Android init or ADB.
Required environment or artifact: A newly signed device driver and installer package on a supported vehicle.

### Unverified: Android install supersession

Maps: Requirement `Explicit uninstall supersedes in-flight install mutations`; Scenario `A request arrives between Android phases`.
Unavailable observation: The actual fixed request path preempts each Android phase and its post-reboot continuation while preserving recovery state.
Reason: The focused host driver test covers initial-phase admission and ordinary continuation, not Android init, every crash cut or SELinux access.
Required environment or artifact: A signed CLI kit and supported Enforcing Android lifecycle run covering request publication, worker yield, reboot continuation and uninstall recovery.
