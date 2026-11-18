# Uninstall recovery specification

## Purpose

Define crash-safe uninstall recovery through the last executable unlink and
conditional, evidence-bound reboots.

## Requirements

### Requirement: Policy digest selectors remain durable reverse authority

Install SHALL capture the original bytes, absence, UID, GID, mode and SELinux context of the complete fixed init digest selector set before publication. Android 9 SHALL use its single plat-and-mapping selector; Android 11 SHALL use the ordered platform, system_ext and product selectors. All current platform digests SHALL be validated from bounded retained nofollow descriptors before any candidate is published. The vendor publication contract SHALL reject a preferred ODM precompiled policy rather than claiming the patched vendor policy will be selected. Schema-v2 policy metadata and schema-v2 terminal recovery authority SHALL retain the original selectors after the short mount journal and installation staging have been removed. Terminal cleanup SHALL restore and verify policy bytes and all original selectors, including absence, before removing reverse authority.

#### Scenario: Digest authority has an incomplete or substituted platform set

- **WHEN** an Android 11 backup loses a selector, reorders or duplicates paths, changes original bytes without their digest, substitutes an owner or supplies a caller-selected path
- **THEN** parsing rejects the backup and retains reverse authority

#### Scenario: A selector was originally absent

- **WHEN** the installation created a fixed selector that was absent in the captured baseline
- **THEN** recovery retains the original absence as authority and removes only that fixed owned selector before terminal cleanup

# Gate: cargo test --workspace mount_policy_transaction::tests::sidecar_backup_binds_complete_platform_sets_bytes_and_original_absence -- --exact
Gate contract: Complete fixed policy digest backup and original absence.
Maps: Requirement `Policy digest selectors remain durable reverse authority`; Scenarios `Digest authority has an incomplete or substituted platform set` and `A selector was originally absent`.
Preconditions: The canonical captured-selector fixture is parsed and the exact test mutates set completeness, order, path, owner, bytes and original absence.
Observable result: Only the complete Android 9 or Android 11 fixed set with exact bytes and original presence/absence is accepted.
Evidence boundary: Host parser and authority model; Android init selection, live SELinux permissions, filesystem crash recovery and successful target uninstall are not inferred.

### Requirement: Schema-one uninstall phases are exact

The schema-version-1 device WAL SHALL advance only through `uninstall-prepare`, `uninstall-agents-stop`, `uninstall-policy-restore-prepare`, `uninstall-app-remove`, `uninstall-runtime-remove`, `uninstall-terminal-cleanup`, `uninstall-absence-verify`. `uninstall-policy-restore-prepare` SHALL only validate and bind the pristine-policy authority. Publishing the pristine policy SHALL be the first recoverable action inside init-owned `uninstall-terminal-cleanup`, before external absence verification. Device-local `uninstall-complete` and unconditional `uninstall-reboot` phases are forbidden because the root containing that authority is removed.

#### Scenario: Terminal cleanup is armed

- **WHEN** runtime removal has completed
- **THEN** external absence verification follows terminal cleanup and no device-local phase can be skipped

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::every_phase_journal_cut_resumes_idempotently_in_strict_order -- --exact
Gate contract: Schema-one uninstall phase vocabulary and order.
Maps: Requirement `Schema-one uninstall phases are exact`; Scenario `Terminal cleanup is armed`.
Preconditions: The exact Rust test interrupts every durable phase boundary.
Observable result: Retry repeats only the interrupted phase and then visits every exact device-local successor through terminal cleanup.
Evidence boundary: Host WAL order only; Android init, exact-zero teardown and reboot remain separately bounded.

### Requirement: Uninstall progress remains observable until root removal

Every durable uninstall phase SHALL publish the same phase from `recovery/<transactionId>/uninstall-journal.json` into `/data/voboost/operation.json` under the uninstall lease. Running, reboot-required and failed observations for one-based phase `N` SHALL use `3N-2`, `3N-1` and `3N`; a failed observation SHALL contain one bounded control-free error and retain the WAL for explicit Retry. Before exact-zero removes the root, the watchdog SHALL publish `uninstall-absence-verify` with `reboot-required` and the armed reboot count. No device-local complete document exists after root removal.

#### Scenario: Uninstall arms its terminal reboot

- **WHEN** the watchdog has durably bound the reboot predicate and boot ID but has not removed the root
- **THEN** the host can observe the exact uninstall transaction, absence-verify phase and reboot-required sequence before the document disappears during exact-zero cleanup

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::uninstall_status_reserves_running_reboot_and_failed_slots -- --exact

Gate contract: Uninstall operation sequence slots.
Maps: Requirement `Uninstall progress remains observable until root removal`; Scenario `Uninstall arms its terminal reboot`.
Preconditions: Representative prepare, runtime-remove and absence-verify phases are supplied to the production sequence function.
Observable result: Running, reboot-required and failed occupy their exact three slots and device-local complete is rejected.
Evidence boundary: Host sequence calculation only; Android status publication, exact-zero root removal and physical reboot are not observed.

### Requirement: Terminal cleanup stays in the loaded teardown domain

The primary uninstall service SHALL publish and verify the pristine vendor
policy bytes on disk without loading them into the running kernel. It SHALL
keep the currently loaded patched policy and the `voboost_uninstall` domain
until the product has reached exact zero residue. Before removing authority it
SHALL durably bind the current canonical boot ID. Terminal cleanup SHALL reject
a different boot ID because that would no longer prove that the patched policy
and its teardown domain remain loaded.

#### Scenario: The device rebooted before terminal cleanup

- **WHEN** the current boot ID differs from the boot ID bound before cleanup
- **THEN** terminal cleanup is rejected without removing its remaining authority

# Unverified: End-to-end teardown-domain reachability

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_cleanup_requires_the_bound_current_boot_and_zero_preconditions -- --exact

Gate contract: Same-boot terminal cleanup boundary.
Maps: Requirement `Terminal cleanup stays in the loaded teardown domain`; Scenario `The device rebooted before terminal cleanup`.
Preconditions: The exact Rust test varies phase, boot identity and remaining package or SELinux-program state.
Observable result: Cleanup is admitted only in the bound boot, after pristine bytes are published and ordinary product state is absent.
Evidence boundary: Host state model; target init, loaded SELinux policy and reboot are not exercised.

### Requirement: Terminal cleanup runs in a separate init service

The primary service SHALL durably record `UninstallWatchdogArmed`, start the
separate init-owned `/data/voboost/voboost-uninstall --watch-uninstall`
service, authenticate its fixed socket peer with root `SO_PEERCRED`, executable
path and exact argv, and complete READY/COMMIT/ACK. The watchdog SHALL persist
`UninstallWatchdogCommitted` before acknowledging COMMIT. It SHALL run in its
own init service and cgroup, not as a child process of the primary service.

#### Scenario: The primary service exits after COMMIT

- **WHEN** the primary service exits after receiving ACK
- **THEN** the init-owned watchdog continues from its durable committed state

# Unverified: Android 9 init service and cgroup behavior

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::uninstall_watchdog_requires_durable_commit_before_terminal_cleanup -- --exact

Gate contract: Durable terminal-watchdog authority.
Maps: Requirement `Terminal cleanup runs in a separate init service`; Scenario `The primary service exits after COMMIT`.
Preconditions: The exact Rust test evaluates the complete terminal phase order.
Observable result: Cleanup cannot advance from active state directly to committed or successor state.
Evidence boundary: Host state-machine model; Android init service and cgroup behavior are not exercised.

### Requirement: The transaction-bound watchdog socket fits production address limits

The uninstall watchdog socket SHALL use the exact path `/data/voboost/recovery/<64-lowercase-hex-transaction-id>/watchdog.sock`. The transaction ID and private recovery directory SHALL remain unabridged, and bind, connect, ownership validation, cleanup and recovery SHALL consume the same constructed path. The pathname including its terminating NUL SHALL fit the supported Linux/Android and Darwin `sockaddr_un.sun_path` limits.

#### Scenario: The maximum production watchdog pathname is constructed

- **WHEN** the constructor receives the full production recovery root and one canonical 64-character transaction ID
- **THEN** the prior `uninstall-watchdog.sock` path is rejected by the system socket-address API and the exact `watchdog.sock` path is accepted

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::production_watchdog_socket_path_fits_system_address_limits -- --exact

Gate contract: Full production watchdog pathname fits the supported system socket address.
Maps: Requirement `The transaction-bound watchdog socket fits production address limits`; Scenario `The maximum production watchdog pathname is constructed`.
Preconditions: The production constructor receives `/data/voboost/recovery/<64 lowercase hex>` and both old and current basenames are submitted to the host system socket-address API.
Observable result: The old 111-byte pathname is rejected and the current 101-byte pathname is accepted without truncating the transaction ID or changing the recovery directory.
Evidence boundary: Host pathname construction and system address validation only; bind/connect protocol, peer authentication, Android SELinux and init ownership remain separate gates.

### Requirement: Terminal removal is descriptor-relative and no-follow

Before removing ordinary product data, the watchdog SHALL authenticate its
running bytes and retain descriptors for `/data`, `/data/voboost` and the init
directory. It SHALL use bounded descriptor-relative traversal, reject mount
boundaries and special inodes, never traverse a symbolic link, and revalidate
named inodes before unlink. Retrying after any completed unlink SHALL
converge.

#### Scenario: A descendant is replaced by a symbolic link

- **WHEN** terminal cleanup reaches that entry
- **THEN** it removes only the link and leaves the linked target unchanged

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_tree_walk_is_descriptor_relative_nofollow_and_idempotent_after_each_cut -- --exact

Gate contract: Descriptor-relative terminal tree removal.
Maps: Requirement `Terminal removal is descriptor-relative and no-follow`; Scenario `A descendant is replaced by a symbolic link`.
Preconditions: The exact Rust test creates nested entries, an external link, retained authority and every top-level interruption cut.
Observable result: Retried cleanup converges and never changes the external target.
Evidence boundary: Host filesystem fixture; Android mounts and storage power loss are not exercised.

### Requirement: An init successor covers the last unlink window

The permanent init file SHALL predeclare both restartable terminal services
while the patched policy is loaded. Both services SHALL invoke the same signed
`voboost-uninstall` inode with distinct fixed argv and explicit
`voboost_uninstall` service labels; stock shell SHALL NOT be a terminal entry
point. Before deleting recovery state, the watchdog SHALL start
`voboost-uninstall-successor`, authenticate it through root `SO_PEERCRED`,
fixed executable path and exact argv, persist `UninstallSuccessorStarted`, and
send GO. Both processes SHALL retain verified no-follow descriptors before GO.
Either survivor SHALL then recover any remount journal, remount the exact init
filesystem read-write, unlink and fsync the bound init hook, restore the mount
read-only, remove the exact recovery transaction, unlink the verified stable
executable, remove the already-empty product root, prove both root and init hook
absent, and request reboot only from the durable reason, predicate fingerprint and boot ID armed before GO. It SHALL use no wildcard, caller path,
recursive removal or shell cleanup command. An ordinary death of either one
terminal process after GO SHALL leave the other with enough retained authority
to converge after init-hook, recovery-state, executable or root unlink.

#### Scenario: The successor dies after unlinking the executable

- **WHEN** `/data/voboost/voboost-uninstall` is absent but the empty product root remains
- **THEN** init restarts its retained in-memory service definition, removes the empty root and exercises the already-armed reboot authority

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::init_successor_restarts_after_every_last_unlink_cut_and_converges_to_zero -- --exact

Gate contract: Last-unlink process-death convergence.
Maps: Requirement `An init successor covers the last unlink window`; Scenario `The successor dies after unlinking the executable`.
Preconditions: The exact Rust test binds both restartable native services and models survivor replay after every irreversible unlink cut.
Observable result: Every modeled single-process-death cut converges through protected init-file removal and exact zero residue to the durable predicate-bound reboot.
Evidence boundary: Host protocol and state model; Android 9 init service and cgroup behavior remain unverified.

### Requirement: Terminal fallback uses the exact Linux restart syscall ABI

The authorized terminal fallback SHALL issue the fixed Linux reboot syscall with `LINUX_REBOOT_MAGIC1`, `LINUX_REBOOT_MAGIC2`, the complete `LINUX_REBOOT_CMD_RESTART` value `0x01234567`, and a null argument. No caller-selected reboot command SHALL be accepted.

#### Scenario: Graceful shutdown does not restart the device

- **WHEN** the authorized terminal fallback reaches its direct syscall after the bounded graceful-shutdown and flush windows
- **THEN** its fixed arguments match Linux UAPI and the restart command is not truncated to an invalid value

# Gate: cargo test --manifest-path shared/Cargo.toml fixed_process::tests::forced_restart_matches_linux_uapi_instead_of_a_truncated_command -- --exact
Gate contract: Fixed Linux reboot ABI.
Maps: Requirement `Terminal fallback uses the exact Linux restart syscall ABI`; Scenario `Graceful shutdown does not restart the device`.
Preconditions: The production argument supplier is checked against linux/reboot.h from pinned NDK r29.
Observable result: The complete restart command and both kernel magic values match the UAPI tuple.
Evidence boundary: Host argument contract; actual terminal restart remains an Enforcing Android integration gate.

## Unverified

### Unverified: Android 9 init service and cgroup behavior

Maps: Requirement `Terminal cleanup runs in a separate init service`; Scenario `The primary service exits after COMMIT`.
Unavailable observation: The supported target creates independent watchdog and successor service cgroups, retains both already-running processes after their named executable and init source are removed, and lets either survivor finish after the other dies.
Reason: Host tests inspect the init contract and model its state transitions but do not execute Android 9 init or its service-cgroup teardown.
Required environment or artifact: A supported-device fault-injection trace for process death after watchdog COMMIT, recovery-state unlink, executable unlink, product-root removal, init-file removal and reboot request.

### Unverified: End-to-end teardown-domain reachability

Maps: Requirement `Terminal cleanup stays in the loaded teardown domain`; Scenario `The device rebooted before terminal cleanup`.
Unavailable observation: The supported target keeps the patched policy loaded, completes both init services in `u:r:voboost_uninstall:s0`, reaches exact zero residue and then performs only externally justified reboots into the pristine policy.
Reason: Host tests do not run target init, kernel SELinux enforcement or reboot.
Required environment or artifact: A supported-device trace with the bound boot ID, loaded-policy identity, process domains, every terminal cut and the changed terminal boot with pristine policy and zero residue.
