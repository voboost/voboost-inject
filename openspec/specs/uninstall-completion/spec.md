# Uninstall completion specification

## Purpose

Define the zero-residue boundary, conditional reboot evidence and the external completion receipt.

## Requirements

### Requirement: Uninstall completion removes the complete product inventory

Terminal cleanup SHALL remove the Android package and every committed or
temporary Voboost path. This includes ordinary product data, uninstall
authority, the recovery transaction, ownership marker, stable native
executables, Android CE and DE package-data aliases, `/data/voboost`, and the
exact init file, including the inventory-bound `/data/voboost/voboost-restore`
artifact and every transaction-local authorization document. Symbolic links, special inodes, foreign data and an over-bound
user inventory SHALL fail closed. Recursive shell removal SHALL not be used.

#### Scenario: A fixed path remains after terminal cleanup

- **WHEN** any path in the closed terminal inventory remains
- **THEN** completion is rejected

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_absence_contract_names_every_fixed_temp_and_app_data_alias -- --exact

Gate contract: Exact terminal absence inventory.
Maps: Requirement `Uninstall completion removes the complete product inventory`; Scenario `A fixed path remains after terminal cleanup`.
Preconditions: The exact Rust test inspects the closed fixed-path and Android app-data inventory.
Observable result: The terminal proof covers product paths, protected mutation temporaries and package-data aliases.
Evidence boundary: Host inventory definition; no target deletion is performed.

### Requirement: Every reboot is justified by a current failed predicate

The device-owned transaction SHALL request reboot only after durably recording
one concrete reboot-recoverable reason, the current boot ID and the exact
predicate to repeat. The init-owned watchdog and successor SHALL retain that
authority through the final unlink window, so an uninstall started in Settings
does not require a desktop process. Repeating the same reason and observation
after a changed boot SHALL fail terminally instead of creating another reboot
loop. A connected installer only observes device progress and performs an
additional full absence verification after the device-owned final reboot.

#### Scenario: The successor reaches zero residue

- **WHEN** the exact product inventory and recovery init file are absent
- **THEN** the init-owned successor requests only the previously armed device-owned reboot without recreating product authority

# Unverified: Settings uninstall completion observation

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::init_successor_restarts_after_every_last_unlink_cut_and_converges_to_zero -- --exact

Gate contract: Zero-residue and conditional-reboot ordering.
Maps: Requirement `Every reboot is justified by a current failed predicate`; Scenario `The successor reaches zero residue`.
Preconditions: The exact Rust test binds the two fixed native terminal invocations and survivor replay model.
Observable result: Protected init-file removal and recovery-state removal precede executable and empty-root removal; reboot follows durable device evidence and exact zero, and every modeled single-process-death cut converges.
Evidence boundary: Host contract model; target reboot and durable storage behavior are not exercised.

### Requirement: Completion exists only as an external receipt

After `/data/voboost` is absent, no device marker or synthetic device report SHALL claim `uninstall-complete`. The installer SHALL issue a terminal receipt only after one observation proves every fixed absence member. The receipt SHALL bind the transaction ID learned before root removal, the last observed boot ID and the complete named check set.

#### Scenario: The operation document disappeared with the product root

- **WHEN** the canonical device operation document can no longer be read
- **THEN** the installer runs the fixed external absence predicate and does not infer completion from the missing document

# Unverified: External uninstall receipt

### Requirement: Host tests do not prove target completion

Passing host tests SHALL NOT be reported as proof that target init, Package
Manager, mounts, SELinux policy restoration or the terminal reboot completed.

#### Scenario: No device uninstall has been run

- **WHEN** all host gates pass
- **THEN** supported-device uninstall completion remains unverified

# Unverified: Target conditional-reboot completion

### Requirement: Uninstall removes only its launcher icon cache namespace

Before stock policy restoration, uninstall SHALL remove only `.vbi1-<64 lowercase hexadecimal digits>.bin` and its `.bak` and `.new` siblings from the trusted launcher UID's private `cache/icons` directory. Corrupt or empty payloads SHALL remain disposable owned cache. Unknown files and the generic directory SHALL remain. Directory handles SHALL reject arbitrary symlinks, UID changes, hard links, special entries and directory replacement. Only the fixed Android user-zero data aliases may resolve to their real peer. Normal removal SHALL require a root-owned receipt correlated to this uninstall transaction and boot, recording either acknowledged cache-only drain or the absence of a bound launcher endpoint. A no-endpoint record SHALL NOT constitute a writer acknowledgment: after daemon stop the native helper SHALL independently prove that no injected launcher writer remains before and after purge. Numeric PID kill and deliberate application crash SHALL NOT supply this proof.

#### Scenario: Corrupt owned cache coexists with stock files

- **WHEN** the cleanup receives owned corrupt and AtomicFile entries beside stock entries
- **THEN** owned entries are removed, stock entries remain and exact namespace absence is verified

#### Scenario: A quiescence receipt belongs to another transaction or boot

- **WHEN** the durable receipt transaction, boot or closed command differs from the accepted uninstall authority
- **THEN** the receipt is rejected and cannot authorize cache purge


# Gate: cargo test --manifest-path uninstall/Cargo.toml cache_cleanup::tests::corrupt_and_atomic_files_removed_foreign_preserved_symlink_target_untouched -- --exact
Gate contract: Exact cache namespace filtering, anchored removal and foreign-file preservation.
Maps: Requirement `Uninstall removes only its launcher icon cache namespace`; Scenario `Corrupt owned cache coexists with stock files`.
Preconditions: Controlled corrupt and empty owned entries, stock entries and an owned symlink pointing outside the cache directory.
Observable result: Exact owned entries disappear while stock entries and the symlink destination remain; repeating cleanup reports no remaining owned entries.
Evidence boundary: Host filesystem behavior; complete Android uninstall requires runtime receipt, policy and reboot checks.

# Gate: cargo test --manifest-path contract/Cargo.toml icon_cache_quiescence::tests::durable_receipt_binds_transaction_boot_and_exact_command -- --exact
Gate contract: Strict durable cache-quiescence receipt correlation.
Maps: Requirement `Uninstall removes only its launcher icon cache namespace`; Scenario `A quiescence receipt belongs to another transaction or boot`.
Preconditions: Matching and mismatched transaction, boot and command receipt objects.
Observable result: Only the matching receipt is accepted; unknown and duplicate fields reject parsing.
Evidence boundary: Host contract parser and equality checks; root-owned file authority and live Android worker identity require runtime evidence.

### Requirement: Uninstall cache maintenance keeps a scoped endpoint context

An adopted cache-only uninstall endpoint SHALL carry its exact PID, starttime, endpoint epoch, resident generation/catalog and accepted desired revision into the cache-quiescence handshake. It SHALL NOT create ordinary desired documents, enable agents or authorize process restart. A foreign PID, endpoint epoch or revision SHALL NOT reuse that maintenance authority. Maintenance context SHALL be available only while uninstall activation is frozen. Finishing uninstall preparation SHALL discard the override; rollback SHALL also close and untrack the cache-only endpoint so ordinary lifecycle can authenticate a fresh endpoint.

#### Scenario: Maintenance handshake has no ordinary activation and rollback releases it

- **WHEN** a cache-only endpoint context is used for the cache handshake, another identity is presented, activation unfreezes and preparation rolls back
- **THEN** only the exact context accepts the correlated cache acknowledgment and receipt, ordinary desired documents remain absent, foreign identities and revision cannot acknowledge it, and rollback removes the endpoint and override

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml runtime::parallel_tests::cache_maintenance_context_does_not_activate_agents_and_rollback_closes_it -- --exact

Gate contract: Scoped maintenance context, correlated acknowledgment and rollback lifetime.
Maps: Requirement `Uninstall cache maintenance keeps a scoped endpoint context`; Scenario `Maintenance handshake has no ordinary activation and rollback releases it`.
Preconditions: A tracked host endpoint receives a maintenance context with no ordinary desired documents; PID, epoch, revision and activation state then differ before rollback.
Observable result: The exact revision accepts C acknowledgment and a transaction/boot-correlated receipt; wrong identity or revision cannot reuse it, no desired document appears, and rollback clears both override and tracker endpoint.
Evidence boundary: Host context consumer, acknowledgment and receipt behavior; native rebind attestation, Java cache drain and target filesystem purge require the target maintenance recovery trace.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml icon_quiescence::tests::exact_correlated_ack_and_foreign_endpoint_fences -- --exact

Gate contract: Exact cache acknowledgment identity fences.
Maps: Requirement `Uninstall cache maintenance keeps a scoped endpoint context`; Scenario `Maintenance handshake has no ordinary activation and rollback releases it`.
Preconditions: An exact pending cache command receives acknowledgments with foreign PID, starttime, epoch, process, revision, generation/catalog or request identity before the exact acknowledgment.
Observable result: Every foreign identity is rejected; only the exact command and endpoint acknowledge and produce the matching transaction/boot receipt.
Evidence boundary: Host acknowledgment owner; target writer drain and native cleanup remain Android observations.

### Requirement: Uninstall recovers only an existing launcher maintenance endpoint

When uninstall starts in a fresh daemon without a launcher downlink, it SHALL inspect only the existing launcher process and recover a transport only when injected maps and retained signed catalog authority admit the exact live PID/starttime. Recovery SHALL use the existing resident rebind operation, re-attest exact resident generation/catalog and require the accepted desired revision before tracking the maintenance endpoint. It SHALL NOT fall back to fresh injection or send an ordinary desired snapshot. Recovery failure SHALL NOT authorize cache purge. A successful recovered endpoint SHALL use the existing correlated cache-only C acknowledgment and transaction/boot receipt before the native helper independently validates the writer and purges the owned namespace.

#### Scenario: A stopped NONE daemon wakes for ordinary uninstall

- **WHEN** a daemon stopped by startup NONE restarts for uninstall while its injected launcher survives with no fresh downlink
- **THEN** only that authenticated existing launcher is rebound, its accepted revision authorizes the cache-only handshake without agent activation, and normal removal obtains the required writer proof before scoped purge

# Unverified: Target launcher maintenance recovery

## Unverified

### Unverified: Target conditional-reboot completion

Maps: Requirement `Host tests do not prove target completion`; Scenario `No device uninstall has been run`.
Unavailable observation: A supported target completes package removal, pristine-policy publication, same-boot watchdog cleanup, exact zero residue and only externally justified reboots into the pristine policy.
Reason: Host tests replace target init, Package Manager, mounts, SELinux and reboot with controlled models.
Required environment or artifact: A supported rooted target trace covering each recorded reboot reason and boot ID, the repeated full predicate, final package absence, zero `/data/voboost` inventory and pristine loaded policy.

### Unverified: Settings uninstall completion observation

Maps: Requirement `Every reboot is justified by a current failed predicate`; Scenario `The successor reaches zero residue`.
Unavailable observation: Settings receives a trustworthy success result after its package and all Voboost files are absent.
Reason: No application observer survives the required zero-residue boundary.
Required environment or artifact: UI semantics that treat the initiated teardown as accepted, or a separately designed surviving observer contract.

### Unverified: External uninstall receipt

Maps: Requirement `Completion exists only as an external receipt`; Scenario `The operation document disappeared with the product root`.
Unavailable observation: The packaged installer observes the complete fixed absence predicate after `/data/voboost` and its operation document are gone and emits one transaction-bound receipt.
Reason: Native host tests cannot execute the separately packaged desktop installer or observe a target after root removal.
Required environment or artifact: One packaged-installer run against a supported target that records the pre-removal transaction and boot IDs, proves every fixed absence member, and retains the emitted receipt.


### Unverified: Target launcher maintenance recovery

Maps: Requirement `Uninstall recovers only an existing launcher maintenance endpoint`; Scenario `A stopped NONE daemon wakes for ordinary uninstall`.
Unavailable observation: The same installed payload survives startup NONE, wakes a fresh daemon for ordinary uninstall, rebinds only the authenticated launcher, obtains the exact Java cache drain acknowledgment and completes scoped purge without ordinary desired activation.
Reason: Host parser and context tests cannot execute Android ptrace, live ART identity, Java cache writer drain and the target filesystem cleanup as one transaction.
Required environment or artifact: A fresh same-build install followed by startup NONE, confirmed daemon stop and ordinary uninstall, retaining exact PID/starttime/epoch, accepted revision, correlated cache receipt, owned namespace absence and terminal uninstall receipt.
