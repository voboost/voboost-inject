# Uninstall control specification

## Purpose

Define the exact privileged uninstall commit and trigger boundary.

## Requirements

### Requirement: Primary uninstall mutations precede terminal handoff exactly once

The primary uninstall phase driver SHALL execute daemon stop, policy-restore preparation, package removal, owned runtime removal and recovery/init-hook publication in exact order. Each action SHALL complete before its phase and observer projection are persisted. Failure SHALL leave the predecessor phase durable so restart repeats the failed action before any successor. Terminal cleanup SHALL be handed to the init-owned continuation only after its recovery authority and hook are complete.

#### Scenario: One primary mutation fails

- **WHEN** any daemon-stop, policy preparation, package, runtime or terminal-handoff action fails
- **THEN** its successor is not persisted and restart repeats that same action

#### Scenario: Primary mutation sequence reaches terminal cleanup

- **WHEN** every primary action succeeds
- **THEN** each action and phase is observed once in exact order before terminal handoff

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::production_uninstall_driver_restarts_every_failed_mutating_phase -- --exact

Gate contract: Primary uninstall failure restart.
Maps: Requirement `Primary uninstall mutations precede terminal handoff exactly once`; Scenario `One primary mutation fails`.
Preconditions: Each production driver action fails once through strict fake operations.
Observable result: No failed phase is persisted; restart executes the same action again before later mutations.
Evidence boundary: Host production orchestration; Android PackageManager, init and SELinux syscalls remain target evidence.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::production_uninstall_driver_executes_every_mutation_before_terminal_handoff -- --exact

Gate contract: Primary uninstall exact action order.
Maps: Requirement `Primary uninstall mutations precede terminal handoff exactly once`; Scenario `Primary mutation sequence reaches terminal cleanup`.
Preconditions: All strict fake actions succeed.
Observable result: The actual production driver executes and persists each primary phase once, verifies ownership before each action and stops at terminal cleanup.
Evidence boundary: Host orchestration and phase publication order; Android external effects are not inferred.

### Requirement: Permanent uninstall authority is closed

The permanent uninstall authority SHALL bind every installed `voboost.json` product member, including daemon, installer, uninstaller, restore executable, `voboost-selinux`, ABI payloads, Android package and AppOp. Executable signature roles SHALL be exactly `daemon`, `install`, `uninstall`, `restore`, and `selinux`; no detached native component manifest exists. The product `restore.json.sig` SHALL be raw 64-byte Ed25519 over the exact canonical `restore.json` bytes under the `restore-manifest` inventory role, identical to installer and daemon verification; the retired install-authorization transcript SHALL NOT be accepted. `/data/voboost/state` is optional runtime data: absence means no agent state was ever persisted, while presence SHALL still require the exact root-owned mode-`0700` directory identity before cleanup. Uninstall SHALL NOT depend on any agent having run.

#### Scenario: Authority inventory differs

- **WHEN** a required member is absent or an extra permanent authority is presented
- **THEN** uninstall fails closed before destructive mutation

#### Scenario: A committed document or signature role is substituted

- **WHEN** a document digest, archived init body, baseline pointer, installed identity or signature role differs from the correlated committed set
- **THEN** the closed parser rejects the set before it grants uninstall authority

# Gate: cargo test --manifest-path shared/Cargo.toml uninstall_contract::contract_tests::exact_committed_contract_binds_every_document_hash_and_signature_role -- --exact

Gate contract: Correlated permanent uninstall document parser.
Maps: Requirement `Permanent uninstall authority is closed`; Scenario `A committed document or signature role is substituted`.
Preconditions: The exact Rust test builds one canonical correlated authority set, then independently substitutes a role and archived init bytes.
Observable result: the canonical set is accepted and each substituted set is rejected.
Evidence boundary: Host parser behavior only; directory enumeration, installed Android artifacts, SELinux labels, native signatures and atomic device publication are not observed.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::package::tests::restore_pair_uses_the_shared_raw_canonical_document_signature -- --exact

Gate contract: Product restore authority signature parity.
Maps: Requirement `Permanent uninstall authority is closed`; Scenario `A committed document or signature role is substituted`.
Preconditions: The uninstaller verifier receives an exact document signature, a legacy transcript signature and a foreign inventory role under one test key.
Observable result: Only raw Ed25519 over the exact document bytes with role `restore-manifest` is accepted.
Evidence boundary: Host signature verification; installed Android files and physical removal remain target evidence.

# Unverified: Permanent uninstall authority inventory

### Requirement: Normal uninstall removes only the signed Voboost Android package

The role-signed `voboost-uninstall` executable SHALL embed the expected SHA-256 of the Voboost Android signing certificate supplied at build time. Immediately before invoking Package Manager removal, it SHALL resolve `ru.voboost` for Android user 0, parse the bounded APK Signing Block v2/v3 certificate directly from the installed base APK through a no-follow file descriptor, require one consistent signer across the present v2/v3 records, and compare its certificate digest with the embedded authority. Both observations SHALL also strictly parse the same positive signed-long `versionCode` from Package Manager. The second observation SHALL require the same package path, inode, certificate and `versionCode`, then global removal SHALL pass that value through `pm uninstall --versionCode` and require global package absence afterwards. Absence after the first check, substitution, ambiguity, malformed or v1-only signing data, another user selection, signer mismatch or an ordinary concurrent update SHALL fail closed. The parser does not independently verify the APK's content signatures: Android Package Manager is the authority that admitted the installed base APK, while this boundary binds that installed object to the release certificate before granting destructive removal. The APK byte digest SHALL NOT be the normal-uninstall identity because OTA versions legitimately change those bytes. Android's external CLI cannot make the preceding observations and removal one atomic operation; a concurrent privileged uninstall and reinstall using the same package, certificate and `versionCode` is outside this threat model and SHALL NOT be described as excluded.

#### Scenario: Another application occupies the package name

- **WHEN** the installed `ru.voboost` base APK is unsigned, malformed, replaced between checks or signed by another certificate
- **THEN** normal uninstall stops before invoking Package Manager removal

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::apk_signer_binding_accepts_one_v2_or_v3_certificate_and_rejects_substitution -- --exact

Gate contract: APK signing-authority parser.
Maps: Requirement `Normal uninstall removes only the signed Voboost Android package`; Scenario `Another application occupies the package name`.
Preconditions: the named host test supplies bounded synthetic v2/v3 signing blocks with matching, substituted and unsupported signer records.
Observable result: only a singular certificate consistent across supported signing records yields the expected certificate SHA-256; substituted and unsupported authority is rejected.
Evidence boundary: host parser behavior only; Android Package Manager serialization, installed APK identity, protected build input and physical-device removal remain unverified.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::package_version_binding_is_canonical_and_bounded -- --exact

Gate contract: Package Manager version binding parser.
Maps: Requirement `Normal uninstall removes only the signed Voboost Android package`; Scenario `Another application occupies the package name`.
Preconditions: the named host test supplies canonical, zero, signed, leading-zero, duplicate and overflowing version inventory outputs.
Observable result: only one positive canonical value within Android's signed-long bound is accepted.
Evidence boundary: host output parser only; stock Android command output and concurrent package operations are not exercised.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::package_removal_command_is_version_guarded -- --exact

Gate contract: Version-guarded Package Manager removal arguments.
Maps: Requirement `Normal uninstall removes only the signed Voboost Android package`; Scenario `Another application occupies the package name`.
Preconditions: the named host test constructs removal arguments for a committed version code.
Observable result: the exact command arguments contain `uninstall --versionCode <value> ru.voboost`.
Evidence boundary: host argument construction only; Android Package Manager execution and race serialization are not exercised.

# Unverified: Android Package Manager package/user and immediate pre-removal identity binding

### Requirement: Uninstall requests preempt incompatible work in one fixed order

After mandatory recovery of an interrupted update switch, an exact root prepared marker SHALL take precedence even over generation activation recovery. An exact app request SHALL take precedence over new generation activation, vehicle-profile creation, update confirmation/apply and injection.

#### Scenario: Uninstall request preempts incompatible work

- **WHEN** an exact request or prepared marker coexists with pending activation work
- **THEN** the daemon applies the fixed preemption order before freezing either update plane

#### Scenario: Uninstall and update markers coexist at boot

- **WHEN** crash recovery has restored a coherent executable and generation state
- **THEN** durable prepared authority preempts generation recovery, then fixed retries freeze and consume incoming update authority before any new activation, confirmation or apply

# Unverified: Uninstall runtime compensation path

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::uninstall_request_or_prepared_marker_preempts_activation_and_native_work -- --exact
Gate contract: Uninstall requests preempt incompatible work in one fixed order host contract.
Maps: Requirement `Uninstall requests preempt incompatible work in one fixed order`; Scenarios `Uninstall request preempts incompatible work`, `Uninstall and update markers coexist at boot`.
Preconditions: The exact Rust test runs its committed fixtures and selects only the named contract harness.
Observable result: the daemon applies the fixed preemption order before freezing either update plane; durable prepared authority preempts generation recovery, then fixed retries freeze and consume incoming update authority before any new activation, confirmation or apply.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Request consumption follows a resolved pre-commit outcome

Before prepared publication, the daemon SHALL consume the app request only after complete transactional compensation has restored live semantics. Incomplete compensation SHALL preserve the request and keep activation fenced for retry.

#### Scenario: Pre-commit restoration remains incomplete

- **WHEN** cleanup fails and compensation cannot prove restoration
- **THEN** the app request remains as the activation fence

# Unverified: Uninstall executable role-signature runtime rejection

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::request_is_consumed_only_after_commit_or_complete_rollback -- --exact
Gate contract: Request consumption follows a resolved pre-commit outcome host contract.
Maps: Requirement `Request consumption follows a resolved pre-commit outcome`; Scenario `Pre-commit restoration remains incomplete`.
Preconditions: The exact Rust test runs its committed fixtures and selects only the named contract harness.
Observable result: the app request remains as the activation fence.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Primary uninstall invocation is exact

Primary execution SHALL require `/data/voboost/voboost-uninstall`, root effective UID, init parent and no arguments. The transaction identifier SHALL be derived from the correlated committed inventory bytes, signed uninstaller digest and current policy-baseline digest. The daemon SHALL publish the exact marker bytes `{"schemaVersion":1,"prepared":true}\n` only at `/data/voboost/recovery/<tx>/uninstall_do.json`. The signed uninstaller SHALL discover exactly that one root-owned transaction and SHALL keep its phase and remount journals in the same recovery directory. Marker, status and operation journals SHALL NOT be written into the permanent `/data/voboost/uninstall` authority.

#### Scenario: Uninstall executable is invoked outside its closed role

- **WHEN** primary path, root identity, init parent, argv or marker bytes differ
- **THEN** the executable exits without teardown mutation

#### Scenario: Operation state is mixed with permanent reverse authority

- **WHEN** the marker or an uninstall phase or remount journal is absent from the one correlated recovery transaction
- **THEN** the executable does not treat a similarly named permanent file as operation authority

#### Scenario: A shell starts the uninstall executable

- **WHEN** its parent is not init
- **THEN** it exits without teardown mutation

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::primary_invocation_pins_marker_path_root_init_parent_and_empty_argv -- --exact

Gate contract: focused host test for the mapped contract.

Maps: Requirement `Primary uninstall invocation is exact`; Scenarios `Uninstall executable is invoked outside its closed role`, `A shell starts the uninstall executable` and `Operation state is mixed with permanent reverse authority`.

Preconditions: the named test constructs its isolated fixtures and fault or substitution cut.

Observable result: the executable exits without teardown mutation; it exits without teardown mutation

Evidence boundary: the exact named host test `tests::primary_invocation_pins_marker_path_root_init_parent_and_empty_argv` proves only its exercised model and filesystem/process fixtures; it does not prove Android device, reboot, SELinux Enforcing or vehicle behavior.
# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::marker_and_closed_operation_guards_are_exact -- --exact

Gate contract: focused host test for the mapped contract.

Maps: Requirement `Primary uninstall invocation is exact`; Scenario `Uninstall executable is invoked outside its closed role`; Scenario `A shell starts the uninstall executable`.

Preconditions: the named test constructs its isolated fixtures and fault or substitution cut.

Observable result: the executable exits without teardown mutation; it exits without teardown mutation

Evidence boundary: the exact named host test `tests::marker_and_closed_operation_guards_are_exact` proves only its exercised model and filesystem/process fixtures; it does not prove Android device, reboot, SELinux Enforcing or vehicle behavior.

### Requirement: Init-owned terminal invocations are exact

The terminal `--watch-uninstall` and `--complete-uninstall` operations SHALL require root, the stable `/data/voboost/voboost-uninstall` executable, init parent and no additional argument. They MAY continue from the correlated `/data/voboost/recovery/<tx>` authority after the primary process exits; no duplicate executable is authorized. The root-only, pathless `--get-uninstall-bound-boot-id` operation SHALL authenticate the same correlated recovery state and output exactly its persisted canonical boot UUID followed by one newline. It SHALL fail if that identity is absent or belongs to another signed uninstaller.

#### Scenario: The watchdog is started outside init

- **WHEN** the fixed watchdog receives exact argv from another parent
- **THEN** it exits without teardown mutation

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::watchdog_invocation_requires_fixed_path_root_init_and_exact_argv -- --exact

Gate contract: focused host test for the mapped contract.

Maps: Requirement `Init-owned terminal invocations are exact`; Scenario `The watchdog is started outside init`.

Preconditions: the named test constructs its isolated fixtures and fault or substitution cut.

Observable result: it exits without teardown mutation

Evidence boundary: the exact named host test `tests::watchdog_invocation_requires_fixed_path_root_init_and_exact_argv` proves only its exercised model and filesystem/process fixtures; it does not prove Android device, reboot, SELinux Enforcing or vehicle behavior.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::persisted_terminal_boot_id_endpoint_is_root_only_pathless_and_state_bound -- --exact

Gate contract: Persisted pre-reboot boot identity output.

Maps: Requirement `Init-owned terminal invocations are exact`; Scenario `The watchdog is started outside init`.

Preconditions: the named host test varies UID, argv, signed-uninstaller digest and persisted terminal boot identity.

Observable result: only root with exact pathless argv and correlated canonical state obtains the bound UUID.

Evidence boundary: host parser and state model only; Android boot identity persistence and installer transport are not exercised.

### Requirement: Prepared uninstall authority is descriptor-bound

Prepared authority and status SHALL be created only through validated root and fixed `uninstall` directory descriptors. Parent symlinks or swaps and foreign symlinked or hard-linked leaf files SHALL be rejected; atomic replacement and fsync SHALL remain bound to the originally opened directory inode.

#### Scenario: Prepared authority parent is substituted

- **WHEN** a protected parent or leaf no longer resolves to its retained verified inode
- **THEN** prepared publication and status fail without following the substituted path

# Gate: cargo test --manifest-path daemon/Cargo.toml uninstall::tests::opened_uninstall_directory_is_stable_across_parent_path_swap -- --exact

Gate contract: focused host test for the mapped contract.

Maps: Requirement `Prepared uninstall authority is descriptor-bound`; Scenario `Prepared authority parent is substituted`.

Preconditions: the named test constructs its isolated fixtures and fault or substitution cut.

Observable result: prepared publication and status fail without following the substituted path

Evidence boundary: the exact named host test `uninstall::tests::opened_uninstall_directory_is_stable_across_parent_path_swap` proves only its exercised model and filesystem/process fixtures; it does not prove Android device, reboot, SELinux Enforcing or vehicle behavior.
# Gate: cargo test --manifest-path daemon/Cargo.toml uninstall::tests::uninstall_authority_rejects_foreign_hard_link -- --exact

Gate contract: focused host test for the mapped contract.

Maps: Requirement `Prepared uninstall authority is descriptor-bound`; Scenario `Prepared authority parent is substituted`.

Preconditions: the named test constructs its isolated fixtures and fault or substitution cut.

Observable result: prepared publication and status fail without following the substituted path

Evidence boundary: the exact named host test `uninstall::tests::uninstall_authority_rejects_foreign_hard_link` proves only its exercised model and filesystem/process fixtures; it does not prove Android device, reboot, SELinux Enforcing or vehicle behavior.
### Requirement: Pre-commit uninstall compensation restores exact live semantics

Every ordinary failure before publication SHALL verify the canonical bytes are still exact, restore the in-memory flag, and project the prior semantics to each affected endpoint with a compensating generation strictly above its provisional disable generation. Compensation SHALL never resend a stale pre-disable `D` or restore stale acknowledgement caches. An unexpected canonical change or a failure of compensation enqueue, drain or acknowledgement SHALL return a compound primary-plus-restoration error and SHALL not claim restoration or consume the app request.

#### Scenario: Pre-commit uninstall compensation cannot restore exact semantics

- **WHEN** cleanup fails before prepared publication and correlated compensation cannot drain and acknowledge
- **THEN** the daemon preserves the request, fences activation and reports the primary-plus-restoration failure

# Unverified: Uninstall runtime compensation path

### Requirement: Uninstall executables require role-separated signatures

Every primary, recovery and install-recovery execution SHALL require its valid appended-signature role before parsing teardown authority. A signature from another native role SHALL not authorize execution.

#### Scenario: Uninstall executable has another role's signature

- **WHEN** executable bytes carry a valid signature for a different native role
- **THEN** teardown exits before mutation

# Unverified: Uninstall executable role-signature runtime rejection

### Requirement: Desktop uninstall publication uses the stable daemon authority

The `--request-desktop-uninstall` management command SHALL authorize the root-executed exact installed daemon identity before publishing the fixed empty request. It SHALL NOT require the installed manifest, an active generation or a healthy resident product. Filesystem identity and publication failures SHALL remain errors.

#### Scenario: Product health is unavailable

- **WHEN** the stable installed daemon identity is authorized while an install is incomplete or product health is unavailable
- **THEN** the command attempts the fixed request publication without invoking active-product authorization

# Unverified: Android stable uninstall request publication

### Requirement: Committed inventory admission degrades only on a context mismatch

The committed uninstall authority read SHALL first require its compile-time SELinux context. Only an unexpected-context error SHALL permit a bounded-context retry that still requires a root-owned mode-0600 single-link regular file, nofollow access, bounded size and stable metadata. A successful retry SHALL record context degradation. A missing bounded context or another identity failure SHALL remain fatal.

#### Scenario: The inventory has a foreign bounded context

- **WHEN** the strict read rejects only the SELinux context of an otherwise valid authority file
- **THEN** the bounded-context retry admits the file and records the degraded context

#### Scenario: Another authority check fails

- **WHEN** the file has no bounded context or fails ownership, mode, type, link, size or stable-identity validation
- **THEN** the read rejects the authority without authorizing uninstall from it

# Unverified: Android degraded uninstall inventory

### Requirement: Init uninstall worker tolerates the bounded lease handoff

The primary uninstall worker SHALL retry acquisition only for the exact `operation busy` result for at most twenty 250-millisecond waits. Every attempt SHALL retain the checked operation authority. Exhausted busy acquisition and every other authority error SHALL remain failures.

#### Scenario: The triggering daemon has not released its lease

- **WHEN** init starts the worker while the triggering daemon still owns the operation lease
- **THEN** the worker waits within the fixed bound, succeeds when authority becomes available, and does not retry a foreign authority error

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::uninstall_lease_waits_for_trigger_handoff_but_preserves_failure_boundaries -- --exact
Gate contract: Bounded daemon-to-init lease handoff.
Maps: Requirement `Init uninstall worker tolerates the bounded lease handoff`; Scenario `The triggering daemon has not released its lease`.
Preconditions: The production retry seam receives transient busy, permanently busy, and foreign-error sequences.
Observable result: Transient busy succeeds, exhausted busy returns the original error after twenty waits, and foreign errors receive no retry.
Evidence boundary: Host acquisition seam; actual init scheduling requires target evidence.

### Requirement: Agent state directory cleanup accepts only product labels

The uninstall validator SHALL require the optional root-owned mode-0700 state directory to carry the canonical agent-state label or the legacy Voboost data label. It SHALL reject stock and foreign labels and SHALL NOT extend the legacy allowance to other protected directories.

#### Scenario: A canonical state directory exists

- **WHEN** the daemon has persisted state in its dedicated SELinux-labelled directory
- **THEN** uninstall admits that directory without relaxing its ownership, mode or no-follow checks

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::state_directory_accepts_only_current_and_legacy_product_contexts -- --exact

Gate contract: Agent state directory labels.
Maps: Requirement `Agent state directory cleanup accepts only product labels`; Scenario `A canonical state directory exists`.
Preconditions: Canonical, legacy product, stock and unrelated protected labels are supplied to the production context matcher.
Observable result: Only the two product state labels pass; the allowance does not apply to root or uninstall directories.
Evidence boundary: Host context matching; complete normal uninstall requires an Enforcing Android run.

## Unverified

### Unverified: Permanent uninstall authority inventory

Maps: Requirement `Permanent uninstall authority is closed`; Scenario `Authority inventory differs`.
Unavailable observation: the production uninstaller accepting exactly the seven permanent authority members and rejecting every missing or extra member.
Reason: no focused executable harness currently maps the complete inventory.
Required environment or artifact: a named uninstaller test varying every member and extra-entry case.

### Unverified: Android Package Manager package/user and immediate pre-removal identity binding

Maps: Requirement `Normal uninstall removes only the signed Voboost Android package`; Scenario `Another application occupies the package name`.

Unavailable observation: stock Android 9 resolves user 0 path and version, the installed APK matches the embedded certificate, an ordinary concurrent update is rejected by `pm uninstall --versionCode`, and global package absence is then proven.

Reason: host parser and argument-construction tests do not execute Android Package Manager or concurrent package operations.

Required environment or artifact: a rooted Android 9 integration test with controlled same-package OTA replacement between both observations and removal, plus all-user package inventory after the attempt.

### Unverified: Uninstall runtime compensation path

Maps: Requirement `Pre-commit uninstall compensation restores exact live semantics`; Scenario `Pre-commit uninstall compensation cannot restore exact semantics`.

Unavailable observation: the complete provisional disable, cleanup failure, compensating enqueue, drain and correlated acknowledgement path with unchanged canonical intent.

Reason: no focused executable harness currently drives and observes that full runtime compensation sequence.

Required environment or artifact: a named daemon integration test with live endpoint transport, injected cleanup failure and assertions over compensating generation, drain, acknowledgement, canonical bytes and retained request.

### Unverified: Uninstall executable role-signature runtime rejection

Maps: Requirement `Uninstall executables require role-separated signatures`; Scenario `Uninstall executable has another role's signature`.

Unavailable observation: the stable uninstaller rejecting a valid signature from every other native role before teardown mutation.

Reason: current focused Cargo tests do not execute all three signed roles with deliberately cross-signed complete binaries; the available Make targets are broad suites rather than one named behavioral test.

Required environment or artifact: one independently selectable executable test that builds or supplies complete cross-signed role binaries, invokes each closed role and observes rejection before mutation.

### Unverified: Android stable uninstall request publication

Maps: Requirement `Desktop uninstall publication uses the stable daemon authority`; Scenario `Product health is unavailable`.
Unavailable observation: The real root-executed installed daemon publishes the durable request during an incomplete or unhealthy Android installation.
Reason: Source inspection confirms the stable authorization branch; host argument parsing does not exercise the installed executable, Android ownership or SELinux path.
Required environment or artifact: A supported Enforcing Android run using the packaged CLI against both an incomplete installation and an unhealthy installed product.

### Unverified: Android degraded uninstall inventory

Maps: Requirement `Committed inventory admission degrades only on a context mismatch`; Scenarios `The inventory has a foreign bounded context`, `Another authority check fails`.
Unavailable observation: The complete strict-read, bounded-context retry and rejection matrix on actual Android SELinux labels and hostile authority identities.
Reason: The host context-mismatch test compares error classifications and cannot observe Android SELinux metadata or the complete secure read path.
Required environment or artifact: An Android fixture varying bounded foreign context, absent context, ownership, mode, link count, size and concurrent identity substitution before uninstall admission.
