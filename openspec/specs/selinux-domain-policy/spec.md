# SELinux domain policy specification

## Purpose

Define separated resident and teardown policy authority.

## Requirements

### Requirement: Init enters distinct resident and teardown domains

The init service SHALL execute the root-owned mode `0700` `voboost_exec`-labeled daemon in `u:r:voboost:s0` and the distinct root-owned mode `0700` `voboost_uninstall_exec`-labeled primary `voboost-uninstall` service in `u:r:voboost_uninstall:s0`. While the patched policy is loaded, the primary hook and both predeclared terminal services SHALL carry the explicit `voboost_uninstall` service `seclabel`. Both restartable terminal services SHALL enter that domain only through the fixed signed `voboost_uninstall_exec` entry point and exact argv. Stock `shell_exec` SHALL NOT be a teardown-domain entry point. Uninstall SHALL publish the pristine policy bytes on disk but keep the patched policy loaded until the product reaches exact zero residue; only then does the surviving terminal service request one terminal reboot. The resident domain SHALL not receive `sys_admin`, `sys_boot`, `kernel:security setenforce`, remount, reboot, system or vendor mutation, package installation/removal or arbitrary package-manager authority; the fixed signed-APK execution admission below is the only resident package mutation. It SHALL receive only the exact property-service path needed for its fixed `ctl.start voboost-uninstall` request. The teardown domain SHALL receive only the `ctl.stop voboost-daemon`, `ctl.start` watchdog and successor, and `sys.powerctl` permissions exercised by the implementation. It MAY search and inspect `app_data_file` directory metadata only to prove that PackageManager removed the three fixed Voboost package-data aliases; it SHALL NOT enumerate, open, read, write, rename or remove package data. It SHALL NOT receive `kernel:security setenforce` or execute/execute-no-transition authority over the install-only `voboost_selinux_exec` program; either grant requires a preceding implementation that exercises and verifies it.

#### Scenario: The resident domain attempts teardown mutation

- **WHEN** it attempts to change enforcing mode, remount a filesystem, set `ctl.stop`, rewrite protected uninstall authority or request reboot
- **THEN** the generated policy contains no resident allow for that operation

#### Scenario: A policy-window retry enters the teardown domain

- **WHEN** the relabeled signed uninstaller resumes after a process interruption
- **THEN** `voboost_uninstall` retains the exact service-start and reboot-property permissions needed to compensate or resume, without setenforce or SELinux-program execution authority

#### Scenario: Terminal cleanup checks application-data absence

- **WHEN** `voboost_uninstall` inspects the fixed CE, DE and compatibility-alias paths after PackageManager removal
- **THEN** policy permits only directory `search` and `getattr` while denying enumeration and mutation

# Gate: make test-selinux-policy-inject
Gate contract: Init enters distinct resident and teardown domains host contract.
Maps: Requirement `Init enters distinct resident and teardown domains`; Scenarios `The resident domain attempts teardown mutation` and `Terminal cleanup checks application-data absence`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the generated policy contains no resident teardown allow and grants the uninstaller only app-data `search` and `getattr`, without enumeration or mutation.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

# Gate: make test-selinux-real-policy

Gate contract: Teardown retry authority.
Maps: Requirement `Init enters distinct resident and teardown domains`; Scenario `A policy-window retry enters the teardown domain`.
Preconditions: The committed policy fixture is injected and queried by the policy database harness.
Observable result: `voboost_uninstall` has `ctl.start` and power-control property authority while neither teardown domain has unused setenforce or SELinux-program execution authority.
Evidence boundary: Host policy-database evaluation; target process transition and runtime enforcement are not exercised.

### Requirement: Resident target-process authority is exact

The resident domain SHALL enumerate the top-level procfs PID directory but SHALL receive target-labeled process, directory, regular-file and magic-link authority only for the exact domains `system_app` and `system_server`. The allowed directory permissions SHALL be `search`, `read`, `open` and `getattr`; regular-file and magic-link permissions SHALL be `read`, `open` and `getattr`; process mutation authority SHALL be exactly `ptrace` and `sigstop`. `sigstop` is used only to regain a proven ptrace stop after a remote-call timeout; no broader signal authority is granted. The policy SHALL NOT grant those target-object permissions through the `domain` attribute or any other injectable domain. Unreadable non-target PID entries SHALL remain non-candidates, while exact signed application process names and the signed logical `launcher` target `system_server` retain discovery, attestation, ABI resolution, ptrace injection and pipe adoption.

#### Scenario: An exact system-app target is evaluated

- **WHEN** the generated policy is injected into the captured f0506h free-09 Chinese 6.0.3 policy
- **THEN** the complete target-process permission set is effective for `system_app` and `system_server`, with no runtime `signal`, `sigkill` or proc write authority over `system_server`

#### Scenario: An unrelated process domain is evaluated

- **WHEN** the generated policy is evaluated for a domain other than `system_app` and `system_server`
- **THEN** the resident has no target-labeled procfs or ptrace permission through that domain

# Gate: make test-selinux-real-policy
Gate contract: Exact resident target-process authority on the captured firmware policy.
Maps: Requirement `Resident target-process authority is exact`; Scenarios `An exact system-app target is evaluated` and `An unrelated process domain is evaluated`.
Preconditions: The named target verifies the committed f0506h free-09 Chinese 6.0.3 policy-v30 fixture digest, injects generated rules and evaluates effective conditional access-vector decisions for the complete target surface.
Observable result: `system_app` and `system_server` have the required process and target-labeled procfs permissions, while every other member of the firmware `domain` attribute lacks that surface.
Evidence boundary: Host libsepol evaluation of the captured policy; live kernel enforcement, installed labels, target process behavior and vehicle operation are not observed.

# Gate: make test-selinux-policy-inject
Gate contract: Generated exact-domain policy structure.
Maps: Requirement `Resident target-process authority is exact`; Scenarios `An exact system-app target is evaluated` and `An unrelated process domain is evaluated`.
Preconditions: The named synthetic policydb harness injects the generated rule table.
Observable result: The generated table contains the complete exact two-domain target surface and no target-surface allow against `domain` or representative unrelated domains.
Evidence boundary: Host synthetic policy structure only; firmware conditional rules, MLS constraints and live enforcement are not observed.

# Gate: make test-selinux-rule-generation
Gate contract: Deterministic generated SELinux rule table.
Maps: Requirement `Resident target-process authority is exact`.
Preconditions: The named target generates `selinux/rules.gen.h` twice from the same `selinux/voboost.te` bytes.
Observable result: Both generated outputs are byte-identical to each other and to the committed generated header.
Evidence boundary: Host generator determinism and source synchronization only; policy semantics and target enforcement are not inferred.

# Gate: make test-selinux-mls
Gate contract: MLS boundary for exact resident target-process authority.
Maps: Requirement `Resident target-process authority is exact`; Scenarios `An exact system-app target is evaluated` and `An unrelated process domain is evaluated`.
Preconditions: The named target verifies the committed fixture digest and evaluates the captured 6.0.3 MLS constraint expressions after generated policy injection.
Observable result: MLS permits the trusted resident to read both the accepted target and a categorized unrelated target, demonstrating that the effective deny for the unrelated domain must come from the exact type-enforcement rules asserted by the real-policy gate.
Evidence boundary: Host evaluation of captured MLS expressions; live kernel enforcement and target labeling are not observed.

### Requirement: Protected uninstall data has a dedicated policy type

The root-owned mode `0700` `/data/voboost/uninstall` directory and all descendants SHALL have the dedicated `voboost_uninstall_data_file` type. This tree SHALL contain only reverse authority: the committed inventory, exact installed-artifact hashes and signature roles, system-state receipt, archived init bytes, current policy-baseline pointer, policy metadata and digest-addressed pristine policy baselines. The resident daemon MAY traverse and read this immutable authority but SHALL have no directory-name or protected-file mutation permission. Prepared marker, status, uninstall phase and remount journal SHALL remain in the correlated `/data/voboost/recovery/<tx>` transaction. Transient `/data/voboost/install` and `/data/voboost/recovery` trees SHALL use their declared staging and recovery types and SHALL be absent in steady state.

The stable root-owned mode `0700` executables SHALL use `voboost_exec` for `/data/voboost/voboost-daemon`, `voboost_uninstall_exec` for `/data/voboost/voboost-uninstall`, and `voboost_selinux_exec` for `/data/voboost/voboost-selinux`. The retained, signed `/data/voboost/voboost-install` SHALL remain root-owned mode `0700` and use `voboost_install_exec`. The separately signed `/data/voboost/voboost-restore` bootstrap SHALL remain `system_file`. Operation, install staging, recovery, agent state, and uninstall inventory SHALL use their separate purpose-owned file types. Before the first patched-policy reboot, stock `su` may mutate only ordinary install and recovery staging. Once patched policy is active, each signed system program SHALL enter only its dedicated domain or fixed stock bootstrap path. Terminal uninstall data and the signed stable uninstaller SHALL retain their custom types until the init-owned watchdog has committed cleanup and the restartable successor owns the last-unlink window.

#### Scenario: Protected uninstall data is written by the resident domain

- **WHEN** the daemon attempts to rewrite canonical metadata, inventory, phase, committed init body or the protected directory
- **THEN** policy denies both protected-file and protected-directory mutation; operation state remains in ordinary recovery data

#### Scenario: The install-only SELinux program is retained after bootstrap

- **WHEN** patched policy is loaded and the constrained uninstaller executes `/data/voboost/voboost-selinux`
- **THEN** the executable has `voboost_selinux_exec`, and neither `voboost_uninstall` nor stock `su` can execute it directly

# Gate: make test-selinux-policy-inject
Gate contract: Protected uninstall data has a dedicated policy type host contract.
Maps: Requirement `Protected uninstall data has a dedicated policy type`; Scenarios `Protected uninstall data is written by the resident domain` and `The install-only SELinux program is retained after bootstrap`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: policy denies resident mutation of the protected reverse-authority tree while retaining read access.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Runtime transaction creation preserves purpose labels

Under the compiled enforcing policy, runtime and installer creation of `operation.lock`, `operation.json`, `.operation.json.tmp`, the fixed `install` root and the fixed `recovery` root SHALL select their declared purpose types through exact filename transitions. A product update SHALL keep `/data/voboost/install/<tx>` as `voboost_install_staging_file`; only its descriptor-retained `candidate` subtree and `product-proposal.json` atomic publication SHALL use `voboost_update_staging_file`. The correlated `/data/voboost/recovery/<tx>` and its rollback members SHALL remain `voboost_recovery_file`. The generated `file_contexts` SHALL produce the same inode mapping during an init-equivalent recursive relabel, including after reboot. Runtime SHALL receive only the create, read, write, rename and cleanup authority required for these product-update install members and the existing operation and recovery transactions. Installer and runtime SHALL remain denied cross-purpose protected authority.

#### Scenario: Runtime publishes an atomic operation descriptor and update

- **WHEN** runtime creates the real operation temporary file, renames it to `operation.json`, creates one update transaction and the tree is relabeled as init would after `post-fs-data`
- **THEN** every inode keeps its exact operation, install, update-candidate or recovery type and runtime can read, write, rename and clean up the transaction

#### Scenario: A transaction domain crosses a purpose boundary

- **WHEN** runtime attempts protected uninstall mutation or installer attempts update-candidate mutation outside its declared staging authority
- **THEN** the effective compiled policy denies the cross-purpose access

# Gate: make test-selinux-real-policy
Gate contract: Runtime transaction creation preserves purpose labels under compiled policy.
Maps: Requirement `Runtime transaction creation preserves purpose labels`; Scenarios `Runtime publishes an atomic operation descriptor and update` and `A transaction domain crosses a purpose boundary`.
Preconditions: The committed captured f0506h policy is injected, serialized and re-read; the harness evaluates filename transitions and effective permissions for a complete update transaction plus negative cross-purpose controls.
Observable result: creation and init-equivalent relabel select identical inode labels, atomic temporary renames retain the declared type, required runtime access and cleanup succeed, and cross-purpose access is denied.
Evidence boundary: Host libsepol and filesystem-model execution against the captured policy; a live Android kernel, actual boot, vehicle and device-side Enforcing behavior are not observed.

### Requirement: Installation verifies activated policy and installed labels

The signed SELinux program and source `selinux/voboost.te` SHALL define all custom types and rules; copying policy source text onto a live system SHALL not count as activation. Android init SHALL invoke only the fixed signed `/data/voboost/voboost-selinux --relabel` operation and SHALL NOT call a general-purpose labeling command. The program SHALL accept no path, verify itself and descriptor-relatively relabel the fixed root: daemon executable, uninstaller authority, its own executable and generation tree. It SHALL set the incoming type only on the `generations/next` directory inode, require its user-0 app UID/GID and mode, correlate that identity with exact device-encrypted `/data/user_de/0/ru.voboost`, preserve the application's validated MLS range, and SHALL NOT traverse incoming descendants. Repeating the exact operation SHALL be idempotent. Installation SHALL fail if Enforcing mode, both executable paths and labels, protected authority, SELinux-program label and both normal and recovery init contracts cannot be verified.

#### Scenario: The daemon keeps a generic data-file label

- **WHEN** installation verifies the installed stable path
- **THEN** it refuses to report the daemon as installed

#### Scenario: Install relabel receives another state or path

- **WHEN** argv includes a caller path, the install prefix or intent differs, a fixed inode is substituted, or `generations/next` contains application-owned descendants
- **THEN** no caller-selected object is labeled and the walker does not inspect or relabel those descendants

# Gate: make test-selinux-relabel-walk
Gate contract: Fixed descriptor-relative install relabel walker host contract.
Maps: Requirement `Installation verifies activated policy and installed labels`; Scenario `Install relabel receives another state or path`.
Preconditions: The C host harness supplies stable files, symlinks, inode substitutions and an application-owned incoming subtree.
Observable result: fixed trusted entries receive their exact types, substitution fails closed, repeated relabel is idempotent and incoming descendants remain untouched.
Evidence boundary: Host filesystem/xattr harness only; Android SELinux Enforcing and vehicle behavior are not inferred.

# Unverified: Target SELinux installation verification

### Requirement: Resident package execution admission is fixed and root owned

The init-owned resident MAY enable or disable only the signed installed `ru.voboost` APK for Android user0, cancel that package's jobs, force-stop it, observe its ActivityManager UID state and request its exact signature-protected scheduler recovery receiver. It SHALL first verify the supported user0-only Android profile, canonical mode and active generation under GenerationGuard and signed APK identity. Additional users, unknown user inventory, unavailable package services and failed command or observation SHALL NOT confirm admission. SELinux SHALL add only activity, jobscheduler and user service lookup to the resident's existing package/Binder chain; no su or unprivileged app grant SHALL be added. Runtime Enforcing remains a separate acceptance gate.

#### Scenario: Required package lifecycle services are selected

- **WHEN** the host contract examines generated policy source
- **THEN** only the named resident service lookup grants are present and neither su service grants nor generic process mutation grants are introduced

#### Scenario: Live kernel admits fixed package service operations

- **WHEN** the installed supported profile enters none and later recovers through the packaged installer in Enforcing
- **THEN** actual package processes and jobs are absent across reboot in none, recovery restores the scheduler, and vehicle endpoint processing continues independently of package-service latency

#### Scenario: Retained generation lock pathname is replaced

- **WHEN** another lock inode replaces the generation guard's retained pathname before APK reconciliation
- **THEN** the production helper rejects the displaced authority before reading canonical product state, mutating the APK or publishing confirmation

# Gate: cargo test --manifest-path daemon/Cargo.toml package_execution::tests::package_execution_policy_grants_only_required_service_finds -- --exact
Gate contract: Fixed APK execution admission policy and receipt authority.
Maps: Requirement `Resident package execution admission is fixed and root owned`; Scenario `Required package lifecycle services are selected`.
Preconditions: The daemon host unit tests compile current policy source and receipt parser.
Observable result: The named service lookup contract holds and no generic process grant or stock-su service grant is introduced.
Evidence boundary: Host contract tests, not live SELinux or Android service execution.


# Gate: cargo test --manifest-path daemon/Cargo.toml package_execution::tests::replaced_generation_guard_cannot_mutate_apk_or_publish_receipt -- --exact
Gate contract: Retained generation lock authority gates the APK helper.
Maps: Requirement `Resident package execution admission is fixed and root owned`; Scenario `Retained generation lock pathname is replaced`.
Preconditions: A trusted temporary generation guard is retained while its lock pathname is replaced by a different trusted inode.
Observable result: The actual APK reconciliation helper returns the exact lock-identity rejection before any package operation or receipt publication.
Evidence boundary: Host retained-filesystem authority; Android Binder and live root-domain permissions remain unverified.

# Unverified: Package execution SELinux enforcement

## Unverified

### Unverified: Target SELinux installation verification

Maps: Requirement `Installation verifies activated policy and installed labels`; Scenario `The daemon keeps a generic data-file label`.
Unavailable observation: A supported target boots Enforcing with the patched bytes, applies the intended file contexts, enters both init domains and rejects a stable daemon path with a generic label.
Reason: Host policy compilation and allow/deny evaluation do not run target init, kernel SELinux enforcement or installation against installed inodes.
Required environment or artifact: A supported target installation trace with Enforcing state, loaded-policy identity, inode labels, both init-domain transitions and the generic-label rejection result.


### Unverified: Package execution SELinux enforcement

Maps: Requirement `Resident package execution admission is fixed and root owned`; Scenario `Live kernel admits fixed package service operations` for installed Android package mutation, cancellation/crash convergence, user-profile observation, scheduler acknowledgement, main-poll vehicle progress, SELinux admission and boot/recovery behavior.
Unavailable observation: Actual user0 package disabled state, independent Android process/job absence across reboot and network availability, CLI-only recovery with a registered periodic job, vehicle endpoint processing while the package service is pending, OTA replacement and interrupted lifecycle recovery under live Enforcing policy.
Reason: Staged source, host parser/worker fixtures and captured policy database evaluation cannot run Android services or the live kernel; the staged payload has not been installed.
Required environment or artifact: The completed signed release payload installed exclusively by its packaged CLI into the supported Voyemu profile, full case16 with independent root receipts and endpoint timestamps, then real-car acceptance.
