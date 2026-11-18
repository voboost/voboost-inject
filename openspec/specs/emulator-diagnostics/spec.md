# emulator-diagnostics Specification

## Purpose

Define bounded installed-operator diagnostics that exercise existing error handling only on an emulator.

## Requirements

### Requirement: Emulator fault windows require installed operator authority

The installed daemon SHALL expose only `startup-mutation-lock`, `vehicle-state-reply-loss` and `uninstall-transport-loss` through a fixed diagnostic command. Admission SHALL require Android QEMU, actual Enforcing, root identity, exact stable signed daemon bytes, active signed product and generation identities, the current boot, and exact daemon and target PID/starttime. The CLI SHALL validate the signed catalog target, exact argv0, stable UID fields and PID/starttime without reading another process's SELinux attributes from the stock ADB su domain. Before every diagnostic effect, the resident daemon SHALL independently attest the target against the active signed catalog, including its SELinux context and unchanged PID/starttime. Failure of resident attestation SHALL leave the marker ineffective; no su policy expansion is permitted. The marker SHALL bind those identities, a fresh token, self-attested owner PID/starttime from the authenticated root CLI and a fixed monotonic lifetime of ninety seconds. Kernel liveness SHALL use a retained OFD write lease on byte zero of the existing operation.lock, independent of the generation flock; ordinary POSIX locks and unsupported-kernel fallback SHALL NOT be used. The resident SHALL require the exact conflicting OFD write range, then recheck the named marker inode and complete canonical bytes/token before admitting an effect. Owner metadata SHALL NOT be described as independent remote-process executable attestation. CLI resident admission SHALL reuse the trusted-root management authority whose runtime producer verifies its own signed running executable; the resident SHALL also self-attest before an effect. Neither side SHALL require new su permissions or runtime reads of the su owner proc files. Unknown arguments, physical hosts, stale identities and concurrent windows SHALL fail closed. EOF, expiry or cancellation SHALL release the window and remove only its own trusted marker. A killed owner, changed boot, daemon, target or generation SHALL make a retained marker inert. Reclamation SHALL reject unsafe metadata and occur only for a stale trusted inode under the existing generation mutation lock. Admission and cleanup SHALL serialize through that same lock; an admitted live marker SHALL exclude a concurrent owner without requiring a separate runtime-file flock. The command SHALL accept no arbitrary shell, path, executable, source, key, duration or destructive operation authority.

#### Scenario: A diagnostic caller supplies foreign authority

- **WHEN** the command or marker has a non-emulator, unknown, stale, expired, replayed or wrong-owner identity
- **THEN** no diagnostic effect is admitted

#### Scenario: A diagnostic owner exits or its window expires

- **WHEN** stdin closes, its deadline passes or the marker owner is no longer the same live process
- **THEN** the fault is inactive, cleanup preserves a substituted foreign inode and a new owner can reclaim only a stale trusted marker

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::authority_is_closed_and_fenced -- --exact

Gate contract: Closed installed diagnostic authority.
Maps: Requirement `Emulator fault windows require installed operator authority`; Scenario `A diagnostic caller supplies foreign authority`.
Preconditions: Production typed parsing and identity predicates receive valid and counterfactual host observations.
Observable result: Unknown actions and changed endpoint, boot, owner and expiry dimensions are rejected.
Evidence boundary: Host parser and authority predicates; Android property and signed installed admission remain target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::window_cleanup_is_inode_bound_and_restores_the_guard -- --exact

Gate contract: Diagnostic cleanup and real mutation-lock lifetime.
Maps: Requirement `Emulator fault windows require installed operator authority`; Scenario `A diagnostic owner exits or its window expires`.
Preconditions: Real host files and a held production GenerationGuard form the window fixture.
Observable result: The guard rejects mutation while held, releases on scope exit, own marker is removed and foreign or unsafe entries are preserved or rejected.
Evidence boundary: Host descriptor ownership and scope cleanup; host disconnect and Android process lifetime require target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::cleanup_waits_for_the_same_generation_lock_as_admission -- --exact

Gate contract: Diagnostic cleanup serializes with generation admission.
Maps: Requirement `Emulator fault windows require installed operator authority`; Scenario `A diagnostic owner exits or its window expires`.
Preconditions: A real host generation guard is held while another thread requests cleanup of its own trusted marker.
Observable result: The marker remains while admission owns the guard and cleanup completes after guard release.
Evidence boundary: Host locking and cleanup only; stock Android su permissions and resident target attestation require target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::operator_lease_requires_exact_ofd_kernel_identity -- --exact

Gate contract: Accept only the exact kernel OFD ownership shape.
Maps: Requirement `Emulator fault windows require installed operator authority`; Scenario `A diagnostic caller supplies foreign authority`.
Preconditions: The production lease-shape predicate receives conflicting write, unlocked, read, POSIX PID and changed-range observations.
Observable result: Only an OFD write lock with PID minus one and the fixed single-byte range is accepted.
Evidence boundary: Host predicate tests; OFD acquisition, lifetime and independence from flock require Linux target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::old_reader_rejects_republished_marker_even_with_reused_pid -- --exact

Gate contract: A retained reader cannot adopt a new operator lease through a republished marker.
Maps: Requirement `Emulator fault windows require installed operator authority`; Scenario `A diagnostic caller supplies foreign authority`.
Preconditions: Real trusted marker descriptors remain retained while the named marker is replaced, or its bytes change under the same inode and owner PID.
Observable result: The old reader rejects both inode replacement and canonical token/identity changes.
Evidence boundary: Host filesystem fencing; concurrent Android owner death and new lease acquisition require target evidence.

### Requirement: Emulator faults exercise existing authenticated production paths

A startup window SHALL hold the real `GenerationGuard` so a current owned Settings startup mutation is rejected before canonical commit and receives no false acknowledgement. A state window SHALL drop only already-authorized FEV or pedestrian-warning operational-key read replies for its exact resident endpoint; writes, durable state bytes and other frames SHALL retain their ordinary paths. An uninstall window SHALL cause one real transport failure only after authenticating its exact Settings peer and before admitting any durable uninstall request. Reusing the same uninstall token SHALL NOT cause a second diagnostic failure. Effects SHALL retain correlated root-owned identity diagnostics without supplied state or success verdicts.

#### Scenario: A current startup mutation meets a real lock holder

- **WHEN** an authorized Settings event requests a startup change while GenerationGuard is held
- **THEN** canonical intent remains unchanged, no acknowledgement is created and the same event can commit after the guard is released

#### Scenario: State reply loss is scoped to one owned target

- **WHEN** an authorized fixed-key read matches the live window and another read does not
- **THEN** only the matching reply is suppressed and the actual stored bytes remain unchanged

#### Scenario: One authenticated uninstall transport fails before admission

- **WHEN** an exact Settings peer reaches a live uninstall window and repeats the request
- **THEN** the first stream fails before destructive admission, wrong peers cannot consume the token and replay does not trigger a second diagnostic loss

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml agent_events::tests::startup_lock_rejects_owned_radio_before_commit_and_ack -- --exact

Gate contract: Real guarded Settings mutation rejection.
Maps: Requirement `Emulator faults exercise existing authenticated production paths`; Scenario `A current startup mutation meets a real lock holder`.
Preconditions: Production Settings mutation routing receives a valid event with an actual held GenerationGuard and a canonical host plan.
Observable result: The held guard prevents canonical mutation and pending acknowledgement; after release the ordinary event commits without losing other intent.
Evidence boundary: Host production lock and routing; actual Settings ACK deadline and UI copy require Android evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::state_reply_loss_is_owned_and_does_not_mutate_storage -- --exact

Gate contract: Authenticated state reply loss.
Maps: Requirement `Emulator faults exercise existing authenticated production paths`; Scenario `State reply loss is scoped to one owned target`.
Preconditions: Production read routing uses a scoped live window fixture, real reply pipe and secure state file.
Observable result: Matching authorized reads produce no reply, wrong target/source/key retains ordinary routing and state bytes remain identical.
Evidence boundary: Host root route and pipe; JNI timeout, Java retries and cancellation require Android evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml emulator_diagnostic::tests::uninstall_loss_is_after_peer_authority_and_one_shot -- --exact

Gate contract: One-shot loss after Settings peer authentication.
Maps: Requirement `Emulator faults exercise existing authenticated production paths`; Scenario `One authenticated uninstall transport fails before admission`.
Preconditions: Production one-shot admission and peer-scoped effect predicates receive trusted and wrong-peer fixtures.
Observable result: Wrong peers cannot consume the window and only one trusted request is lost before the destructive callback.
Evidence boundary: Host authenticated dispatch; actual LocalSocket and Settings retryable copy require target evidence.

# Unverified: Packaged Android diagnostic lifecycle

## Unverified

### Unverified: Packaged Android diagnostic lifecycle

Maps: Requirements `Emulator fault windows require installed operator authority` and `Emulator faults exercise existing authenticated production paths`; Scenarios `A diagnostic caller supplies foreign authority`, `A diagnostic owner exits or its window expires`, `A current startup mutation meets a real lock holder`, `State reply loss is scoped to one owned target` and `One authenticated uninstall transport fails before admission`.
Unavailable observation: Fresh signed-kit QEMU admission, actual kernel identity and SELinux behavior, host disconnect cleanup, JNI UNAVAILABLE retry/cancel, real rejected Settings ACK timeout and uninstall error copy.
Reason: Host fixtures do not execute those Android paths.
Required environment or artifact: The same newly constructed signed kit and the maintained twenty-seven-case Voyemu runtime program.
