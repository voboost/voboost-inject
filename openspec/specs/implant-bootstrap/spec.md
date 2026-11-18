# Implant bootstrap specification

## Purpose

Define generation-bound bootstrap and class loading.

## Requirements

### Requirement: Bootstrap and class loading are generation-bound

The bootstrap envelope SHALL bind PID, process, epoch, generation, catalog digest, core, ordered modules, required artifacts and the initial desired snapshot. The implant SHALL load core first and isolate each module in its own child classloader. Invalid framing, identity, ordering, duplicates or unknown fields SHALL fail before agent initialization.

#### Scenario: Bootstrap names another generation

- **WHEN** a module identity does not belong to the resident generation
- **THEN** the implant loads no Voboost class from that envelope

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_pipe::tests::envelope_is_deterministic_and_preserves_descriptor_order -- --exact
Gate contract: Bootstrap generation mapping.
Maps: Requirement `Bootstrap and class loading are generation-bound`; Scenario `Bootstrap names another generation`.
Preconditions: The daemon test constructs ordered descriptors with a mismatched generation identity.
Observable result: The exact test rejects the mismatched descriptor order and identity before publication.
Evidence boundary: Host Rust logic only; it does not prove in-process ART class loading on an emulator or vehicle.

# Gate: make test-implant-pipe-manifest
Gate contract: Strict bootstrap manifest parsing.
Maps: Requirement `Bootstrap and class loading are generation-bound`; Scenario `Bootstrap names another generation`.
Preconditions: The host C++ parser receives malformed, duplicate, unknown, and invalid manifest inputs.
Observable result: The named parser test rejects each invalid manifest without selecting a core entry.
Evidence boundary: Host parser seam only; it does not execute LSPlant or OEM Java initialization.

### Requirement: Dynamic modules retain exact catalog process bindings

For every selected split module, the daemon SHALL copy the module's complete declared target-process set from the verified catalog into the bootstrap manifest. The strict implant parser SHALL reject an absent, empty, duplicate, or over-bound process set. The implant SHALL pass that set through the pinned `AgentEntry.registerModule` JNI descriptor before initialization, so the Java registry creates the module only for an exact declared process and rejects every other process. Duplicate or conflicting module registration SHALL fail the bootstrap without replacing the first binding.

#### Scenario: A split module is registered for its declared process set

- **WHEN** a verified module declares one or more exact target processes and native bootstrap registers its child classloader
- **THEN** `AgentEntry.create(id, process)` resolution succeeds for each declared process and returns no agent for an undeclared process

#### Scenario: Process binding or registration conflicts

- **WHEN** the bootstrap contains an empty or duplicate process, or a second module registration reuses an ID
- **THEN** registration fails closed without weakening or replacing the original exact-process binding

# Gate: make test-implant-pipe-manifest
Gate contract: Strict split-module process metadata.
Maps: Requirement `Dynamic modules retain exact catalog process bindings`; Scenarios `A split module is registered for its declared process set` and `Process binding or registration conflicts`.
Preconditions: The production manifest parser receives valid, empty, duplicate and malformed process arrays.
Observable result: The exact complete process set is retained for JNI registration, while empty and duplicate bindings are rejected.
Evidence boundary: Host parser seam only; it proves the descriptor supplied to the production JNI path, not ART method invocation or Java factory creation.

# Unverified: ART split-module registration

### Requirement: Bootstrap construction is memory-bounded

The signed release MAY contain up to 256 MiB across different targets, but one process bootstrap SHALL contain at most 64 MiB aggregate core, module and artifact payload. Before opening any payload, the daemon SHALL derive the exact `VBOOST1` wire length from signed descriptors with checked arithmetic, reject an invalid, overflowing or over-bound layout, and make one fallible exact reservation for the final envelope. It SHALL then re-open and re-verify each immutable-generation file at use time and append that one file directly in descriptor order. Construction SHALL retain no complete payload collection beside the final envelope; its additional payload storage is at most the current individually bounded file. A descriptor or read size mismatch or allocation failure SHALL fail before injection. The implant SHALL enforce the same aggregate cap from the header before allocating the manifest or files.

#### Scenario: Process payload reaches its aggregate boundary

- **WHEN** checked signed descriptors total exactly 64 MiB and every use-time read still matches its descriptor
- **THEN** construction is admitted with one exact envelope reservation and preserves core, module and artifact order

#### Scenario: Process payload exceeds its aggregate boundary

- **WHEN** descriptors total more than 64 MiB, overflow arithmetic or the receiver header advertises an over-bound total
- **THEN** daemon and implant reject the bootstrap before payload allocation or target initialization

#### Scenario: Envelope allocation or use-time verification fails

- **WHEN** exact reservation fails or one sequential read differs in size or digest
- **THEN** no injection begins and no partially constructed envelope is retained for retry

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_pipe::tests::manifest_budget_accepts_n_minus_one_and_n_but_rejects_n_plus_one -- --exact
Gate contract: Aggregate descriptor budget.
Maps: Requirement `Bootstrap construction is memory-bounded`; Scenarios `Process payload reaches its aggregate boundary` and `Process payload exceeds its aggregate boundary`.
Preconditions: The exact Rust test supplies N-1, N, N+1, and overflowing descriptor totals.
Observable result: N-1 and N are admitted while N+1 and overflow are rejected before construction.
Evidence boundary: Host Rust arithmetic and reservation policy; it does not measure Android process memory.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::bootstrap_use_time_read_rejects_absent_symlink_mode_size_hash_and_tamper -- --exact
Gate contract: Sequential payload verification.
Maps: Requirement `Bootstrap construction is memory-bounded`; Scenario `Envelope allocation or use-time verification fails`.
Preconditions: The exact Rust test mutates or substitutes one payload at its use-time read boundary.
Observable result: The read fails closed before injection authority is returned.
Evidence boundary: Host filesystem and Rust construction logic; allocation failure injection and target delivery are not exercised.


Maps: Requirement `Bootstrap construction is memory-bounded`; Scenario `Process payload exceeds its aggregate boundary`.
Preconditions: The host C++ receiver reads hostile headers and bounded pipe input.
Observable result: The named test rejects over-bound or malformed framing before consuming a payload body.
Evidence boundary: Host receiver seam only; arm64, armv7, and vehicle execution remain outside this gate.

### Requirement: Pending bootstrap retry authority is frozen

A pending result SHALL transfer the envelope into retry ownership without an envelope-sized clone. Retry ownership SHALL freeze the exact verified generation and catalog authority, complete ordered process agent-ID set, desired semantic document, monotonic document generation and verified native release manifest used by the original envelope. Re-attestation and payload verification SHALL use only that frozen authority. Before either check, the current daemon-owned desired state SHALL exist and exactly match the frozen resident generation and catalog, document generation, ordered IDs and semantic bytes. If that state is absent, or the active generation, catalog, enabled process IDs, desired semantics or document generation changes before retry, the daemon SHALL cancel the retained retry fail-closed and wait for a natural process restart. An A(n) to B(n+1) to A(n+2) transition SHALL not revive A(n), and retained bytes SHALL never be authorized with replacement IDs or catalog policy.

#### Scenario: Pending authority changes before retry

- **WHEN** a pending bootstrap was built for mixed, Forced-EV-only, enabled or generation-R1 semantics and the current plan or generation changes to the opposite policy, disables an agent or activates R2
- **THEN** the daemon cancels the retained retry and does not re-attest or verify its bytes through the replacement agent set, catalog or native release authority

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::pending_retry_aba_document_generation_cancels_frozen_authority -- --exact
Gate contract: ABA retry rejection.
Maps: Requirement `Pending bootstrap retry authority is frozen`; Scenario `Pending authority changes before retry`.
Preconditions: The exact Rust test advances desired-state generation through an A-B-A sequence.
Observable result: The retained A authority is rejected after the generation changes.
Evidence boundary: Host daemon state machine only; no target process is injected.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::pending_retry_r1_to_r2_cancels_frozen_authority -- --exact
Gate contract: Resident generation retry rejection.
Maps: Requirement `Pending bootstrap retry authority is frozen`; Scenario `Pending authority changes before retry`.
Preconditions: The exact Rust test retains R1 bytes and activates R2 before retry.
Observable result: Retry cancels without authorizing R1 through R2 state.
Evidence boundary: Host daemon state machine only; target resident state is not observed.

### Requirement: Bootstrap descriptor and memfd transport has bounded ownership

Envelope delivery SHALL borrow the caller-owned bytes across a scoped writer rather than allocate an envelope-sized thread copy. Writer and target pipe duplicates SHALL be close-on-exec, deadline arithmetic SHALL saturate after scheduler stalls, and materialized memfds SHALL be close-on-exec and sealed against write/grow/shrink. Once payload bytes are materialized, the implant SHALL promptly release envelope vectors. It SHALL close core and module DEX memfds only after the agent seam consumes them, retain ancillary-artifact memfds while the resident generation can open their registered `/proc/self/fd` paths, discard staged replacements on failure without affecting resident artifacts, and close the resident artifact set at process teardown or only after a successful generation replacement.

#### Scenario: Bootstrap transport completes or closes every descriptor

- **WHEN** envelope delivery finishes, fails or stalls past its bounded deadline, or an agent opens an ancillary artifact after initialization has returned
- **THEN** writer duplicates and consumed DEX memfds close on their exact lifecycle while the sealed ancillary fd remains identity-stable and readable for the resident generation without an envelope-sized copy

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::bootstrap_writer_duplicate_is_cloexec -- --exact
Gate contract: Writer descriptor inheritance.
Maps: Requirement `Bootstrap descriptor and memfd transport has bounded ownership`; Scenario `Bootstrap transport completes or closes every descriptor`.
Preconditions: The exact Rust test creates the writer duplicate on the host.
Observable result: The duplicate carries close-on-exec.
Evidence boundary: Host descriptor flags only; Android target adoption is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::bootstrap_writer_transaction_is_only_a_borrowed_slice -- --exact
Gate contract: Borrowed writer payload.
Maps: Requirement `Bootstrap descriptor and memfd transport has bounded ownership`; Scenario `Bootstrap transport completes or closes every descriptor`.
Preconditions: The exact Rust test constructs a writer transaction from an existing envelope.
Observable result: The transaction borrows the envelope slice without an envelope-sized owned copy.
Evidence boundary: Host Rust ownership seam; allocator behavior in an injected process is outside scope.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::implant_contract_deferred_retry_resets_envelope_and_memfds -- --exact
Gate contract: Deferred native cleanup.
Maps: Requirement `Bootstrap descriptor and memfd transport has bounded ownership`; Scenario `Bootstrap transport completes or closes every descriptor`.
Preconditions: The exact Rust test returns the deferred native result with owned envelope and memfd state.
Observable result: Retry state retains only the contractually owned resources and resets consumed state.
Evidence boundary: Host daemon/native contract seam; it does not prove kernel fd lifetime in Android.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::implant_contract_hard_native_failures_release_bootstrap_storage -- --exact
Gate contract: Hard-failure native cleanup.
Maps: Requirement `Bootstrap descriptor and memfd transport has bounded ownership`; Scenario `Bootstrap transport completes or closes every descriptor`.
Preconditions: The exact Rust test returns each hard native failure after bootstrap ownership transfer.
Observable result: Bootstrap storage is released and is not retained for retry.
Evidence boundary: Host daemon/native contract seam; injected-process cleanup is not observed.


Maps: Requirement `Bootstrap descriptor and memfd transport has bounded ownership`; Scenario `Bootstrap transport completes or closes every descriptor`.
Preconditions: The production ownership helper receives DEX and ancillary host descriptors across failed and successful publication.
Observable result: DEX and failed staged descriptors close while the active ancillary descriptor remains readable until replacement.
Evidence boundary: Host C++ ownership seam; sealing, Android `/proc/self/fd`, arm64, armv7, and vehicle behavior remain outside scope.

### Requirement: Bootstrap registers dormant applicable process modules

For interface and hidden startup, a bootstrap SHALL register every applicability-selected non-executor module matching the target process, including currently disabled modules. The desired document SHALL remain limited to effectively enabled agents, so registration SHALL NOT start disabled agents. None mode and disable-all SHALL add no dormant modules; unsupported and unrelated-process modules SHALL be excluded.

#### Scenario: A disabled applicable module is enabled later

- **WHEN** a process bootstraps with one applicable module disabled and its desired enablement changes later
- **THEN** the registry already contains that module while the desired set starts only the enabled modules, and unsupported, unrelated-process, none and disable-all cases remain excluded

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::bootstrap_registers_disabled_applicable_modules_without_starting_them -- --exact

Gate contract: Dormant applicable process module registration.
Maps: Requirement `Bootstrap registers dormant applicable process modules`; Scenario `A disabled applicable module is enabled later`.
Preconditions: The native fixture starts with one enabled and one disabled applicable module in the same process, then flips enablement and exercises exclusion cases.
Observable result: The bootstrap module IDs remain complete across the flip while the desired IDs change, and each excluded case omits its module.
Evidence boundary: Host metadata and selection only; live EN/RU changes require the Voyemu cycle.

### Requirement: Genuine hook backup is published before target activation

The production hook bridge SHALL require the per-hook LSPlant publication extension without falling back to the legacy racy call. It SHALL publish the genuine reflected backup through the existing HookCallback.setBackup(Method) signature before DoHook copies the backup and activates the target entry point. The publisher SHALL run outside SuspendAll; rejection or a pending JNI exception SHALL prevent target activation. The original LSPlant Hook ABI SHALL remain available, and the Java afterreturn setter SHALL remain an idempotent publication. No busy wait, fake original target, new global freeze or permission change is permitted by this boundary.

#### Scenario: A peer invokes the newly activated trampoline

- **WHEN** peer execution resumes after target activation
- **THEN** the genuine backup was already published and is ready before that callback runs

#### Scenario: Backup publication fails

- **WHEN** the publisher rejects or carries an exception
- **THEN** target activation does not run and the failure result or exception is preserved at the transaction boundary

# Gate: make test-lsplant-backup-publication

Gate contract: Actual pinned publication transaction, ordering and required native extension.
Maps: Requirement `Genuine hook backup is published before target activation`; Scenarios `A peer invokes the newly activated trampoline`, `Backup publication fails`.
Preconditions: The exact SHA-verified prepared LSPlant helper supplies the host transaction code; modeled ART activation records publication, backup copy, target activation and peer resume; source checks bind the helper around DoHook and require the production extension and unchanged Java setter signature.
Observable result: Publication precedes backup copy and target activation, the earliest resumed callback sees the copied backup, rejection/exception prevents activation, and activation result/exception is not rewritten. Both native ABIs retain original Hook and new extension exports.
Evidence boundary: Host transaction/source seam and both ABI build; real JNI callback scheduling, font OFF/ON lifecycle and device/vehicle readiness require coordinator-owned runtime acceptance.


### Requirement: Managed startup uses an owned worker

The native staging call SHALL consume the verified envelope and prepare exactly one process-owned worker without entering JNI on the borrowed execution thread. Managed startup SHALL use the worker's own JNI attachment only after a commit correlated with PID, starttime, nonce, generation and catalog has been sent following successful helper exit and safe native restoration and detach. Staging SHALL NOT publish agent readiness. EOF, cancellation or stale authority SHALL prevent later readiness publication without forcibly unwinding managed frames.

#### Scenario: An interrupted OEM resource call continues

- **WHEN** the original OEM thread is inside a native resource operation during staging
- **THEN** it resumes after native restoration and detach before the distinct worker enters JNI, and the worker completes without borrowed managed reentry

# Unverified: Owned-worker Android continuation

### Requirement: Worker control identity and outcomes are closed

Worker control frames SHALL use the exact 160-byte WKSS/WKSC layout and bind each attempt to its process starttime, generation, catalog and unique nonce. Helper failure, incomplete envelope delivery and mismatched authority SHALL deny commit. Terminal records SHALL match the tracked endpoint epoch; replay and late readiness after the observation deadline SHALL be rejected. A deferred worker SHALL retire its old endpoints before a bounded full bootstrap retry.

#### Scenario: Commit is accepted after successful helper completion

- **WHEN** a staged helper exits successfully after safe restoration and detach and the complete envelope writer succeeds
- **THEN** the exact binding authorizes one commit; wrong helper results, failed exits, incomplete writers and mismatched identity deny it

#### Scenario: A stale terminal record cannot publish readiness

- **WHEN** a record uses the wrong process starttime or endpoint epoch, replays a terminal outcome or arrives after the observation deadline
- **THEN** it does not authorize ready status and no managed frame is forcibly stopped

#### Scenario: Deferred cleanup preserves a fresh retry

- **WHEN** a worker finishes deferred and the same live PID retries
- **THEN** cleanup of the old owned descriptors cannot close reused descriptors from the fresh attempt

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_worker::tests::commit_requires_staged_detach_writer_and_exact_identity -- --exact

Gate contract: Closed commit authorization.
Maps: Requirement `Worker control identity and outcomes are closed`; Scenario `Commit is accepted after successful helper completion`.
Preconditions: The production commit binding and successful-helper receipt constructor are exercised with successful and rejected outcomes.
Observable result: Only matching identity, successful staged helper exit and complete writer yield a commit frame.
Evidence boundary: Host Rust policy; actual Android helper restoration and target JNI require runtime evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_worker::tests::terminal_identity_epoch_replay_and_status_barrier -- --exact

Gate contract: Endpoint identity and once-only terminal readiness.
Maps: Requirement `Worker control identity and outcomes are closed`; Scenario `A stale terminal record cannot publish readiness`.
Preconditions: The production registry receives wrong-starttime, wrong-epoch, valid and replayed records.
Observable result: Only the first valid record permits status routing; mismatches and replay are rejected.
Evidence boundary: Host registry and endpoint policy, not Android scheduling.

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_worker::tests::observation_deadline_rejects_late_ready_without_managed_unwind -- --exact

Gate contract: Bounded readiness observation without forced unwind.
Maps: Requirement `Worker control identity and outcomes are closed`; Scenario `A stale terminal record cannot publish readiness`.
Preconditions: The production registry's observation deadline expires before its ready record.
Observable result: Failure is returned and later ready cannot open the status barrier.
Evidence boundary: Host deadline policy; cancellation of real Android work requires runtime evidence.

# Unverified: Deferred worker Android retry

### Requirement: Worker dispatch and channel ownership are once-only

The production worker gate SHALL invoke its managed-work callback at most once for a matching commit. Cancellation before publication SHALL deny readiness. Its channel owner SHALL close each owned descriptor once and SHALL NOT close a later reused descriptor.

#### Scenario: Concurrent commits and cancelled publication

- **WHEN** concurrent callers attempt the same commit or cancellation precedes publication
- **THEN** one work callback runs and cancelled publication does not become ready

#### Scenario: Owned descriptors are retired before reuse

- **WHEN** old owned channels are closed and a descriptor number is reused
- **THEN** repeated old-owner cleanup leaves the new descriptor and unrelated original endpoints open

# Gate: make test-bootstrap-worker

Gate contract: Production native dispatch and owned descriptor cleanup seams.
Maps: Requirement `Worker dispatch and channel ownership are once-only`; Scenarios `Concurrent commits and cancelled publication`, `Owned descriptors are retired before reuse`.
Preconditions: The production native gate and channel owner execute concurrent admission, cancellation, original-lock continuation and descriptor reuse; native decoding consumes a golden frame written by the Rust test.
Observable result: One callback runs after admission, cancelled publication is rejected, closed channels do not close reused descriptors, and malformed frames are rejected.
Evidence boundary: Host C++ dispatch/channel ownership and Rust wire layout; this does not execute the complete Android capsule or Deferred retry path.

### Requirement: Inline ART hook backups precede caller resumption

Native bootstrap SHALL resolve thread, garbage-collection critical-section and suspension prerequisites before installing an ART inline hook. Each inline installation SHALL hold the mutator-exclusive suspension through backend activation and assignment of the genuine LSPlant backup, including its member-function representation. Symbol resolution and JNI calls SHALL remain outside that suspension. A resolver-only handler SHALL reject inline installation, and an already published hook SHALL retain its original backup on repeated admission. A failed preparation SHALL leave the target unactivated and release the suspension scope.

#### Scenario: A caller arrives during inline activation

- **WHEN** a caller attempts to enter the mutator scope at backend activation before the installer returns its genuine original
- **THEN** the caller remains blocked until the actual LSPlant backup is assigned and subsequently invokes the genuine original with unchanged arguments and result

#### Scenario: Preparation fails or admission repeats

- **WHEN** symbol resolution or backend preparation fails, or a previously published hook is admitted again
- **THEN** failed preparation does not activate a replacement, suspension ownership is released, and repeated admission preserves the first genuine backup

# Gate: make test-inline-hook-publication

Gate contract: Production inline-hook suspension and backup assignment ordering.
Maps: Requirement `Inline ART hook backups precede caller resumption`; Scenarios `A caller arrives during inline activation`, `Preparation fails or admission repeats`.
Preconditions: The host test compiles the exact prepared LSPlant HookHandler header, extracts the production suspension wrapper and Dobby installation body, and substitutes host mutator locking and backend dependencies.
Observable result: A caller attempting access at actual backend activation is blocked until the real backup slot is populated; original arguments/results and member representation are retained, Thumb pointer identity survives, failed preparation does not activate, and repeated admission retains the original backup.
Evidence boundary: Host production control flow with simulated ART locks and backend patch dependencies; it does not prove Android suspension, OS code-page faults, or vehicle acceptance.

# Unverified: Inline-hook ART suspension on Android

### Requirement: Bootstrap phases serialize only the same target PID

One process PID SHALL have at most one active two-phase bootstrap across poll and retry callers. Different PIDs SHALL NOT share that serialization lock. PID reuse SHALL remain serialized until the preceding job releases ownership because staged receipts are keyed by PID; every job still reattests the exact target starttime. Lock acquisition failure SHALL fail closed before the first remote call.

#### Scenario: Two callers share a PID while another targets a different PID

- **WHEN** one caller holds the bootstrap lock and two other callers target the same and a different PID
- **THEN** the same PID cannot acquire ownership until release while the different PID can proceed

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::bootstrap_lock_excludes_same_pid_and_allows_different_pid -- --exact

Gate contract: PID-scoped bootstrap ownership.
Maps: Requirement `Bootstrap phases serialize only the same target PID`; Scenario `Two callers share a PID while another targets a different PID`.
Preconditions: An active production lock, a second reference to its PID and a distinct PID worker.
Observable result: Same-PID try-lock fails while a different-PID thread acquires ownership before the first releases it; the shared PID becomes available after release.
Evidence boundary: Host ownership lock; parallel native helper execution, Android detach safety and runtime dispatch require target acceptance.

## Unverified

### Unverified: ART split-module registration

Maps: Requirement `Dynamic modules retain exact catalog process bindings`; Scenario `A split module is registered for its declared process set`.
Unavailable observation: An Android runtime has not executed the production implant JNI call through `AgentEntry.registerModule` and then resolved the registered factory for correct and incorrect process names.
Reason: Host C++ tests cannot instantiate `InMemoryDexClassLoader` or exercise ART JNI, and host Java tests in the producer repository do not prove the native call boundary.
Required environment or artifact: An emulator or supported target process with the built implant, core DEX and at least one split module DEX, plus status evidence for exact-process acceptance and wrong-process rejection.

### Unverified: Owned-worker Android continuation

Maps: Requirement `Managed startup uses an owned worker`; Scenario `An interrupted OEM resource call continues`.
Unavailable observation: A fresh candidate has not yet proved successful helper restoration/detach followed by a distinct attached worker, original OEM progress, complete OEM boot checks and agent readiness.
Reason: Host dispatch and native builds cannot instantiate ART or reproduce the interrupted OEM AssetManager frame.
Required environment or artifact: The next immutable Voyemu candidate, correlated ordinary helper/worker logs and the full functional cycle.

### Unverified: Deferred worker Android retry

Maps: Requirement `Worker control identity and outcomes are closed`; Scenario `Deferred cleanup preserves a fresh retry`.
Unavailable observation: The complete Android worker Deferred path and subsequent same-PID full bootstrap have not run in a current runtime candidate.
Reason: Native channel-owner tests prove local descriptor reuse safety, not target capsule/global cleanup ordering.
Required environment or artifact: A current Android candidate with correlated worker terminal outcome, endpoint retirement and successful same-PID retry.

### Unverified: Inline-hook ART suspension on Android

Maps: Requirement `Inline ART hook backups precede caller resumption`; Scenario `A caller arrives during inline activation`.
Unavailable observation: The new native closure has not yet completed owned-worker bootstrap and concurrent OEM class loading without the observed Launcher native crash on Android.
Reason: Host mutator simulation and official ART source contracts do not execute the guest suspension primitives or establish runtime ELF identity.
Required environment or artifact: A new immutable Android candidate with exact ART and LSPlant identity, ordinary native bootstrap diagnostics and complete functional verification; supported OEM runtime acceptance remains separate.
