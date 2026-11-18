# Daemon lifecycle specification

## Purpose

Define daemon ownership, kill-switch behavior and safe generation retention.

## Requirements

### Requirement: One init-managed daemon owns the runtime

Android init SHALL launch `/data/voboost/voboost-daemon` directly as root in `u:r:voboost:s0`. The `voboost-daemon` service SHALL be neither `oneshot` nor `disabled`; init owns crash restart.

#### Scenario: The daemon exits after boot

- **WHEN** the service process exits
- **THEN** init may relaunch the stable path without rebooting multimedia

# Unverified: Target init supervision

### Requirement: One resident poll preserves operation exclusion and adoption order

Each resident daemon iteration SHALL first observe in-memory frozen, durable prepared and requested uninstall authority. When none exists it SHALL poll the descriptor-only product OTA socket, recover a durable product activation, adopt a changed verified active generation before considering incoming activation, execute the runtime poll, and run log cleanup only when the iteration does not hand off a product reboot. When any uninstall authority exists it SHALL perform neither OTA polling nor incoming activation while product recovery and runtime observation remain reachable.

#### Scenario: Uninstall authority appears before incoming activation

- **WHEN** any one of the frozen, prepared or requested uninstall authorities is present
- **THEN** OTA polling and incoming activation are skipped while product recovery and runtime observation continue

#### Scenario: Runtime poll requests update reboot

- **WHEN** the runtime poll returns the durable reboot disposition
- **THEN** the iteration returns reboot handoff without running post-poll log cleanup

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::production_daemon_iteration_excludes_activation_for_every_uninstall_authority -- --exact

Gate contract: Resident operation exclusion.
Maps: Requirement `One resident poll preserves operation exclusion and adoption order`; Scenario `Uninstall authority appears before incoming activation`.
Preconditions: The production iteration receives each uninstall authority independently and together through strict fake actions.
Observable result: OTA and incoming activation are never called, while product recovery, generation comparison and runtime polling remain reachable.
Evidence boundary: Host orchestration; persistent Android files and concurrent processes are modeled by exact boolean authorities.

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::production_daemon_iteration_adopts_before_activation_and_runtime_poll -- --exact

Gate contract: Resident generation adoption order.
Maps: Requirement `One resident poll preserves operation exclusion and adoption order`; Scenario `Uninstall authority appears before incoming activation`.
Preconditions: The active generation differs and no uninstall authority exists.
Observable result: The actual iteration calls OTA, generation comparison, adoption, activation and runtime poll in exact order.
Evidence boundary: Host strict-action orchestration; generation bytes are covered by generation tests.

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::production_daemon_iteration_returns_reboot_without_post_poll_cleanup -- --exact

Gate contract: Resident reboot handoff boundary.
Maps: Requirement `One resident poll preserves operation exclusion and adoption order`; Scenario `Runtime poll requests update reboot`.
Preconditions: The production iteration receives `RebootForUpdate` from the real runtime disposition type.
Observable result: It returns the reboot disposition and does not execute log cleanup after the handoff point.
Evidence boundary: Host orchestration; Android property service and physical reboot remain unverified.

### Requirement: Daemon singleton authority is descriptor-bound

The resident owner SHALL enforce its singleton through `/data/voboost/run/daemon.pid`; the injection producer SHALL enforce its separate singleton through `/data/voboost/run/inject.pid`. The two roles MAY coexist, but a second process for either role SHALL fail while that role retains its lock. The injection orchestration loop SHALL remain synchronous. Both roles SHALL require `/data/voboost` and `/data/voboost/run` to be root-owned mode-0755 directories, creating only a missing run entry within an already verified root-zone descriptor. Each role SHALL retain its singleton before initializing its logger or request transport. It SHALL open or create its fixed pid basename relative to the retained descriptor without following links, require a root-owned mode-0600 single-link regular file, and retain directory and locked-file descriptors for its process lifetime. PID truncation, write and fsync SHALL use the locked descriptor; named-file and directory identity SHALL be checked before and after publication. Directory or leaf substitution, symlinks, hard links, foreign ownership, unexpected modes and special files SHALL fail closed.

#### Scenario: Runtime lock authority is substituted

- **WHEN** a directory or pidfile name no longer resolves to the retained verified inode
- **THEN** startup or the serialized CLI operation fails without writing through the substituted path

#### Scenario: Owner and injection singletons coexist independently

- **WHEN** the owner and injection producer retain their distinct current-contract pid locks
- **THEN** each excludes only its own replacement, and replacing injection does not release the owner lock

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject pidfile::tests::never_reopens_pidfile_name_for_truncate_or_write -- --exact
Gate contract: Locked pidfile publication.
Maps: Requirement `Daemon singleton authority is descriptor-bound`; Scenario `Runtime lock authority is substituted`.
Preconditions: The exact Rust test substitutes the pidfile pathname after the daemon retains and locks the original descriptor.
Observable result: PID truncation and write remain on the retained inode and never reopen the substituted name.
Evidence boundary: Host filesystem descriptor behavior; Android init concurrency is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject pidfile::tests::rejects_run_directory_path_swap -- --exact
Gate contract: Retained run-directory identity.
Maps: Requirement `Daemon singleton authority is descriptor-bound`; Scenario `Runtime lock authority is substituted`.
Preconditions: The exact Rust test swaps the named run directory after retaining its verified descriptor.
Observable result: Publication detects the directory identity mismatch and fails without writing through the replacement path.
Evidence boundary: Host directory-inode checks; target mount and SELinux behavior are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::singleton_authority_precedes_logger_and_failure_never_initializes_logging -- --exact
Gate contract: Singleton authority precedes logger side effects.
Maps: Requirement `Daemon singleton authority is descriptor-bound`; Scenario `Runtime lock authority is substituted`.
Preconditions: The startup seam records pidfile and logger initialization order and injects a failed singleton acquisition.
Observable result: Successful startup acquires the pidfile authority before logger initialization, while failed acquisition never invokes the logger.
Evidence boundary: Host startup dispatch; Android init umask and live socket publication require target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon pidfile::tests::owner_and_inject_have_independent_exclusive_lifetimes -- --exact

Gate contract: Distinct current owner and injection singleton lifetimes.
Maps: Requirement `Daemon singleton authority is descriptor-bound`; Scenario `Owner and injection singletons coexist independently`.
Preconditions: The real shared pidfile acquisition implementation uses current OWNER_PID_NAME and INJECT_PID_NAME in a retained host directory fixture.
Observable result: Both locks coexist, duplicate role acquisition fails, and injection replacement leaves the owner exclusive.
Evidence boundary: Host descriptor locks and current contract constants; installed Android services and SELinux execution require runtime evidence.

### Requirement: Installer-owned handoffs cannot race generation recovery

Init MAY start the installer and daemon concurrently after either install reboot. While the exact verified operation is in an installer-owned phase — `install-reboot-first`, `install-reboot-second`, `install-runtime-verify`, `install-inventory-commit` or `install-cleanup` with the exact outcome and reboot count for that phase — the daemon SHALL perform no generation recovery, runtime, OTA or unrelated work. It SHALL request only the fixed `voboost-install` service and re-read the signed operation/WAL authority with exponential backoff from 50 milliseconds to a one-second cap. `install-agents` is deliberately excluded because the daemon is the required generation authority there. Once the installer publishes `install-agents` after the first reboot, normal generation activation SHALL continue and publish its acknowledgement; after the second reboot, normal daemon startup SHALL wait until installer verification and cleanup complete. A malformed, failed, foreign or otherwise different operation SHALL never enter this waiting path and SHALL retain the ordinary fail-closed recovery behavior.

#### Scenario: Init starts daemon before installer continuation acquires the lease

- **WHEN** the daemon observes the exact first-reboot install handoff before the installer advances the WAL
- **THEN** it does not acquire generation authority, retries only the fixed installer service, and begins generation activation only after `install-agents` is durably visible

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::installer_owned_handoff_restarts_only_the_fixed_installer_with_capped_backoff -- --exact
Gate contract: Installer-owned handoff serialization.
Maps: Requirement `Installer-owned handoffs cannot race generation recovery`; Scenario `Init starts daemon before installer continuation acquires the lease`.
Preconditions: The startup seam classifies first-reboot, generation-owned, second-reboot, cleanup and failed states, then observes three exact installer-owned states followed by a generation-authorized phase.
Observable result: Only the fixed installer request is emitted three times, waits grow from 50 to 100 to 200 milliseconds, and the loop exits before generation recovery.
Evidence boundary: Host scheduling seam; Android property delivery, init ordering and live WAL progression require target evidence.

### Requirement: Kill switch disables future activation only

The root-owned kill switch SHALL prevent new injection and activation without killing OEM processes, rebooting multimedia or hiding diagnostics.

#### Scenario: Kill switch becomes active

- **WHEN** a new target process is discovered
- **THEN** no injection is attempted and existing OEM processes continue

# Gate: cargo test --manifest-path daemon/Cargo.toml safety::tests::kill_switch_active_when_plan_disable_all -- --exact
Gate contract: Kill-switch injection admission.
Maps: Requirement `Kill switch disables future activation only`; Scenario `Kill switch becomes active`.
Preconditions: The exact Rust test activates `disableAll` in the daemon safety plan before target admission.
Observable result: The safety decision blocks new injection without producing process-termination authority.
Evidence boundary: Host safety-plan logic; OEM process continuation is not observed on Android.

### Requirement: Garbage collection preserves every live reference

Generation cleanup SHALL protect `current`, `previous`, resident generation identities and recent generation directories within the grace window. The `current` and `previous` pointers SHALL be root-owned, single-link, immutable mode-`0444` files containing exactly one lowercase generation SHA-256 plus LF; daemon activation and installer acknowledgement verification SHALL use the same mode. Startup SHALL verify every digest-named retained immutable generation and compute live target processes from the union of all their signed catalogs, including generations older than `previous`; it SHALL NOT derive liveness only from the active catalog. A malformed retained generation or any live union target without a verified resident-generation identity SHALL defer all removal. Rejected imports SHALL be quarantined with bounded retention. A cleanup error SHALL defer removal rather than broaden its target.

At catalog cutover and retained-authority cleanup, daemon-lifetime safety maps SHALL retain only agent/process identities reachable from the current catalog or a live resident/pending generation. Obsolete attempt, quarantine, crash and degraded entries SHALL be removed so repeated signed catalog rotations cannot grow memory without bound, while live resident safety state remains intact.

#### Scenario: A retired generation may still be resident

- **WHEN** its age is inside the grace window or a live endpoint identifies it
- **THEN** cleanup preserves it

#### Scenario: An older retained catalog names a process dropped by current

- **WHEN** that process remains live after multiple catalog cutovers and the daemon restarts
- **THEN** startup includes it in resident discovery and does not garbage-collect its exact verified generation

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::generation_pointers_use_the_same_readonly_mode_as_installer_verification -- --exact
Gate contract: Generation pointer mode agreement.
Maps: Requirement `Garbage collection preserves every live reference`.
Preconditions: Two verified generations are activated so both `current` and `previous` pointers are published.
Observable result: Both pointer files use the immutable mode `0444` required by installer acknowledgement verification.
Evidence boundary: Host filesystem mode and pointer rotation; Android init and live generation loading require target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::retained_generation_scan_includes_beyond_previous_and_fails_closed_on_corruption -- --exact
Gate contract: Retained catalog discovery closure.
Maps: Requirement `Garbage collection preserves every live reference`; Scenario `An older retained catalog names a process dropped by current`.
Preconditions: The exact Rust test retains verified generations beyond `previous` and also supplies a corrupt retained generation.
Observable result: Verified older catalogs join discovery while corruption fails closed before removal authority.
Evidence boundary: Host generation inventory; live Android process enumeration is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::generation_gc_defers_when_any_live_resident_identity_is_unknown -- --exact
Gate contract: Unknown resident generation defers collection.
Maps: Requirement `Garbage collection preserves every live reference`; Scenario `A retired generation may still be resident`.
Preconditions: The exact Rust test reports a live union target without a verified resident-generation identity.
Observable result: Garbage collection removes no retained generation.
Evidence boundary: Host daemon reconciliation; target resident identity observation is simulated.

# Gate: cargo test --manifest-path daemon/Cargo.toml safety::tests::catalog_pruning_bounds_rotated_identities_and_preserves_active_state -- --exact
Gate contract: Bounded safety-map catalog pruning.
Maps: Requirement `Garbage collection preserves every live reference`; Scenarios `A retired generation may still be resident` and `An older retained catalog names a process dropped by current`.
Preconditions: The exact Rust test rotates catalogs while retaining active resident safety state and obsolete identities.
Observable result: Obsolete identities are pruned to a bounded set while active resident state is preserved.
Evidence boundary: Host in-memory safety maps; long-running target memory behavior is not measured.
### Requirement: Uninstall requests arrive over exactly two attested channels

A resident uninstall request SHALL originate either from the stable desktop CLI's exact empty file in the root-owned run area or from the Settings host's `uninstall-request` RPC on the fixed daemon socket `/data/voboost/run/daemon.sock`. The socket RPC SHALL be admitted only when SO_PEERCRED reports the system uid and the peer's exact process is `com.qinggan.app.setting`; every other peer SHALL receive `wrong-peer` and no request SHALL be recorded. A second request while one is unconsumed or a prepared uninstall is committed SHALL answer `busy` and change nothing. No user-space application file SHALL participate in the request contract.

#### Scenario: The Settings host delivers one accepted request

- **WHEN** the attested Settings process sends `uninstall-request` and no request is unconsumed
- **THEN** the daemon records the in-memory request, the runtime poll observes it, and a duplicate answers `busy`

#### Scenario: The desktop file keeps priority over install work

- **WHEN** the desktop CLI publishes its exact empty request file
- **THEN** the install worker stops before its next mutation and the daemon runtime observes the request

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::socket_rpc_uninstall_attests_the_peer_and_stays_busy_idempotent -- --exact

Gate contract: Attested uninstall RPC dispatch.
Maps: Requirement `Uninstall requests arrive over exactly two attested channels`; Scenario `The Settings host delivers one accepted request`.
Preconditions: The fake Settings peer verifier and the pure RPC dispatcher.
Observable result: Wrong-peer never records a request, the attested peer is accepted once, retry answers busy, and unknown operations are stream errors.
Evidence boundary: Dispatcher logic; real socket, SO_PEERCRED and SELinux require the live daemon.

# Gate: cargo test --manifest-path install/Cargo.toml tests::explicit_uninstall_request_stops_the_driver_before_any_mutation -- --exact

Gate contract: Desktop uninstall preempts install work.
Maps: Requirement `Uninstall requests arrive over exactly two attested channels`; Scenario `The desktop file keeps priority over install work`.
Preconditions: The scripted install driver fixture.
Observable result: The journal phase does not advance after the fence appears.
Evidence boundary: Host install worker logic only.

### Requirement: Injection jobs preserve one synchronous control owner

The synchronous daemon loop SHALL dispatch all available process injection jobs without waiting for another process to finish, ordered by the catalog-derived `startupPriority` (`vehicle`, `interface`, `applications`, `background`). Fresh and pending targets SHALL share that ordering, with pending targets admitted first within an equal priority. No absent process or agent readiness barrier SHALL delay dispatch. One PID SHALL have at most one active job across both bootstrap phases, including PID reuse. Each job SHALL receive immutable target and generation authority and one complete process bootstrap envelope; only the daemon loop SHALL adopt returned endpoints, update trackers, publish status or schedule retries.

#### Scenario: Several targets are available while one injection blocks

- **WHEN** targets of different priorities and a pending retry are ready and one target's worker blocks
- **THEN** all distinct PIDs are dispatched in priority order, the retry is admitted, and the synchronous owner can service an endpoint before the blocked worker finishes

#### Scenario: A second job addresses an active PID

- **WHEN** another request addresses the same PID, including a different starttime
- **THEN** it is refused until the complete existing job has been joined

# Gate: cargo test --manifest-path daemon/Cargo.toml injection_jobs::tests::distinct_targets_overlap_and_owner_services_while_blocked -- --exact
Gate contract: Concurrent process jobs with a synchronous owner.
Maps: Requirement `Injection jobs preserve one synchronous control owner`; Scenario `Several targets are available while one injection blocks`.
Preconditions: Host workers for four distinct PIDs wait on explicit release channels while the owner services a pipe.
Observable result: Every worker starts before release, endpoint service completes while jobs remain active, and every result is joined.
Evidence boundary: Real host threads and pipes; Android helpers, ptrace and vehicle readiness are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml injection_jobs::tests::same_pid_is_excluded_until_join_even_after_worker_finishes -- --exact
Gate contract: PID-scoped job lifetime.
Maps: Requirement `Injection jobs preserve one synchronous control owner`; Scenario `A second job addresses an active PID`.
Preconditions: A host job retains one PID through worker completion and owner collection.
Observable result: Duplicate dispatch is refused before and after worker completion until collection joins it; another PID proceeds.
Evidence boundary: Host job ownership; native per-PID bootstrap serialization has its separate injector gate.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::bootstrap_and_rebind_admission_share_one_pid_owner -- --exact
Gate contract: Shared bootstrap and rebind PID admission.
Maps: Requirement `Injection jobs preserve one synchronous control owner`; Scenario `A second job addresses an active PID`.
Preconditions: An owned host bootstrap job, then an owned rebind job, block on explicit release channels for the same PID.
Observable result: Duplicate bootstrap admission preserves the original job, and a rebind-owned PID refuses bootstrap dispatch until collection joins it.
Evidence boundary: Host root admission and real worker ownership; native operations are modeled.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::collected_completion_suppresses_stale_appearance_without_rebinding -- --exact
Gate contract: Completion collection fences stale appearance snapshots.
Maps: Requirement `Injection jobs preserve one synchronous control owner`; Scenario `A second job addresses an active PID`.
Preconditions: A host completion has just adopted its real endpoints while a pass-local appearance still lists the same PID.
Observable result: Fresh admission preserves that endpoint and status and starts neither another bootstrap nor a rebind job.
Evidence boundary: Host completion/admission integration; Android discovery timing is not measured.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime_loop::tests::mixed_startup_batch_admits_retries_by_priority_without_waiting -- --exact
Gate contract: Combined fresh and retry admission.
Maps: Requirement `Injection jobs preserve one synchronous control owner`; Scenario `Several targets are available while one injection blocks`.
Preconditions: Ready fresh and retry entries span every startup priority and include equal-priority peers.
Observable result: Vehicle entries dispatch first and a retry precedes equal-priority fresh entries without waiting for completion.
Evidence boundary: Host dispatcher ordering; target discovery and Android worker latency remain target evidence.

### Requirement: Injection ownership survives stale results and terminal fences

Before adopting a job result, the daemon SHALL revalidate the frozen target identity and generation/catalog/document authority. A stale target completion SHALL close its owned descriptors without overwriting a replacement endpoint. A successfully loaded or staged result for the same exact target after a generation or document cutover SHALL retain a controlled endpoint under its original verified resident authority, receive the latest resident desired projection, and SHALL NOT be relabeled or publish stale failure/readiness as replacement-generation status. Old-generation Settings mutations SHALL remain forbidden. A deferred envelope SHALL NOT be retried under changed authority. An activation freeze, uninstall preparation, committed `startup: none`, native reboot handoff or SIGTERM SHALL stop new admissions and join every active injection job before releasing daemon ownership. Waiting for ordinary helper cleanup SHALL continue servicing tracked pipes; an in-flight native operation SHALL NOT be abandoned by dropping a thread handle or terminating its owner. Ordinary helper deadlines SHALL still terminate failed helpers; expiration of a reap deadline SHALL retain child ownership until terminal observation rather than authorize an unproved handoff.

#### Scenario: Authority changes while a job is running

- **WHEN** the target starttime changes, or an unsuccessful result's generation, catalog or desired document changes before completion
- **THEN** the old result is rejected and its descriptors close without overwriting replacement tracking or status

#### Scenario: A completed resident belongs to an older generation

- **WHEN** native loading or staging completed for an unchanged target while its desired generation changed
- **THEN** its endpoint remains controlled under the original verified resident generation, receives the latest resident desired projection including empty uninstall cleanup, and staged work is observed until its terminal result without retrying the obsolete envelope

#### Scenario: A product update could replace in-flight native inputs

- **WHEN** process jobs still own native helper operations
- **THEN** the synchronous iteration defers OTA admission and product recovery while continuing runtime service, and permits product mutation again after every job is joined

#### Scenario: A terminal fence arrives while a worker is blocked

- **WHEN** a stop or freeze begins with an active job
- **THEN** further admissions fail, endpoint service continues, and the fence returns only after the worker has completed and been joined

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::stale_completion_closes_endpoints_without_tracking_or_replacement_status -- --exact
Gate contract: Stale-result endpoint ownership.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `Authority changes while a job is running`.
Preconditions: Host completion fixtures reuse a target PID or return unsuccessful outcomes after generation, catalog or document changes, with real pipe descriptors.
Observable result: A reused-PID result preserves the replacement registration; unsuccessful obsolete-authority results publish no replacement status, and every unadopted descriptor closes.
Evidence boundary: Host root adoption and descriptor ownership; live Android identity changes remain target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml injection_jobs::tests::freeze_rejects_admission_and_drains_before_owner_drop -- --exact
Gate contract: Terminal job drain.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A terminal fence arrives while a worker is blocked`.
Preconditions: A host job is blocked while the owner closes admissions and services its release pipe.
Observable result: New work is refused, service runs while the job is active, and drain joins the worker before owner drop.
Evidence boundary: Host worker lifetime; Android cleanup/detach, update, uninstall, init and physical reboot require target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::unsafe_cleanup_fences_admission_even_when_target_identity_is_stale -- --exact
Gate contract: Unsafe cleanup never opens replacement admission.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `Authority changes while a job is running`.
Preconditions: A host completion reports unproved native cleanup after target identity changed.
Observable result: Both bootstrap and rebind admissions close, the root becomes degraded, and owned descriptors close without publishing a replacement endpoint.
Evidence boundary: Host completion policy; live helper cleanup and ptrace detach require target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::reap_deadline_retains_ownership_until_terminal_observation -- --exact
Gate contract: A reap deadline is not release authority.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A terminal fence arrives while a worker is blocked`.
Preconditions: The production child-retention loop sees an expired deadline, a still-running observation and an interrupted observation before terminal exit.
Observable result: It reports the deadline once, retains ownership through both waits, and returns only after terminal observation.
Evidence boundary: Host modeled wait observations; real child termination is covered separately and Android ptrace cleanup remains unverified.

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::bootstrap_abort_preserves_unsafe_cleanup_failure -- --exact
Gate contract: Abort failure propagation.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A terminal fence arrives while a worker is blocked`.
Preconditions: The native abort result mapper receives unsafe cleanup and ordinary terminal results.
Observable result: Unsafe cleanup remains distinct while ordinary abort outcomes retain the original initialization failure classification.
Evidence boundary: Host result mapping; native abort execution remains target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::changed_generation_completion_keeps_old_resident_control_and_delivers_empty_desired -- --exact
Gate contract: Controlled old-generation completion.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A completed resident belongs to an older generation`.
Preconditions: A successful host result carries an original verified generation while the owner has adopted a replacement and an uninstall cleanup projection.
Observable result: Its endpoint remains bound to the original generation, the active status identity remains the replacement, and the real downlink receives an empty desired frame under resident authority.
Evidence boundary: Host root adoption and Unix stream delivery; managed Android cleanup is not executed.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::staged_old_generation_remains_controlled_until_terminal_outcome -- --exact
Gate contract: Staged resident cutover ownership.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A completed resident belongs to an older generation`.
Preconditions: A staged host result owns a binding and endpoint after active-generation cutover.
Observable result: The old authority is retained while pending, the exact terminal receipt is accepted, and readiness observation preserves the controlled endpoint without re-injecting its envelope.
Evidence boundary: Host binding registry and root retry path; Android worker scheduling and hooks are not executed.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::uninstall_freeze_joins_active_jobs_before_returning -- --exact
Gate contract: Explicit uninstall freeze owns pending worker completion.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A terminal fence arrives while a worker is blocked`.
Preconditions: A real host worker remains blocked when the public runtime uninstall freeze is set.
Observable result: Freeze returns only after joining the worker, leaves no active native jobs, and keeps admissions closed.
Evidence boundary: Host public freeze path; durable prepared retry, Android init and physical uninstall remain unverified.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::terminal_drain_services_real_state_reply_before_joining_blocked_job -- --exact
Gate contract: Runtime service during terminal cleanup.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A terminal fence arrives while a worker is blocked`.
Preconditions: A blocked host injection worker can finish only after a tracked Settings client receives a real state reply.
Observable result: Production terminal drain services the request and flushes its reply before joining the worker, then returns with no active jobs and admissions closed.
Evidence boundary: Host runtime, state router and Unix streams; real helper detach is not executed.

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::active_injection_jobs_fence_native_product_mutations_but_keep_runtime_service -- --exact
Gate contract: Native-input mutation exclusion.
Maps: Requirement `Injection ownership survives stale results and terminal fences`; Scenario `A product update could replace in-flight native inputs`.
Preconditions: The production iteration receives active-job and joined-job states through its strict action seam.
Observable result: Active jobs exclude OTA and product recovery while runtime service remains reachable; joined jobs permit both product operations again.
Evidence boundary: Host iteration dispatch; Android filesystem replacement, helper reads and live OTA remain target evidence.

# Unverified: Android concurrent injection lifecycle

### Requirement: Startup none closes Android APK execution admission

Committed none SHALL disable the signed installed `ru.voboost` package for the supported user0-only profile, cancel all its scheduled jobs, force-stop its UID and independently confirm disabled state, nonexistent ActivityManager UID and absence of periodic job0x5642 before final Settings completion and init self-stop. Failure SHALL keep the resident alive for bounded-command retry without successful none confirmation. Canonical none with a stopped daemon SHALL remain admissible to installer startup recovery; a stopped interface/hidden daemon or unavailable daemon identity SHALL not gain that admission. Installer recovery SHALL invalidate the previous execution receipt under GenerationGuard before committing interface or hidden, then start the init-owned daemon. Only that runtime SHALL re-enable the APK and require the fixed ordered receiver's successful JobScheduler registration acknowledgement. Vehicle injections SHALL dispatch before enabled-APK recovery. Package operations SHALL run in one owned bounded worker; the main poll SHALL continue registration, native completion collection, pipe reads and desired-state processing while it is pending. Changed generation or mode SHALL cancel between fixed commands; shutdown, uninstall and update terminal paths SHALL cancel and join owned package work before releasing authority or exiting. A cached receipt SHALL bind the active generation, signed manifest, kernel boot and mode; a CLI confirmation SHALL require both fresh resident status and current execution receipt. Unavailable Android services, wrong identity, denied operation, timeout, missing scheduler acknowledgement and stale receipt SHALL not become success. An interrupted mutation SHALL converge from the canonical mode on the next resident pass. Activation-frozen updates SHALL retain existing update/reboot ordering and reconcile execution after restart; a package replacement SHALL not grant APK authority to change root mode.

#### Scenario: A previous execution receipt is stale

- **WHEN** generation, manifest, boot or startup mode differs or the receipt has missing or unknown fields
- **THEN** management cannot confirm APK execution admission from it

#### Scenario: Pending or denied package admission

- **WHEN** a package service is pending or denies mutation
- **THEN** runtime none completion and management success remain unconfirmed while main-poll callbacks continue independently

#### Scenario: Installed APK execution boundary in Enforcing

- **WHEN** the installed supported profile enters none and later recovers through the packaged installer in Enforcing
- **THEN** actual package processes and jobs are absent across reboot in none, recovery restores the scheduler, and vehicle endpoint processing continues independently of package-service latency

#### Scenario: Canonical none has stopped its daemon

- **WHEN** management classifies daemon identity for canonical none, interface and hidden
- **THEN** a verified running daemon is admitted for each mode, a stopped daemon is admitted only for none, and unavailable identity is rejected

# Gate: cargo test --manifest-path daemon/Cargo.toml package_execution::tests::apk_execution_confirmation_rejects_each_stale_authority -- --exact
Gate contract: Startup receipt authority.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `A previous execution receipt is stale`.
Preconditions: Current daemon host receipt parser and exact policy source compile.
Observable result: Every stale identity or malformed receipt is rejected and only the complete matching authority is accepted.
Evidence boundary: Host receipt parser only; package mutation, jobs, process absence, crash convergence, startup latency and Enforcing require installed emulator checks.


# Gate: cargo test --manifest-path shared/Cargo.toml package_execution::tests::every_interrupted_disable_retries_to_closed_state -- --exact
Gate contract: Fixed APK execution adapter and interruption convergence.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `A previous execution receipt is stale`.
Preconditions: The shared crate host tests use the fixed command adapter with scripted failures and root cancellation.
Observable result: Each interrupted disable remains unconfirmed and retry converges to a closed package state.
Evidence boundary: Host scripted service adapter, not live Android package services or Enforcing.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::package_execution_denial_prevents_management_status_confirmation -- --exact
Gate contract: Management refuses successful status after admission denial.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Pending or denied package admission`.
Preconditions: The named production admission gate or owned worker is executed by its host regression fixture.
Observable result: Management refuses successful status after admission denial.
Evidence boundary: Host production gate and simulated service/callback fixture; installed Android service and real vehicle readiness are not proved.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::package_execution_pending_and_denied_never_complete_none_or_stop_service -- --exact
Gate contract: Runtime refuses final none after pending or denied admission.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Pending or denied package admission`.
Preconditions: The named production admission gate or owned worker is executed by its host regression fixture.
Observable result: Runtime refuses final none after pending or denied admission.
Evidence boundary: Host production gate and simulated service/callback fixture; installed Android service and real vehicle readiness are not proved.

# Gate: cargo test --manifest-path daemon/Cargo.toml package_execution::worker_tests::held_package_service_does_not_block_vehicle_registration_reads_or_completion -- --exact
Gate contract: Owned package worker leaves caller callbacks unblocked.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Pending or denied package admission`.
Preconditions: The named production admission gate or owned worker is executed by its host regression fixture.
Observable result: Owned package worker leaves caller callbacks unblocked.
Evidence boundary: Host production gate and simulated service/callback fixture; installed Android service and real vehicle readiness are not proved.

# Gate: cargo test --manifest-path daemon/Cargo.toml package_execution::worker_tests::changed_generation_cancels_old_operation_and_never_confirms_it -- --exact
Gate contract: Old worker cancellation cannot confirm a new generation.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Pending or denied package admission`.
Preconditions: The named production admission gate or owned worker is executed by its host regression fixture.
Observable result: Old worker cancellation cannot confirm a new generation.
Evidence boundary: Host production gate and simulated service/callback fixture; installed Android service and real vehicle readiness are not proved.


# Unverified: Native APK execution in Enforcing
# Gate: cargo test --manifest-path daemon/Cargo.toml management::package_execution_stopped_none_preserves_installer_recovery_admission -- --exact
Gate contract: Canonical stopped none retains installer recovery admission.
Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Canonical none has stopped its daemon`.
Preconditions: The production management classifier is evaluated for every supported startup mode and all available daemon identity states.
Observable result: Running is admitted for each mode, stopped only for none, unavailable for no mode.
Evidence boundary: Host management classifier; actual CLI recovery and Android service start remain installed-runtime gates.



### Requirement: Desktop uninstall requested authority is independently correlated

A successful desktop uninstall request MAY return a bounded canonical schema-1 acknowledgement with operation `uninstall`, state `requested`, the actual committed-inventory-derived transaction ID and current boot ID. This acknowledgement SHALL remain distinct from a durable prepared-operation report. A legacy or degraded producer MAY return empty output and SHALL NOT fabricate authority.

The producer SHALL persist this same authority in bounded root-owned mode-0600 `run/desktop-uninstall-authority.json` before exposing the unchanged empty request marker. An existing malformed or conflicting sidecar SHALL be rejected. The producer SHALL retain the existing global generation exclusion guard while validating committed inventory and publishing the request, and through acknowledgement output and flush. Resident preparation SHALL validate the sidecar and committed inventory under its acquired global operation lease before publishing the irreversible prepared marker. A transient busy lease SHALL retain the exact request and sidecar for the existing paced daemon poll without extending the host deadline; it SHALL NOT be treated as resolved rollback. Request consumption after committed preparation or definitive complete rollback SHALL also remove its sidecar.

Host observation, fresh-boot and all-nine-predicate completion, conflicting later identities and legacy empty-response handling remain owned by [installer device-workflow](../../../../voboost-installer/openspec/specs/device-workflow/spec.md), Requirement `Correlated requested authority survives a fast uninstall`. A producer acknowledgement alone SHALL NOT establish completed removal.

#### Scenario: Desktop publisher serializes requested authority

- **WHEN** the producer serializes actual requested authority
- **THEN** the acknowledgement contains requested state, transaction and boot identity
- **AND** it contains no prepared report, outcome or status sequence

#### Scenario: Substituted inventory or boot authority is rejected

- **WHEN** the requested sidecar is checked against a substituted transaction or boot identity
- **THEN** validation rejects it and rejects malformed or duplicate fields

#### Scenario: Publisher retains exclusion through acknowledgement flush

- **WHEN** the management writer publishes and flushes the requested acknowledgement
- **THEN** the global generation guard excludes resident preparation while the writer is active
- **AND** preparation remains pending with its request and sidecar retained until that guard is released

# Gate: cargo test --manifest-path daemon/Cargo.toml uninstall::tests::desktop_requested_authority_serializes_distinct_from_prepared_report -- --exact

Gate contract: Requested admission is distinct from prepared authority.
Maps: Requirement `Desktop uninstall requested authority is independently correlated`; Scenario `Desktop publisher serializes requested authority`.
Preconditions: A producer-owned requested admission with transaction and boot identity.
Observable result: Actual serialization contains exactly the five requested fields and no prepared report, outcome or sequence.
Evidence boundary: Host native producer serializer; committed inventory and device removal are separate boundaries.

# Gate: cargo test --manifest-path daemon/Cargo.toml uninstall::tests::desktop_authority_rejects_inventory_substitution_and_boot_change -- --exact

Gate contract: Sidecar identity must match current committed authority.
Maps: Requirement `Desktop uninstall requested authority is independently correlated`; Scenario `Substituted inventory or boot authority is rejected`.
Preconditions: Valid admission bytes followed by transaction substitution, changed boot, malformed bytes and duplicate schema field.
Observable result: The actual validator accepts only matching authority and rejects each substitution.
Evidence boundary: Host sidecar validator; actual committed filesystem inventory and SELinux remain installed-runtime gates.

# Gate: cargo test --manifest-path daemon/Cargo.toml uninstall::tests::desktop_management_dispatch_holds_global_guard_through_write_and_flush -- --exact

Gate contract: The real mutation guard survives management output and flush.
Maps: Requirement `Desktop uninstall requested authority is independently correlated`; Scenario `Publisher retains exclusion through acknowledgement flush`.
Preconditions: A real GenerationGuard, management acknowledgement writer and prepared-operation lease acquisition.
Observable result: Writer and flush exclude competing generation admission, a busy preparation retains the request and sidecar, and lease acquisition succeeds after publication drops the guard.
Evidence boundary: Host management writer and real operation exclusion; this does not execute full Android publish_prepared or complete removal.

## Unverified

### Unverified: Android concurrent injection lifecycle

Maps: Requirements `Injection jobs preserve one synchronous control owner` and `Injection ownership survives stale results and terminal fences`; Scenarios `Several targets are available while one injection blocks`, `A second job addresses an active PID`, `Authority changes while a job is running`, `A terminal fence arrives while a worker is blocked`, `A completed resident belongs to an older generation` and `A product update could replace in-flight native inputs` for live Android behavior.
Unavailable observation: Overlapping signed helpers on distinct targets, unchanged same-PID exclusion, live PID/generation changes and terminal freeze cleanup with proven ptrace detach.
Reason: Host threads and descriptor tests do not run Android's signed helper, SELinux policy or native ptrace cleanup.
Required environment or artifact: Focused supported Android emulator traces followed by SELinux Enforcing target evidence and cold-boot vehicle observations.

### Unverified: Target init supervision

Maps: Requirement `One init-managed daemon owns the runtime`; Scenario `The daemon exits after boot`.
Unavailable observation: Installed Android init launches the stable daemon path in `u:r:voboost:s0` and restarts it after exit without rebooting multimedia.
Reason: Host pidfile and synchronous-loop tests do not execute target init or observe its SELinux transition and restart policy.
Required environment or artifact: A supported target boot and crash-restart trace containing init service state, executable identity, process SELinux context and multimedia uptime.


### Unverified: Native APK execution in Enforcing

Maps: Requirement `Startup none closes Android APK execution admission`; Scenario `Installed APK execution boundary in Enforcing` for installed Android package mutation, cancellation/crash convergence, user-profile observation, scheduler acknowledgement, main-poll vehicle progress, SELinux admission and boot/recovery behavior.
Unavailable observation: Actual user0 package disabled state, independent Android process/job absence across reboot and network availability, CLI-only recovery with a registered periodic job, vehicle endpoint processing while the package service is pending, OTA replacement and interrupted lifecycle recovery under live Enforcing policy.
Reason: Staged source, host parser/worker fixtures and captured policy database evaluation cannot run Android services or the live kernel; the staged payload has not been installed.
Required environment or artifact: The completed signed release payload installed exclusively by its packaged CLI into the supported Voyemu profile, full case16 with independent root receipts and endpoint timestamps, then real-car acceptance.
