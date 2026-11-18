# Injector remote execution specification

## Purpose

Define ptrace remote-call stop, result and restoration contracts.

## Requirements

### Requirement: Remote calls restore only a proven stopped tracee

Before attaching the group, the injector SHALL block catchable termination signals in the calling thread. Before writing a temporary PC, SP and zero return address, it SHALL save the selected TID's registers. Every attach and remote wait SHALL be bounded. On remote-call timeout it SHALL send an unmaskable stop, wait for a ptrace stop, then restore registers. Every exit SHALL attempt cleanup for every safely stopped attached TID even after one detach failure. It SHALL detach the selected TID only after successful register restore, or skip it when that TID is proven gone. `ECHILD` or other loss of wait ownership SHALL NOT be treated as proof of exit; the attached task remains cleanup-owned and the attempt fails closed. Stop, restore or detach uncertainty SHALL return the unsafe-cleanup error.

The resident daemon SHALL execute the ptrace operation in a separate exec-owned helper before any attach or register mutation. The helper SHALL require root, the fixed signed daemon executable, exact private argv, and a live no-argument parent with the same executable inode. Its bounded canonical request SHALL bind the target identity and exact fixed payload/bootstrap inputs. The helper exclusively owns attach, stopped threads, original registers, every remote call, restoration and detach. Request, response, acknowledgement and child-exit observation SHALL use bounded envelopes, nonblocking descriptors, monotonic deadlines, `poll` and nonblocking child observation. Daemon death, including SIGKILL, SHALL close the control pipe but SHALL NOT terminate the helper. A controller timeout SHALL close its control descriptors and return without killing or synchronously reaping a helper that still owns cleanup. The helper SHALL remain alive with the tracee stopped and retry exact full-register restoration and explicit detach with bounded backoff and an in-process health record until each succeeds or the tracee is proven gone. Result descriptors SHALL remain helper-owned until the daemon reopens them and acknowledges the bounded response.

#### Scenario: Controller dies during either ABI mutation seam

- **WHEN** the controller is killed after the helper has published temporary PC, SP and result registers through the ARM64 or ARM32 seam
- **THEN** the independent helper restores the exact full saved register image, detaches, continues the tracee and only then exits

#### Scenario: A remote call times out while the tracee is running

- **WHEN** the follow-up stop cannot be proven
- **THEN** the injector neither writes registers nor detaches the tracee as if cleanup succeeded

#### Scenario: Register restoration fails

- **WHEN** the stopped target still exists
- **THEN** detach is forbidden and unsafe cleanup is surfaced to the daemon

#### Scenario: A peer detach fails

- **WHEN** one stopped peer cannot be detached
- **THEN** cleanup still attempts every other attached TID and returns unsafe cleanup

#### Scenario: Wait ownership is lost after attach

- **WHEN** `waitpid` returns `ECHILD` for a task already attached
- **THEN** cleanup still attempts that task and returns unsafe cleanup rather than classifying it as gone

# Gate: make test-injector-ptrace-state
Gate contract: Remote calls restore only a proven stopped tracee host contract.
Maps: Requirement `Remote calls restore only a proven stopped tracee`; Scenarios `A remote call times out while the tracee is running`, `Register restoration fails`, `A peer detach fails`, `Wait ownership is lost after attach`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the injector neither writes registers nor detaches the tracee as if cleanup succeeded; detach is forbidden and unsafe cleanup is surfaced to the daemon; cleanup still attempts every other attached TID and returns unsafe cleanup; cleanup still attempts that task and returns unsafe cleanup rather than classifying it as gone.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

# Gate: make test-injector-ptrace-recovery
Gate contract: Production ARM register recovery retries before detach.
Maps: Requirement `Remote calls restore only a proven stopped tracee`; Scenarios `Controller dies during either ABI mutation seam` and `Register restoration fails`.
Preconditions: The host test installs failures only through the production GETREGSET, SETREGSET and DETACH syscall seam and drives the production ARM64 and ARM32 register structures and recovery loop.
Observable result: initial restore and detach failures increment the health record; no detach occurs before the exact PC, LR, SP and complete saved register image is observed; later success detaches explicitly.
Evidence boundary: Host execution of production ABI state and recovery control flow with modeled syscall results; Android kernel ptrace behavior, SELinux Enforcing, controller process ownership and vehicle behavior are not inferred.

# Gate: make test-injector-parent-death
Gate contract: Exec-owned helper survives controller death and restores the tracee host contract.
Maps: Requirement `Remote calls restore only a proven stopped tracee`; Scenario `Controller dies during either ABI mutation seam`.
Preconditions: The supplementary host harness forks a controller, helper and tracee and kills the controller while x86_64 temporary registers are active.
Observable result: the independent helper survives controller SIGKILL, restores and detaches the host tracee, and leaves it alive.
Evidence boundary: This is supplementary x86_64 lifecycle evidence only. ARM register layout and production recovery control flow are gated separately; Android kernel ptrace behavior, SELinux Enforcing, physical device and vehicle behavior remain unverified.

# Gate: make test-injector-production-host

Gate contract: Production-linked injector entry and target-memory boundary.
Maps: Requirement `Remote calls restore only a proven stopped tracee`; Scenarios `Controller dies during either ABI mutation seam`, `Register restoration fails`.
Preconditions: A Linux host compiles the actual `injector.c`, `elf_resolve.c`, thread-group, parser and recovery translation units; the harness creates a live child tracee and invokes `vbi_inject` with a deliberately invalid observed starttime before remote mutation.
Observable result: The actual top-level attaches then rejects with identity mismatch, detaches without killing the child, clears all output descriptors/diagnostics, and actual target-memory helpers accept exact self-memory while rejecting null, overflow, mismatch and over-bound writes.
Evidence boundary: Linux x86_64 execution of production translation units through the pre-remote-mutation boundary; ARM register mutation, Android procfs/SELinux and successful remote loading remain unverified.

### Requirement: Only the return trap yields a remote result

For arm64 the injector SHALL accept only a SIGSEGV stop with restored zero LR and zero PC semantics; for armeabi-v7a it SHALL accept only a SIGSEGV stop with zero PC semantics. Every `PTRACE_GETREGSET` destination SHALL be zero-initialized and the kernel-updated `iov_len` SHALL equal the exact ABI register structure size before any SP, PC, LR, argument or result field is consumed. Unexpected stops, exits, wait errors, short or long register sets and failed register reads SHALL not yield handles, pointers or file descriptors. A successful zero return value SHALL remain distinct from a transport failure; descriptor zero SHALL be rejected by descriptor consumers.

#### Scenario: The target stops for an unrelated signal

- **WHEN** the expected zero-return trap is not observed
- **THEN** the injector restores the saved frame and returns failure

#### Scenario: The kernel returns a short register set

- **WHEN** `PTRACE_GETREGSET` succeeds but reports fewer or more bytes than the selected ABI requires
- **THEN** the injector consumes no register field and fails the remote call or scratch-address selection

# Unverified: Android remote return register contract
### Requirement: Helper parent argv accepts exact OEM EOF representation

After verifying root identity, signed helper executable, fixed path and matching parent executable inode, the helper SHALL accept exactly the fixed daemon path either terminated by EOF or one NUL byte. Additional bytes, arguments, padding, another path or basename-only representation SHALL be rejected. No authentication predicate or stock-domain permission SHALL be relaxed.

#### Scenario: OEM proc cmdline omits the final NUL

- **WHEN** the authenticated parent's kernel cmdline is the exact fixed daemon path without a trailing NUL
- **THEN** the parent is accepted with the same root/signature/inode checks

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::helper_parent_accepts_oem_eof_or_single_nul_but_never_extra_arguments -- --exact

Gate contract:
Maps: Requirement `Helper parent argv accepts exact OEM EOF representation`; Scenario `OEM proc cmdline omits the final NUL`.
Preconditions: Actual observed OEM EOF bytes, standard NUL form and unrelated/extra-argument forms.
Observable result: Only the two exact daemon representations pass.
Evidence boundary: Host byte validation; physical parent authentication requires target verification.

### Requirement: Failed remote transport fences subsequent target calls

The injector SHALL separate transport outcome from the callee return value for both ARM ABIs. A failed register mutation, continue, wait, cleanup stop, result read, unexpected stop or restoration SHALL fence subsequent remote calls in the same injection, including state-reply getters and successful handoff. A verified return trap with successful restoration SHALL accept a returned zero independently of descriptor validation. Observed non-return-trap stop signals SHALL remain available for detach; ptrace event stops SHALL not become delivered stock signals. Cleanup-stop SIGSTOP origin remains unverified and retains the existing cleanup policy. A failure diagnostic SHALL identify stage, wait status, signal, available PC/LR, execution and restoration outcome without claiming ART managed-stack safety from register restoration.

#### Scenario: Failed initialization previously collapses to zero

- **WHEN** the remote transport fails during initialization
- **THEN** its result is not published as zero and no secondary getter or handoff callback executes

#### Scenario: A function successfully returns zero

- **WHEN** the exact return trap and restoration succeed with result zero
- **THEN** the result remains successful and a subsequent call may execute

#### Scenario: A genuine stop interrupts the remote call

- **WHEN** an unrelated signal or a non-return-trap SIGSEGV stops the callee
- **THEN** the transport fails, preserves the stock signal and records available PC/LR before restoration

#### Scenario: Cleanup cannot establish or restore the stopped frame

- **WHEN** the cleanup stop or frame restoration fails
- **THEN** the transport reports failure without allowing another remote call or claiming successful restoration

# Gate: make test-injector-remote-call

Gate contract: Production synchronous remote-call outcome, sequence fence and saved-origin metadata.
Maps: Requirement `Failed remote transport fences subsequent target calls`; Scenarios `Failed initialization previously collapses to zero`, `A function successfully returns zero`, `A genuine stop interrupts the remote call`, `Cleanup cannot establish or restore the stopped frame`.
Preconditions: Fake OS callbacks drive the same production execution state machine and checked dispatcher with ARM64 and ARM32 return-trap rules, zero results, mutation/continue/wait/read failures, timeout, failed stop, genuine signal, ptrace event and failed restoration. Actual saved-origin capture uses exact ARM64/ARM32 structures, null/unsupported/non-exact inputs and legitimate zero fields.
Observable result: Failed transport leaves the caller output unchanged and invokes no secondary getter/handoff callback; successful zero proceeds; cleanup counts and retained signals match the actual outcome. Saved origin metadata stays independent of callee fields and rejects unavailable inputs without consuming them.
Evidence boundary: Host production-seam execution and both-ABI compilation; actual Android ptrace, ART managed-stack continuation and the Launcher crash cause remain unverified.


### Requirement: Saved origin context remains separate from callee context

Native diagnostics SHALL capture only original PC/LR and an explicit validity flag from the already successful exact register read, without another target read or argument dump. ARM64 and ARM32 fields SHALL use their own saved register structures. Unavailable, unsupported or non-exact capture SHALL carry invalid origin metadata; legitimate zero PC/LR SHALL not imply unavailable. Original metadata SHALL remain separate from callee stop PC/LR and SHALL not establish lock ownership, a direct caller or ART continuation safety. Helper records identify the target and closed native/managed-init/handoff phase without changing execution, signal, timeout or cleanup behavior.

#### Scenario: Exact saved registers are available

- **WHEN** an exact saved ARM64 or ARM32 frame is captured
- **THEN** origin PC/LR and validity describe that saved frame independently of callee stop PC/LR, including legitimate zero fields

#### Scenario: Origin capture is unavailable

- **WHEN** a saved frame is null, unsupported or has non-exact length
- **THEN** no register field is consumed and origin metadata is explicitly invalid

# Gate: make test-injector-remote-call

Gate contract: Exact saved-origin metadata remains independent of callee context.
Maps: Requirement `Saved origin context remains separate from callee context`; Scenarios `Exact saved registers are available`, `Origin capture is unavailable`.
Preconditions: The production capture helper receives actual ARM64/ARM32 register structures, valid zero PC/LR, short/long frame lengths, null and unsupported inputs; independent modeled callee PC/LR describe a failed remote call.
Observable result: Saved PC/LR and validity match the original frame, unavailable inputs clear metadata without consuming fields, and callee fields never replace original metadata.
Evidence boundary: Host production capture seam and both ABI build. Actual target original context and lock/caller correlation require coordinator-owned runtime observations.

### Requirement: Managed bootstrap permits peer safepoints under execution ownership

The exact `@pipe-bootstrap-load` call SHALL retain whole-group admission and native loader/dlsym protection until the resolved entry and register restoration are verified. Before managed initialization, the injector SHALL disable execution-TID clone tracing while that TID remains stopped, switch cleanup to explicit tracked ownership, detach stopped peers with retained signals, and revalidate execution and target identity. Option, peer-release or identity failure SHALL permit no managed entry; partial ownership failure SHALL remain unsafe cleanup. Execution registers, genuine signals, descriptor handoff and signed transaction/generation checks SHALL retain their existing boundaries. Managed cleanup SHALL not infer ownership of new untraced worker TIDs from inventory; native clone tracking and cleanup SHALL remain unchanged. No SIGCONT, ART suspend-flag change or increased timeout is permitted by this boundary.

#### Scenario: A stopped peer cannot acknowledge an ART-like safepoint

- **WHEN** managed initialization needs a peer acknowledgement while that peer is ptrace-stopped
- **THEN** the managed boundary releases the peer before initialization while retaining the stopped execution TID and its cleanup ownership

#### Scenario: Managed initialization creates a worker

- **WHEN** a new worker is created after the managed boundary disables execution clone tracing
- **THEN** that worker is not automatically stopped and final cleanup never claims it as an attached task

#### Scenario: Managed entry cannot establish its ownership boundary

- **WHEN** clone-option change, peer detach, stopped-execution proof or identity validation fails
- **THEN** managed initialization does not run and cleanup retains every still-owned task with its recorded signal

# Gate: make test-injector-managed-call

Gate contract: Production thread-group managed entry, safepoint progress and explicit cleanup ownership.
Maps: Requirement `Managed bootstrap permits peer safepoints under execution ownership`; Scenarios `A stopped peer cannot acknowledge an ART-like safepoint`, `Managed initialization creates a worker`, `Managed entry cannot establish its ownership boundary`.
Preconditions: Actual managed-entry and final-cleanup functions use modeled ptrace ops; a controlled peer acknowledges a suspension request only after the production detach callback releases it; clone-option, partial detach, identity drift, gone peer, unproven stop and retained SIGTERM/SIGSTOP fixtures cover negative boundaries.
Observable result: The attached peer cannot acknowledge before entry but progresses after it; execution stays attached/stopped; new worker remains untraced and final cleanup does not inventory/adopt it; failures prevent entry and remaining owned tasks are cleaned with exact signals. Omitting peer release or retaining clone tracing makes the regression fail.
Evidence boundary: Host execution dependency and ownership seam; native thread-group regression and both ABI compilation complement it. Android ART scheduling, managed continuation, cleanup SIGSTOP origin, old crash cause and complete device/vehicle readiness remain unverified.

### Requirement: Non-return signal diagnostics precede original-context restoration

For an observed non-return signal stop, the injector SHALL invoke its optional diagnostic capture before restoring the interrupted original frame, without changing stock signal delivery or cleanup outcomes. ARM64 capture SHALL consume only saved FP/LR pairs from the exact stopped execution TID's writable stack mapping, use fixed buffers and at most sixteen frame reads, and emit only frame/return addresses and availability metadata. Invalid, cyclic, unaligned, out-of-bounds or unreadable chains SHALL stop with explicit unavailable reasons; an end marker or limit SHALL not claim complete unwinding. Return traps and ptrace events SHALL not produce a signal chain. Diagnostic errno SHALL not replace transport/restore metadata. ARM32 frame format remains unavailable rather than using assumed offsets.

#### Scenario: A genuine signal interrupts the callee

- **WHEN** a non-return SIGABRT or SIGSEGV is observed with a captured callee frame
- **THEN** diagnostic capture happens before original restoration and the stock signal remains retained

#### Scenario: The callee frame chain is incomplete

- **WHEN** alignment, monotonicity, cycle, bounds or memory-read validation fails, or sixteen frames are consumed
- **THEN** the bounded chain reports its partial count and reason without reading beyond the validated mapping or claiming a complete unwind

#### Scenario: The remote call reaches its return trap

- **WHEN** the exact zero-PC/LR return trap or a ptrace event is observed
- **THEN** no non-return signal chain is captured

# Gate: make test-injector-callee-frames

Gate contract: Bounded production FP-chain reader and pre-restore remote-call capture ordering.
Maps: Requirement `Non-return signal diagnostics precede original-context restoration`; Scenarios `A genuine signal interrupts the callee`, `The callee frame chain is incomplete`, `The remote call reaches its return trap`.
Preconditions: The actual frame reader uses a fixed memory fixture with exact bounds, end marker, limit, failed read, cycle, backward/unaligned/overflow/out-of-bounds pointers; the actual remote-call state machine observes non-return SIGABRT/SIGSEGV, a return trap and ptrace event with diagnostic callback errno mutation.
Observable result: No read exceeds the validated range or sixteen frames; partial count/reason is explicit; capture occurs before original restore and retained signals/outcomes are unchanged; return traps/events emit no chain.
Evidence boundary: Host production-reader/call-order seam and both ABI compilation. Actual Android map collection, target chain, ART fatal context, ARM32 layout and complete unwinding remain unverified.

### Requirement: Interrupted linker execution is not a remote loader entry point

Before scratch writes or remote calls, the injector SHALL reject an interrupted execution PC or LR inside an executable mapping of the exact system linker for the target ABI. It SHALL release the complete stopped group before a bounded reacquisition, revalidate the target identity on each acquisition, and permit no remote mutation while the linker remains busy. Exhaustion, unreadable context or unsafe detach SHALL fail closed.

#### Scenario: Settings is interrupted while protecting linker allocator pages

- **WHEN** the interrupted PC or LR belongs to an executable system linker mapping
- **THEN** that context is classified as busy before remote loader entry

#### Scenario: The interrupted address belongs to a different mapping

- **WHEN** neither PC nor LR belongs to the exact ABI linker executable mapping
- **THEN** the linker-address guard does not classify that context as busy

# Unverified: Android linker safe-point reacquisition


## Unverified

### Unverified: Android remote return register contract

Maps: Requirement `Only the return trap yields a remote result`; Scenarios `The target stops for an unrelated signal` and `The kernel returns a short register set`.
Unavailable observation: Production arm64 and armeabi-v7a ptrace calls reject unrelated stops and non-exact kernel register-set lengths before consuming a result.
Reason: The host injector tests do not execute the Android ABI-specific `PTRACE_GETREGSET` and remote-return path against target processes, while an NDK build proves only compilation.
Required environment or artifact: Rooted Android arm64 and armeabi-v7a target processes with controlled unrelated-stop and short/long-register-set fault injection plus observed injector results and restored tracee state.

### Unverified: Android linker safe-point reacquisition

Maps: Requirement `Interrupted linker execution is not a remote loader entry point`; Scenarios `Settings is interrupted while protecting linker allocator pages`, `The interrupted address belongs to a different mapping`.
Unavailable observation: Both ABI production paths reacquire a complete group after busy context, revalidate identity and perform no scratch writes or remote calls before a clear context; exhaustion and failed detach prevent entry.
Reason: Host address classification and compilation do not execute Android ptrace admission and reacquisition.
Required environment or artifact: Controlled Android loader-busy target plus observed successful Settings injection with the newly packaged native guard and original failure retained.

## Requirement: durable unresolved loader lifetime quarantine

The daemon SHALL publish a root-owned write-ahead marker before each native
injection call. The marker SHALL bind the kernel boot ID, attested target PID,
starttime and process name. It SHALL use the existing trusted root zone without
changing directory modes, SELinux domains, remote deadlines or target rights.

### Scenario: executed native loader timeout
- **WHEN** native loading times out after execution and safe CPU restore/detach
- **THEN** the injector returns loader-unresolved (-12)
- **AND** the marker remains durable
- **AND** bootstrap, abort and resident rebind for the same lifetime are denied
  before any further native call, including after daemon restart

### Scenario: unfinished call at daemon exit
- **WHEN** the daemon exits before durable completion of a native call
- **THEN** its marker remains
- **AND** restart cannot treat absence of a completion as successful loader unwind

### Scenario: independently attested new lifetime
- **WHEN** the target starttime differs or the kernel boot ID differs
- **THEN** the prior lifetime marker does not authorize or block the new lifetime
- **AND** markers from an older boot are removed only after trusted strict validation

### Scenario: completed ordinary call
- **WHEN** the native outcome proves completion without loader-unresolved or unsafe cleanup
- **THEN** the daemon validates and durably removes its exact write-ahead marker

### Scenario: hostile or corrupted safety marker
- **WHEN** a marker has invalid ownership, mode, link count, schema or identity,
  or marker persistence fails
- **THEN** native admission fails closed
- **AND** diagnostic status is not imported as an alternative safety authority

The marker namespace is bounded to 128 current-boot files, each at most 1024
bytes. A full namespace denies new calls rather than evicting unresolved live
lifetimes. Different targets retain independent marker files and helpers.
