# Runtime transport specification

## Purpose

Define anonymous-pipe transport, framing and per-endpoint queue bounds.

## Requirements

### Requirement: Runtime uplink draining yields between bounded endpoint batches

One uplink drain invocation SHALL perform at most eight reads of at most 8192 bytes each, even when its endpoint remains readable. Unread bytes SHALL remain in the pipe and incomplete records SHALL remain in the endpoint's existing framing state for the next invocation, preserving ordering and discard state. A busy endpoint SHALL NOT prevent the synchronous poll pass from continuing to process discovery and other endpoints.

#### Scenario: An uplink remains continuously readable

- **WHEN** the reader supplies another chunk after every successful read
- **THEN** the drain returns after eight reads without consuming the ninth chunk and a subsequent invocation resumes the same record stream

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::continuously_readable_uplink_yields_and_retains_partial_record -- --exact
Gate contract: Bounded uplink drain and stream continuation.
Maps: Requirement `Runtime uplink draining yields between bounded endpoint batches`; Scenario `An uplink remains continuously readable`.
Preconditions: The production drain loop receives a controlled always-readable byte source and the existing per-endpoint frame buffer.
Observable result: Eight reads return control, the ninth remains unread, and the next invocation completes the retained partial record without loss or duplication.
Evidence boundary: Host execution of the production drain loop; Android process recreation and reinjection require runtime evidence.

### Requirement: Runtime communication uses only bound anonymous pipes

Each injected process SHALL receive one daemon-created uplink and downlink pair bound to its PID, process, epoch and resident generation. Implant and agents SHALL not open Voboost filesystem paths or choose another process, agent or generation by payload text. EOF, `EPIPE` or protocol poison SHALL close the session without a filesystem fallback.

#### Scenario: The daemon side disappears

- **WHEN** an endpoint observes EOF or broken pipe
- **THEN** it fails safe and does not read configuration or state from disk

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::policy_is_pipe_only_no_target_readable_bootstrap_or_shared -- --exact
Gate contract: Pipe-only runtime policy.
Maps: Requirement `Runtime communication uses only bound anonymous pipes`; Scenario `The daemon side disappears`.
Preconditions: The exact Rust test evaluates endpoint policy for bootstrap, state and shared-path access.
Observable result: Runtime authority contains only bound pipes and exposes no target-readable Voboost path fallback.
Evidence boundary: Host policy construction; injected-process filesystem syscalls are not observed.

# Gate: cargo test --manifest-path daemon/Cargo.toml downlink::tests::epipe_on_closed_read_end_poisons_without_panicking -- --exact
Gate contract: Broken downlink session closure.
Maps: Requirement `Runtime communication uses only bound anonymous pipes`; Scenario `The daemon side disappears`.
Preconditions: The exact Rust test closes the pipe read end before a queued downlink write.
Observable result: `EPIPE` poisons the endpoint without panic or fallback.
Evidence boundary: Host anonymous pipe behavior; Android target teardown timing is not exercised.

### Requirement: Runtime uplink frames have a strict bounded schema

Every uplink frame SHALL have a known one-byte type, bounded length and exact payload schema. Parsing SHALL retain explicit per-FD discard state: after the first byte beyond the record bound, every byte through exactly the next newline SHALL be discarded, and only a subsequent record may be parsed.

#### Scenario: An oversized uplink record is followed by valid data

- **WHEN** one endpoint exceeds the record bound before a newline and then sends a valid record
- **THEN** the daemon discards the complete oversized record and parses only the subsequent record

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::per_fd_oversize_discards_exact_tail_through_newline -- --exact
Gate contract: Oversized uplink discard boundary.
Maps: Requirement `Runtime uplink frames have a strict bounded schema`; Scenario `An oversized uplink record is followed by valid data`.
Preconditions: The exact Rust test sends an over-bound record in chunks followed by one valid record on the same FD.
Observable result: The complete hostile tail is discarded through its newline and only the subsequent record is delivered.
Evidence boundary: Host stream framer; target pipe scheduling is not exercised.

### Requirement: Runtime uplink text is strict UTF-8

Every uplink record SHALL be strict UTF-8 and invalid bytes SHALL NOT be lossily normalized into protocol input.

#### Scenario: Invalid UTF-8 precedes a valid uplink record

- **WHEN** one endpoint sends an invalid UTF-8 record followed by valid UTF-8
- **THEN** the invalid record is rejected without changing or consuming the following record

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::invalid_utf8_record_is_rejected_without_affecting_next_record -- --exact
Gate contract: Strict uplink UTF-8 admission.
Maps: Requirement `Runtime uplink text is strict UTF-8`; Scenario `Invalid UTF-8 precedes a valid uplink record`.
Preconditions: The exact Rust test routes one invalid UTF-8 record and then a valid record.
Observable result: The invalid record yields no event and the next valid record is parsed unchanged.
Evidence boundary: Host parser; Android byte transport is not exercised.

### Requirement: Runtime downlink queues preserve bounded per-endpoint order

The daemon SHALL maintain bounded per-FD downlink queues, preserve partial-write offsets, retry `EAGAIN` without duplicating bytes and poison only the failing endpoint on overflow or hard write error. One flush SHALL do bounded work. Backpressure on one endpoint SHALL NOT block or retry frames on another endpoint.

#### Scenario: A downlink write is partial and then returns EAGAIN

- **WHEN** only a prefix is written before backpressure
- **THEN** the next writable event resumes at the remaining offset exactly once

#### Scenario: One endpoint exceeds its queue bound

- **WHEN** enqueueing another frame would exceed the per-FD limit
- **THEN** that endpoint is closed while other endpoints remain serviceable

# Gate: cargo test --manifest-path daemon/Cargo.toml downlink::tests::queued_frames_preserve_order_across_backpressure -- --exact
Gate contract: Partial-write downlink ordering.
Maps: Requirement `Runtime downlink queues preserve bounded per-endpoint order`; Scenario `A downlink write is partial and then returns EAGAIN`.
Preconditions: The exact Rust test injects a partial write and `EAGAIN` across multiple queued frames.
Observable result: The next flush resumes at the exact remaining offset and preserves frame order without duplication.
Evidence boundary: Host write seam; Android pipe capacity is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml downlink::tests::capacity_rejects_whole_frame_and_hard_error_poisons_endpoint -- --exact
Gate contract: Per-endpoint queue overflow isolation.
Maps: Requirement `Runtime downlink queues preserve bounded per-endpoint order`; Scenario `One endpoint exceeds its queue bound`.
Preconditions: The exact Rust test fills one endpoint queue and injects a hard write error.
Observable result: The whole new frame is rejected and only the failing endpoint is poisoned.
Evidence boundary: Host queue state; concurrent target endpoints are not exercised.

### Requirement: Implant stream framing preserves message boundaries

The implant SHALL use one persistent bounded stream framer for both desired snapshots and state replies. Split and coalesced frames SHALL preserve order; an oversized frame SHALL be discarded through its terminating newline so its tail cannot become a synthetic frame. A large valid `D` immediately before a correlated `R` SHALL not consume or misalign that reply.

#### Scenario: Implant frames are split and coalesced

- **WHEN** desired and reply frames cross read boundaries or arrive in one read
- **THEN** the implant preserves their complete order without treating an oversized tail as a new frame

# Gate: make test-implant-pipe-bootstrap
Gate contract: Implant stream framing preserves message boundaries host contract.
Maps: Requirement `Implant stream framing preserves message boundaries`; Scenario `Implant frames are split and coalesced`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the implant preserves their complete order without treating an oversized tail as a new frame.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: None self-stop preserves final bounded resident delivery

Before committed none self-stop, the daemon SHALL render the fresh none desired state for existing tracked endpoints and service pending correlated confirmations through the existing ordered D/A admission. It SHALL perform no new target injection. Final flush SHALL resume retained offsets for at most one fixed 750-millisecond total deadline, isolate poisoned or blocked peers, and report incomplete delivery without claiming acknowledgement. The implant watcher SHALL drain available bounded frames before treating POLLHUP/EOF as idle, apply buffered desired state outside the transport mutex and retain the correlated A for ordinary polling. JNI mutation-acknowledgement polling SHALL also drain readable final frames when POLLIN and POLLHUP arrive together, before treating the writer closure as terminal; the existing bounded drain, framing, JSON and request-correlation checks SHALL remain in force.

#### Scenario: None is committed before an ordinary desired pass

- **WHEN** canonical none is observed with an eligible live Settings endpoint
- **THEN** the fresh none profile is queued and delivered before self-stop instead of leaving the old profile

#### Scenario: Final delivery encounters backpressure or writer closure

- **WHEN** final D/A delivery returns EAGAIN, a peer remains blocked, or the writer closes before the reader wakes
- **THEN** healthy bytes retain exact order and identity, blocked waiting stays bounded and the reader consumes available D/A before entering idle

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml tests::none_terminal_delivery_pushes_fresh_settings_profile_before_self_stop -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `None self-stop preserves final bounded resident delivery`; Scenario `None is committed before an ordinary desired pass`.
Preconditions: The actual terminal delivery routine owns an eligible live Settings endpoint and a real pipe consumer.
Observable result: A fresh D carries none plus the existing Settings host before the routine returns.
Evidence boundary: Host production terminal routine and pipe; Android init self-stop and guest boot absence remain separate target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml tests::none_terminal_delivery_resumes_backpressured_pair_and_bounds_a_blocked_peer -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `None self-stop preserves final bounded resident delivery`; Scenario `Final delivery encounters backpressure or writer closure`.
Preconditions: Real full pipes retain an ordered none D/A pair and another peer never drains.
Observable result: The healthy pair resumes without loss or duplication, its document bytes match exactly, and the blocked peer cannot extend the fixed terminal deadline.
Evidence boundary: Host production queue/terminal routine; Android pipe scheduling is separate runtime evidence.

# Gate: make test-implant-downlink

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `None self-stop preserves final bounded resident delivery`; Scenario `Final delivery encounters backpressure or writer closure`.
Preconditions: The production bounded watcher reader receives complete D/A on a real pipe after its writer closes, and the JNI polling helper receives a final correlated A on a real AF_UNIX socketpair reporting POLLIN together with POLLHUP.
Observable result: Both readers preserve the final replayable correlated acknowledgement; JNI polling returns the exact final document for its request and rejects a request newer than the final acknowledged ID.
Evidence boundary: Host actual reader/framer/snapshot path; JNI application and visible Android rendering require independent target evidence.

### Requirement: Live authority reads are descriptor-bound and bounded

Trusted live manifests, detached signatures and canonical intent SHALL be opened nofollow through fixed directory descriptors and rejected from metadata before allocating beyond their respective bounds. Signature reads SHALL use the exact signature cap; stat-then-path-read sequences are not a valid bound.

#### Scenario: Oversized live authority is presented

- **WHEN** live authority metadata exceeds its exact bound or names a link
- **THEN** the daemon rejects it before unbounded allocation or path-based reread

# Gate: cargo test --manifest-path daemon/Cargo.toml installed_product::tests::active_product_loader_rejects_sparse_oversize_and_links_before_parse -- --exact
Gate contract: Bounded live manifest and signature loading.
Maps: Requirement `Live authority reads are descriptor-bound and bounded`; Scenario `Oversized live authority is presented`.
Preconditions: The exact Rust test supplies a sparse over-bound active product manifest and a linked replacement through the live loader.
Observable result: Descriptor metadata admission rejects both before product parsing.
Evidence boundary: Host filesystem metadata; Android sparse-file behavior is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::canonical_reader_rejects_sparse_oversize_before_reading_body -- --exact
Gate contract: Bounded canonical intent loading.
Maps: Requirement `Live authority reads are descriptor-bound and bounded`; Scenario `Oversized live authority is presented`.
Preconditions: The exact Rust test presents a sparse over-bound canonical intent file through the descriptor-relative reader.
Observable result: The reader rejects metadata before reading or allocating the body.
Evidence boundary: Host descriptor-relative file read; target app-data mount behavior is not exercised.

### Requirement: Removal restart permission is bound to a live transition

The `E|request|runtime|restart|process:revision` request SHALL require a current verified resident generation and a daemon-owned removal transition bound to PID, starttime, endpoint epoch and desired revision. Pending removed IDs SHALL survive unrelated desired changes while disabled and SHALL NOT transfer to a new process. A one-use monotonic permission SHALL precede the correlated acknowledgement; only its matched death avoids crash and panic increments.

#### Scenario: The current endpoint requests removal restart

- **WHEN** the old endpoint requests its current removal revision
- **THEN** one bounded permission precedes its acknowledgement and other endpoints cannot consume it

#### Scenario: Desired state changes while removal is pending

- **WHEN** a later desired snapshot keeps the removed agent disabled
- **THEN** only the old endpoint retains its removal debt; re-enable or a new process cancels eligibility

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::restart_removal_stamp_is_bound_to_the_old_live_endpoint -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual desired writer and tracker own a live fixture endpoint.

Observable result: Removal grants eligibility only to its exact old PID/starttime/epoch; a new tracked process cannot borrow it.

Evidence boundary: Host daemon ownership only.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_restart::tests::current_signed_removal_authorizes_only_its_own_death_once -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual permit store receives current and stale endpoint capabilities.

Observable result: The named branch verifies single consumption, authority rejection, exact expiry, independent PID reuse or newer-revision replacement respectively.

Evidence boundary: Host permit storage only; Android recreation and crypto verification are outside this boundary.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_restart::tests::stale_identity_or_no_removal_never_creates_a_permit -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual permit store receives current and stale endpoint capabilities.

Observable result: The named branch verifies single consumption, authority rejection, exact expiry, independent PID reuse or newer-revision replacement respectively.

Evidence boundary: Host permit storage only; Android recreation and crypto verification are outside this boundary.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_restart::tests::duplicates_do_not_extend_the_exact_expiry_or_rearm_the_request -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual permit store receives current and stale endpoint capabilities.

Observable result: The named branch verifies single consumption, authority rejection, exact expiry, independent PID reuse or newer-revision replacement respectively.

Evidence boundary: Host permit storage only; Android recreation and crypto verification are outside this boundary.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_restart::tests::reused_pid_needs_new_attested_birth_and_its_own_removal -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual permit store receives current and stale endpoint capabilities.

Observable result: The named branch verifies single consumption, authority rejection, exact expiry, independent PID reuse or newer-revision replacement respectively.

Evidence boundary: Host permit storage only; Android recreation and crypto verification are outside this boundary.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_restart::tests::newer_confirmed_revision_can_replace_an_expired_unfinished_permission -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `The current endpoint requests removal restart`.

Preconditions: The actual permit store receives current and stale endpoint capabilities.

Observable result: The named branch verifies single consumption, authority rejection, exact expiry, independent PID reuse or newer-revision replacement respectively.

Evidence boundary: Host permit storage only; Android recreation and crypto verification are outside this boundary.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::test_support::pending_removal_survives_other_changes_but_not_reenable_or_a_new_endpoint -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Removal restart permission is bound to a live transition`; Scenario `Desired state changes while removal is pending`.

Preconditions: The production debt function receives pending removal and later desired IDs.

Observable result: Disabled IDs survive on the old endpoint; re-enable and endpoint replacement cancel them.

Evidence boundary: Host transition policy only.

### Requirement: Restart acknowledgement does not replace mutation acknowledgement

Restart and mutation confirmations SHALL coalesce independently on each endpoint and retain their existing retry limits.

#### Scenario: Both confirmations are pending

- **WHEN** a restart confirmation follows a mutation and delivery retries
- **THEN** both correlated request IDs remain independently deliverable

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::restart_confirmation_cannot_replace_the_user_mutation_ack -- --exact

Gate contract: Confirmed agent removal and restart authority.

Maps: Requirement `Restart acknowledgement does not replace mutation acknowledgement`; Scenario `Both confirmations are pending`.

Preconditions: The production queues receive both request classes for one endpoint.

Observable result: The restart and a newer mutation survive separate retries without replacing each other.

Evidence boundary: Host queue behavior only.

# Unverified: Packaged removal restart handshake

### Requirement: Launcher cache quiescence is a correlated closed operation

The bound launcher downlink SHALL accept only a bounded `C` command with the exact cache-quiescence schema. Its command slot SHALL remain separate from desired state and mutation acknowledgments. The implant SHALL call the cache-only Java drain outside transport locks and emit an acknowledgment only after successful drain, with unchanged transport epoch and pending command. The daemon SHALL accept that acknowledgment only for its exact pending nonce, PID, process starttime, endpoint epoch, resident generation, catalog and document revision. Queue admission, EOF and ordinary status SHALL NOT constitute cache quiescence.

#### Scenario: A foreign or replaced endpoint acknowledges a cache request

- **WHEN** nonce, PID, starttime, epoch or document identity differs from the pending launcher request
- **THEN** the daemon rejects the acknowledgment and cannot publish a quiescence receipt

# Gate: cargo test --manifest-path daemon/Cargo.toml icon_quiescence::tests::exact_correlated_ack_and_foreign_endpoint_fences -- --exact
Gate contract: Exact endpoint and nonce correlation for the closed cache-only acknowledgment.
Maps: Requirement `Launcher cache quiescence is a correlated closed operation`; Scenario `A foreign or replaced endpoint acknowledges a cache request`.
Preconditions: A pending request and controlled matching and foreign endpoint contexts.
Observable result: Only the exact pending endpoint succeeds; unsolicited acknowledgments and foreign nonce or endpoint identities have no effect.
Evidence boundary: Host parser and correlation checks; Android JNI worker drain requires emulator evidence.

### Requirement: Launcher observation uses one closed root operation

The existing daemon socket SHALL reject `launcher-page-observe` from a non-root peer, a zero peer PID, a nonce outside the exact lowercase 64-hex grammar, or an unknown operation. The operation accepts only the existing exact `requestId` and `operation` request envelope; it exposes no supplied class, method, field, expression, command, or selector.

#### Scenario: A foreign caller requests launcher observation

- **WHEN** a non-root peer, zero peer PID, malformed nonce, or unknown operation reaches the root dispatcher
- **THEN** the dispatcher rejects it without requesting resident observation

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::launcher_observation_socket_refuses_foreign_peer_and_bad_nonce -- --exact

Gate contract: Closed root dispatcher rejection.
Maps: Requirement `Launcher observation uses one closed root operation`; Scenario `A foreign caller requests launcher observation`.
Preconditions: The production dispatcher receives the named forbidden peer or operation inputs.
Observable result: Every named input returns an error before observation admission.
Evidence boundary: Host dispatcher; real Android peer credentials and signed executable authentication remain packaged-runtime evidence.

### Requirement: Launcher observation parsing is exact and fail closed

The `P` response parser SHALL accept only the exact pending command identity, closed outcome and reason, ordered capture times, and exact typed observation fields. Observed data SHALL describe settled AllApps index one, idle scrolling, no computing layout, the fixed display-zero MainActivity application window, the exact launcher grid and layout-manager classes, positive bounds, bounded unique item positions and labels, and a 12-slot page count and page-aligned first position. A nonzero actual offset SHALL remain raw observation rather than being normalized to first page. Unknown or duplicate fields, explicit null observation, foreign nonce, and unavailable data carrying observation SHALL be rejected. Page-query evidence SHALL remain independent of feature status and SHALL NOT assert that features are active.

#### Scenario: A response contains a foreign command or unknown field

- **WHEN** a response changes the pending nonce, adds an unknown field, or duplicates a field
- **THEN** the parser returns no accepted observation

#### Scenario: A settled later page or inconsistent profile is observed

- **WHEN** the exact typed observation describes a settled later page or changes a required settled-profile value
- **THEN** a later page retains its actual position and offset while an inconsistent profile is rejected

# Gate: cargo test --manifest-path daemon/Cargo.toml launcher_page::tests::nonce_and_response_fail_closed -- --exact

Gate contract: Exact response envelope and nonce parser.
Maps: Requirement `Launcher observation parsing is exact and fail closed`; Scenario `A response contains a foreign command or unknown field`.
Preconditions: The production parser receives a valid unavailable response and foreign or malformed variants.
Observable result: The valid response is accepted; foreign nonce, unknown field and duplicate field are rejected.
Evidence boundary: Host JSON parser; this does not prove actual launcher capture.

# Gate: cargo test --manifest-path daemon/Cargo.toml launcher_page::tests::nested_observation_profile_is_closed_and_settled -- --exact

Gate contract: Typed settled launcher profile.
Maps: Requirement `Launcher observation parsing is exact and fail closed`; Scenario `A settled later page or inconsistent profile is observed`.
Preconditions: The production nested parser receives an exact valid fixture, a later page and changed settled-profile fields.
Observable result: Valid first and later pages retain their values; wrong outer item, page count, unaligned first position, moving scroll, computing layout and nested unknown fields fail.
Evidence boundary: Host parser; actual OEM view discovery and JNI delivery remain unverified below.

### Requirement: Launcher observation correlation fences endpoint and boot lifetimes

The correlation predicate SHALL require equal process, target PID and starttime, endpoint epoch, resident generation, catalog and document generation, plus unchanged root boot ID and daemon PID and starttime. Its boot-clock interval SHALL require dispatch time no later than capture start, capture start no later than finish, and finish no later than root receipt. The root receipt carries decimal-string process identity fields, integer document generation and capture milliseconds, and omits observation for unavailable results.

#### Scenario: Endpoint lifetime or capture interval changes

- **WHEN** any bound endpoint or daemon lifetime field differs or capture lies outside the request interval
- **THEN** the correlation predicate rejects the observation

# Gate: cargo test --manifest-path daemon/Cargo.toml launcher_page::tests::endpoint_lifetime_daemon_boot_and_capture_fences -- --exact

Gate contract: Endpoint identity and boot-clock interval predicates.
Maps: Requirement `Launcher observation correlation fences endpoint and boot lifetimes`; Scenario `Endpoint lifetime or capture interval changes`.
Preconditions: The production predicates receive exact and individually foreign identity fields plus ordered and disordered capture intervals.
Observable result: Only equal endpoint and daemon identities and an inclusive ordered interval pass.
Evidence boundary: Host predicate logic; actual Android CLOCK_BOOTTIME and SystemClock.elapsedRealtime correspondence remains packaged-runtime evidence.

### Requirement: Disabled launcher features retain separate observation authority

For the exact signed applicable launcher target, bootstrap admission SHALL derive catalog attestation IDs separately from enabled feature execution IDs. Empty launcher execution IDs SHALL remain empty, and observation admission SHALL NOT alter the canonical plan or activate disabled features. Existing signed applicable module registration is retained so ordinary later feature activation can use the resident runtime.

#### Scenario: Every launcher feature is disabled

- **WHEN** the applicable signed catalog declares a launcher target while its feature execution set is empty
- **THEN** the launcher receives separate nonempty attestation IDs and its desired document keeps every feature disabled without plan mutation

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::launcher_observer_authority_keeps_all_features_disabled -- --exact

Gate contract: Separate launcher bootstrap authority and disabled execution.
Maps: Requirement `Disabled launcher features retain separate observation authority`; Scenario `Every launcher feature is disabled`.
Preconditions: A verified-generation host fixture declares an applicable launcher target with disabled feature intent.
Observable result: The production authority function returns applicable launcher IDs; another process gets none; bootstrap desired execution remains disabled and the plan is unchanged.
Evidence boundary: Host bootstrap metadata and admission policy, not Android injection or feature lifecycle execution.

### Requirement: Launcher observation remains on the common resident transport

The root-only fixed CLI SHALL authenticate its stable active-product executable and independently verify the resident PID, starttime, boot, root UID fields and ownership of the exact descriptor-bound pidfile FLOCK through the bounded kernel lock inventory before and after accepting a receipt. The resident SHALL validate its own stable native role and exact running active-product executable before publishing a strict root:root mode0600 server authority under the trusted run directory. The producer SHALL read the calling worker task’s bounded `/proc/thread-self/attr/current` (falling back only on ENOENT to `/proc/self/task/<current-native-TID>/attr/current`) and require exactly `u:r:voboost:s0` before publication. Schema2 authority SHALL require an explicit `producerContext` field containing this self-attested context as well as PID, starttime, boot, signed-manifest digest and executable hash; old schema and missing or foreign context SHALL fail closed. The producer context SHALL be documented as resident self-attestation inside the trusted-root file boundary, not independently observed remote SID. The client SHALL NOT read another process procattr. Optional publication errors SHALL remain in the observation worker, with bounded info/debug diagnostics throttled to at most one failure message per thirty seconds; they SHALL NOT block vehicle startup. the CLI SHALL compare every field to current independent observations and the signed installed manifest and exact installed executable. This is the existing trusted-root management-file boundary against unprivileged applications, not independent verification of another process executable or socket peer credentials: root administrators can replace root-owned authority. The CLI SHALL NOT open or readlink another process /proc/PID/exe, broaden stock su privileges, or fall back when the kernel lock proof or authority is unavailable. The resident self-verification and installed-file verification are separate checks and SHALL NOT be reported as client-side running-executable attestation. On nosuid data partitions the CLI SHALL use the existing root-owned management file authority without adding stock su socket access or relying on an exec domain transition. Its private run/launcher-observe directory SHALL be root:root mode0700; immutable nonce request and response files SHALL be root-owned mode0600, descriptor-bound and size-bounded. Requests SHALL bind the current daemon incarnation, boot and a maximum seven-second boot-clock deadline. The resident worker SHALL reject expired, foreign, malformed and duplicate-field requests before observation. CLI writers SHALL serialize under the private directory lock. Replies SHALL bind the same nonce and boot, expire within seven seconds and retain the existing endpoint, generation and capture validation. Orphan replies SHALL be reclaimed after expiry or a boot change. The synchronous daemon poll SHALL dispatch only one unambiguous launcher endpoint; the management relay worker waits at most five seconds outside that poll. A bounded separate `P` command slot SHALL share the existing serialized downlink. Its optional common `AgentEntry.observeLauncherPage(String):String` JNI lookup fails closed when unavailable and does not change required initialization ABI. The implant calls the common observer outside downlink locks, preserves Unicode through ASCII JSON escapes, bounds its response to 16 KiB, and serializes partial nonblocking uplink writes within 100 ms, closing a torn stream before another frame can follow. Root nonce reuse is rejected within a bounded daemon-lifetime admission set; capacity exhaustion fails closed. Timeout, no endpoint and malformed evidence cannot establish first-page state.

#### Scenario: The fresh packaged common observer is queried with launcher features disabled

- **WHEN** the root operator queries the disabled-feature launcher through the signed stable CLI
- **THEN** one current boot- and endpoint-bound common observation is returned without starting feature hooks, or the query fails closed

# Unverified: Packaged launcher page observation

### Requirement: Cluster desired state is a projection of canonical intent

The Android root Plan SHALL remain the only user-intent authority. Cluster desired rows SHALL derive from that admitted Plan and the signed catalog's QNX targets. The courier SHALL accept only opaque take/result delivery requests. A semantic projection change SHALL commit its signed outbox before a bounded fixed courier wake; unchanged poll passes SHALL not repeat that wake.

#### Scenario: One logical agent targets Android and QNX

- **WHEN** the canonical Plan enables or disables that logical ID
- **THEN** the Cluster projection uses the same enabled intent and never writes another user setting

# Gate: cargo test -p voboost-daemon cluster_control::tests::canonical_plan_is_only_projection_authority -- --exact
Gate contract: Single desired authority.
Maps: Requirement `Cluster desired state is a projection of canonical intent`; Scenario `One logical agent targets Android and QNX`.
Preconditions: A mixed target catalog and admitted canonical Plan are supplied.
Observable result: Native desired rows follow that Plan and invalid or stale Plan identities reject projection.
Evidence boundary: Host semantics; Android UI and courier execution remain separate.

### Requirement: Delivery does not imply native application

Desired writes and ELF delivery SHALL not become Applied. A native observed receipt SHALL bind current device authority, catalog closure, admitted generation, challenge, desired revision and desired digest. Missing pairing SHALL report setup-required without unsigned fallback. The synchronous QNX service SHALL keep Runtime2/Agent3 lifecycle outcomes separate from transport delivery.

#### Scenario: Desired changes before a verified receipt arrives

- **WHEN** the derived enabled value changes
- **THEN** observations remain pending and are never inferred as Applied from the outbox

# Gate: cargo test -p voboost-daemon cluster_control::tests::projection_is_idempotent_and_never_claims_applied -- --exact
Gate contract: Honest derived observation and bounded wake.
Maps: Requirement `Delivery does not imply native application`; Scenario `Desired changes before a verified receipt arrives`.
Preconditions: A root-owned mailbox receives repeated and changed canonical projections.
Observable result: Unchanged projection preserves revisions and wakes once; changed desired is pending rather than Applied.
Evidence boundary: Host mailbox and wake dispatch guard; Android broadcast and QNX execution are not inferred.

# Gate: cargo test -p voboost-contract-core --test cluster_authority applied_needs_current_challenge_desired_and_admitted_generation -- --exact
Gate contract: Native receipt authority binding.
Maps: Requirement `Delivery does not imply native application`; Scenario `Desired changes before a verified receipt arrives`.
Preconditions: Device-signed receipt fixtures vary their current authority bindings.
Observable result: Only current admitted generation, desired state and challenge authorize Applied.
Evidence boundary: Host cryptographic protocol; exact QNX and physical readbacks remain unverified.

# Unverified: exact-qnx-and-vehicle-acceptance

## Unverified

### Unverified: Packaged removal restart handshake

Maps: Requirements `Removal restart permission is bound to a live transition` and `Restart acknowledgement does not replace mutation acknowledgement`; all Scenarios.

Unavailable observation: The real native pipe carries the request and acknowledgement, the old application exits normally, the new instance receives only the latest configuration, and retained agents become ready without suppressing native crashes.

Reason: The new protocol currently has host boundary evidence only.

Required environment or artifact: Fresh immutable beta1 DMG and the full Voyemu cycle with actual PID/starttime, diagnostic and crash-tail receipts.


### Unverified: Packaged launcher page observation

Maps: Requirement `Launcher observation remains on the common resident transport`; Scenario `The fresh packaged common observer is queried with launcher features disabled`.
Unavailable observation: The real signed CLI authenticates the Android daemon socket; fresh all-disabled injection starts only common runtime execution; native downlink and JNI deliver current OEM launcher state; Unicode and partial writes remain intact; root boot-clock brackets match Java capture and a replaced process cannot borrow a receipt.
Reason: This isolated source stage has host parser, dispatcher, admission, format, Clippy and native downlink checks, but no fresh signed packaged Android build or emulator run. Optional JNI capture is not executable in the host environment.
Required environment or artifact: Coordinator-owned fresh full product build and the complete Voyemu install, boot, page transition and uninstall sequence under SELinux Enforcing, including all-disabled and wrong-peer or stale-lifetime evidence. Device and vehicle acceptance remain separate.

### Unverified: exact-qnx-and-vehicle-acceptance

Maps: Requirement `Delivery does not imply native application`; Scenario `Desired changes before a verified receipt arrives`.
Unavailable observation: Exact QNX and physical gauge font lifecycle through mTLS, startup, enable/disable/reload and recovery.
Reason: Host cryptographic tests and QNX cross-build do not observe native font readbacks or physical output.
Required environment or artifact: Release-bound paired QNX guest and exact firmware vehicle, with native readback and rollback evidence.
