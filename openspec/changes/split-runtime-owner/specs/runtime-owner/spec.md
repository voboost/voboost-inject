# Runtime owner

## ADDED Requirements

### Requirement: A single daemon owns runtime storage

The voboost-daemon process SHALL exclusively serialize runtime state, configuration and canonical file-log mutations. The voboost-inject process SHALL manage target discovery, admission, injection and agent lifecycle through bounded authenticated daemon IPC without a local storage fallback. Shared code SHALL contain no runtime storage or file-log implementation. Offline product transactions SHALL acquire their operation authority and stop the runtime owner before changing its files.

#### Scenario: Inject is unavailable

- **WHEN** injection is unavailable or restarts
- **THEN** daemon state and native vehicle ownership remain independent and inject does not create a second file writer

#### Scenario: Daemon is unavailable

- **WHEN** a client cannot establish the current authenticated daemon session
- **THEN** its storage operation fails without silently writing a local copy

# Unverified: Runtime owner separation acceptance

### Requirement: Native agent execution preserves explicit user intent

The daemon SHALL discover native executors from the accepted generated agent catalog and registry without hardcoded vehicle-agent policies. Native agent executors SHALL cancel queued restoration from an older intent after a durable explicit OFF and SHALL emit commands only with current authority, verified preservation inputs and independent feedback handling. CAN echo SHALL NOT be accepted as ECU application.

#### Scenario: Explicit OFF overtakes old restoration

- **WHEN** OFF is committed before an older queued ON is emitted
- **THEN** the older ON loses emission authority and no UI checkbox is reverted

#### Scenario: A preservation input is unavailable

- **WHEN** a required adjacent CAN field has no valid source in the current epoch
- **THEN** the daemon reports unavailable input and does not substitute zero or emit a partial command

# Unverified: Early native vehicle acceptance

### Requirement: The daemon orders captured native-agent choices

The daemon SHALL serialize captured-choice ordering for registry-declared journals, validate the current boot and capture identity, and persist pending before native admission. Completing a capture SHALL require the latest identity and its canonical option value. Generic journal replacement SHALL NOT replace a registered captured-choice journal. Lost replies SHALL NOT cause the client to reconnect and replay the mutation. Native admission SHALL be revoked before uncertain reads or writes of a newly captured choice.

#### Scenario: Captured choices arrive out of order

- **WHEN** current-boot choices arrive with older or conflicting capture identities
- **THEN** the daemon retains the latest durable choice and distinguishes pending, committed and superseded admission

#### Scenario: Completion precedes canonical commit or belongs to an old choice

- **WHEN** completion has a different identity or its choice is not canonical
- **THEN** pending remains set and native admission remains fenced

#### Scenario: A captured-choice journal is unreadable

- **WHEN** a valid new choice encounters unsafe or unreadable journal storage
- **THEN** it fails without native admission or following a redirected journal path

#### Scenario: Generic journal mutation bypasses captured-choice ordering

- **WHEN** a generic compare-and-swap attempts to replace a registered captured-choice journal
- **THEN** it is rejected without changing the retained choice or its pending fence

#### Scenario: A prepare or finish reply is lost

- **WHEN** the owner commits prepare or finish but its reply is interrupted
- **THEN** the client reports unavailable without a second dispatch and the owner retains the committed phase

#### Scenario: A capture belongs to an unknown source, boot or future time

- **WHEN** captured input lacks the declared journal authority or current capture identity
- **THEN** it cannot publish a new captured choice

#### Scenario: A failed capture is followed by an unrelated refresh

- **WHEN** a newly captured choice cannot yet be persisted and another configuration refresh or older delivery follows
- **THEN** its process-local fence and latest ordering remain until durable recovery, without claiming survival of an unpersisted record across process replacement

#### Scenario: Recovery encounters a newer unconfirmed OFF

- **WHEN** an older pending ON and a newer unconfirmed OFF exist in the live owner
- **THEN** old completion cannot unfence the source and owner recovery durably completes the newer OFF

#### Scenario: A conflicting duplicate is followed by the legitimate choice

- **WHEN** an identical captured identity supplies a conflicting choice and the legitimate request is retried
- **THEN** the conflicting choice cannot poison process-local ordering or prevent recovery of the retained legitimate choice

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::prepare_persists_pending_before_admission_and_orders_captured_choices -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `Captured choices arrive out of order`.
Preconditions: A declared native source and generated VOBOOST_NATIVE_REGISTRY are configured; captures arrive newer, older and with conflicting equal identity. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: The latest pending WAL remains byte-identical after superseded or conflicting captures and admission is fenced.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::finish_requires_current_canonical_choice_and_exact_captured_identity -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `Completion precedes canonical commit or belongs to an old choice`.
Preconditions: Prepare has persisted pending; completion is attempted before canonical commit and after a newer capture. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: Only exact current completion after canonical commit clears pending; stale completion preserves the newer WAL.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::unreadable_journal_revokes_admission_before_any_new_capture_write -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `A captured-choice journal is unreadable`.
Preconditions: The native source is admitted and its state-directory path is replaced by a fixture symlink. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: Prepare reports unavailable and revokes admission without following the redirected store.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::generic_journal_cannot_replace_a_declared_captured_choice -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `Generic journal mutation bypasses captured-choice ordering`.
Preconditions: A current pending OFF capture exists and a decoded generic journal replacement requests older committed ON. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: The dispatcher rejects the replacement and retains the exact pending WAL and fence.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon composition::captured_choice_without_ack_keeps_owner_wal_and_never_reconnects -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `A prepare or finish reply is lost`.
Preconditions: The real framed owner and private Store receive each mutation once; the host relay drops the committed reply. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: The client returns unavailable after one connection; pending or completed WAL and canonical choice remain committed.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::captured_authority_rejects_unknown_source_foreign_boot_and_future_time -- --exact
Gate contract: Daemon-owned captured-choice transaction.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `A capture belongs to an unknown source, boot or future time`.
Preconditions: The generated native registry and current owner boot are established. Native tests receive the existing generated agent registry through VOBOOST_NATIVE_REGISTRY.
Observable result: Unknown source or key, foreign boot and future capture publish no journal.
Evidence boundary: Host real Store and filesystem; framed transport where named, with only peer admission bypassed. No CAN, Enforcing, reboot or vehicle application proof.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::failed_capture_remains_fenced_across_refresh_and_older_delivery -- --exact
Gate contract: Process-local captured-choice fencing.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `A failed capture is followed by an unrelated refresh`.
Preconditions: An admitted source encounters a controlled temporary-file collision while capturing OFF. Generated VOBOOST_NATIVE_REGISTRY is configured.
Observable result: Repair and refresh do not restore admission, and an older ON cannot replace the process-local latest capture.
Evidence boundary: Host real Store and filesystem; a never-persisted capture is not proven durable across owner replacement, and no CAN action is exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::recovery_resumes_newest_unconfirmed_off_without_finishing_an_older_on -- --exact
Gate contract: Process-local captured-choice fencing.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `Recovery encounters a newer unconfirmed OFF`.
Preconditions: An earlier ON is pending and a newer OFF failed its first WAL write in the same live owner. Generated VOBOOST_NATIVE_REGISTRY is configured.
Observable result: Old completion remains blocked; recovery commits the newer OFF and its exact identity.
Evidence boundary: Host real Store and filesystem; a never-persisted capture is not proven durable across owner replacement, and no CAN action is exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::intent::tests::conflicting_duplicate_does_not_poison_legitimate_retry_or_recovery -- --exact
Gate contract: Conflicting duplicates do not poison captured-choice recovery.
Maps: Requirement `The daemon orders captured native-agent choices`; Scenario `A conflicting duplicate is followed by the legitimate choice`.
Preconditions: Generated VOBOOST_NATIVE_REGISTRY is configured and a legitimate OFF capture has a durable pending WAL.
Observable result: Conflicting ON is rejected, the legitimate retry succeeds and recovery commits the same OFF identity.
Evidence boundary: Host real Store and filesystem; no CAN or vehicle application is exercised.

## Unverified

### Unverified: Runtime owner separation acceptance

Maps: Requirement `A single daemon owns runtime storage`; Scenarios `Inject is unavailable`, `Daemon is unavailable`.
Unavailable observation: Complete packaged install/update/remove and independent daemon/inject restart in Android Enforcing.
Reason: The process, store, IPC and signing implementations have host checks, but the complete target lifecycle has not been accepted together.
Required environment or artifact: One packaged split-runtime candidate and a fresh owned Android Enforcing machine with independent process identity and storage observations.

### Unverified: Early native vehicle acceptance

Maps: Requirement `Native agent execution preserves explicit user intent`; Scenarios `Explicit OFF overtakes old restoration`, `A preservation input is unavailable`.
Unavailable observation: Early native CAN restoration and cancellation with source-valid preserved inputs and independent ECU feedback.
Reason: Production native Context, TX and Java ownership handover are not yet integrated and accepted on the target.
Required environment or artifact: Implemented native execution, an OEM-faithful CAN emulator, and physical START/wake to independent ECU-feedback measurements for the requested early-start timing.
