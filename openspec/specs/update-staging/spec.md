# Update staging specification

## Purpose

Define descriptor-bound product candidate admission without a component-specific release channel or native manifest.

## Requirements

### Requirement: Product OTA is descriptor-bound

The app SHALL hand the daemon one exact signed canonical `voboost.json`, its raw `release-catalog` signature and only the changed artifact descriptors through the authenticated local OTA socket. The daemon SHALL verify descriptor metadata, size, SHA-256, manifest signature, canonical artifact order and exact changed-subset equality before retaining any candidate byte. The daemon SHALL NOT read a host path, shell command, URL, `voboost-inject.json`, `update-ready.json` or `update-ack.json` as update authority.

#### Scenario: Descriptor count or identity differs

- **WHEN** a proposal omits a descriptor, adds one, reorders it or substitutes its inode or digest
- **THEN** the daemon rejects the proposal before durable product admission

# Gate: cargo test -p voboost-daemon ota_transport::tests::missing_extra_and_trailing_descriptors_fail_closed -- --exact
Gate contract: Exact descriptor inventory.
Maps: Requirement `Product OTA is descriptor-bound`; Scenario `Descriptor count or identity differs`.
Preconditions: The host socketpair test sends missing, extra and trailing descriptors around one canonical request.
Observable result: Every non-exact descriptor inventory is rejected without a proposal call.
Evidence boundary: Host Unix descriptor transport; Android peer labels and storage durability are not exercised.

### Requirement: Product proposals become durable before pending

After verification, the daemon SHALL bind the opaque product transaction ID in `recovery/<transactionId>/product-proposal.json`, copy only declared changed bytes into `install/<transactionId>/candidate`, reconstruct the complete product closure in fresh root-owned storage and return `pending` only after the corresponding WAL state is durable. Exact replay SHALL resume the same candidate; the same transaction ID with different product identity SHALL fail. The reconstructed closure SHALL contain exactly every `voboost.json` artifact plus `voboost.json` and `voboost.json.sig`.

#### Scenario: Admission is interrupted and replayed

- **WHEN** the same signed candidate is replayed before and after its durable proposal WAL
- **THEN** copying resumes for the same identity and a colliding identity is rejected

# Gate: cargo test --manifest-path daemon/Cargo.toml ota_transport::tests::production_replay_binds_one_transaction_to_one_candidate -- --exact
Gate contract: Durable product proposal replay.
Maps: Requirement `Product proposals become durable before pending`; Scenario `Admission is interrupted and replayed`.
Preconditions: The host test interrupts descriptor copying and reconstructs the production backend from the same root.
Observable result: Exact replay resumes, while same-ID substitution is rejected.
Evidence boundary: Host filesystem, descriptors and process-local locking; Android fsync hardware durability is not observed.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::complete_candidate_inventory_rejects_missing_extra_link_and_hash -- --exact
Gate contract: Exact complete product closure.
Maps: Requirement `Product proposals become durable before pending`; Scenario `Admission is interrupted and replayed`.
Preconditions: The host test materializes the full signed product inventory and substitutes missing, extra, linked and wrong-hash members.
Observable result: Only the exact manifest plus signature and declared artifact closure verifies.
Evidence boundary: Host root-owned directory semantics; Android SELinux labels are not exercised.

### Requirement: Candidate transfer is bounded and offline

The daemon SHALL stream descriptor bytes through fixed 64 KiB buffers and SHALL retain no aggregate product body. Missing bytes SHALL fail admission; the daemon SHALL not resolve endpoints, hold download credentials or fetch replacement bytes.

#### Scenario: A product candidate contains many changed artifacts

- **WHEN** the daemon verifies and retains a multi-artifact descriptor handoff
- **THEN** each member is processed with a fixed buffer and no aggregate candidate allocation

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::descriptor_admission_uses_fixed_chunks_without_aggregate_body_buffers -- --exact
Gate contract: Bounded offline descriptor transfer.
Maps: Requirement `Candidate transfer is bounded and offline`; Scenario `A product candidate contains many changed artifacts`.
Preconditions: The source-level host test inspects the descriptor verifier and trusted descriptor copier.
Observable result: Both paths use fixed 64 KiB chunks and allocate no body-sized `Vec`.
Evidence boundary: Host source topology; target RSS and network syscall absence require integration evidence.

### Requirement: Uninstall preempts product admission

The resident loop SHALL stop polling the OTA socket when an uninstall request, prepared uninstall authority or in-memory uninstall freeze exists. Irreversible uninstall publication SHALL additionally require no durable `product-proposal.json` transaction. The daemon SHALL leave an existing product WAL intact for its product recovery owner.

#### Scenario: Uninstall authority exists during a daemon iteration

- **WHEN** any uninstall fence is present
- **THEN** the iteration performs neither OTA polling nor incoming generation activation

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::production_daemon_iteration_excludes_activation_for_every_uninstall_authority -- --exact
Gate contract: Uninstall preempts new product admission.
Maps: Requirement `Uninstall preempts product admission`; Scenario `Uninstall authority exists during a daemon iteration`.
Preconditions: The host state-machine test enumerates request, prepared and frozen uninstall authority.
Observable result: No OTA or incoming activation call occurs in any enumerated state.
Evidence boundary: Host state-machine ordering; Android scheduling is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::uninstall_fence_requires_product_candidate_authority_to_be_idle -- --exact
Gate contract: Durable product WAL excludes uninstall commit.
Maps: Requirement `Uninstall preempts product admission`; Scenario `Uninstall authority exists during a daemon iteration`.
Preconditions: The host test compares an idle recovery root with one trusted product WAL.
Observable result: Only the idle root admits the uninstall fence.
Evidence boundary: Host trusted-directory semantics; complete uninstall execution is not exercised.

### Requirement: Explicit reapply uses a fresh complete-closure intent

The root-only `--reapply-offline-product <expected-active-manifest-sha256> <stage-hex64>` command SHALL bind the fresh stage ID as its transaction ID and admit every signed manifest artifact without removing canonical intent, configuration or vehicle state. Existing active operations SHALL block another intent. A consumed stage SHALL remain available for recovery with a protected receipt bound to stage, operation and signed manifest identities.

#### Scenario: The same release is explicitly reapplied

- **WHEN** the operator supplies a fresh stage ID and the inspected active content identity
- **THEN** the complete signed artifact set belongs to that new transaction and replay resumes the same intent

# Gate: cargo test -p voboost-daemon product_candidate::tests::explicit_reapply_uses_fresh_intent_full_closure_and_retains_consumed_stage -- --exact
Gate contract: Fresh explicit full-closure intent.
Maps: Requirement `Explicit reapply uses a fresh complete-closure intent`; Scenario `The same release is explicitly reapplied`.
Preconditions: A complete signed same-release fixture and current active hash are supplied.
Observable result: The fresh transaction retains all artifacts and consumed stage bytes; duplicate intent is idempotent and stale hashes or malformed IDs fail.
Evidence boundary: Host admission; device activation is separate.

### Requirement: Stage preparation preserves previous recovery inputs

`--prepare-offline-stage <stage-hex64>` SHALL create only the requested private empty stage after verifying every sibling's root-owned consumed receipt, exact signed manifest and complete artifact closure. A sibling without a verified terminal lifecycle SHALL block preparation. Once terminal lifecycle is verified, its protected terminal receipt SHALL remain valid across later completed operations. Preparation SHALL not remove previous stage files.

#### Scenario: A previous stage is consumed but its operation is incomplete

- **WHEN** a new stage is requested before terminal lifecycle evidence exists
- **THEN** preparation rejects it and preserves every previous byte

# Gate: cargo test -p voboost-daemon product_candidate::tests::offline_stage_preparation_requires_verified_terminal_consumption_and_preserves_bytes -- --exact
Gate contract: Nondeleting terminal-stage preparation.
Maps: Requirement `Stage preparation preserves previous recovery inputs`; Scenario `A previous stage is consumed but its operation is incomplete`.
Preconditions: A signed complete stage has a consumed receipt before and after a completed operation.
Observable result: Incomplete lifecycle blocks; completed lifecycle creates only the exact new stage and retains the old signed bytes; unexpected files block.
Evidence boundary: Host protected filesystem lifecycle; desktop transport and device activation are separate.

# Unverified: Target daemon network absence

## Unverified

### Unverified: Target daemon network absence

Maps: Requirement `Candidate transfer is bounded and offline`; Scenario `A product candidate contains many changed artifacts`.
Unavailable observation: The production Android daemon performs no DNS resolution or outbound connection while candidate bytes are missing.
Reason: Source topology does not observe all target syscalls.
Required environment or artifact: A supported target daemon trace under syscall or network-namespace observation.
