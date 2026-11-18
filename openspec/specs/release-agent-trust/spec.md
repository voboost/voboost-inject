# Release agent trust specification

## Purpose

Define authenticated catalogs and exact generation payload identity.

## Requirements

### Requirement: Agent catalog trust is selected before payload parsing or file use

The daemon SHALL bound the catalog bytes and verify the raw 64-byte Ed25519 signature with the immutable embedded `agent-catalog` root over all catalog bytes including the final LF. It SHALL then parse the complete catalog. No catalog payload path SHALL be opened before signature verification and complete validation succeed. Verification SHALL never try multiple keys.

The catalog signature authenticates agent-to-process authority and Voboost payload integrity only. It SHALL NOT be described as runtime firmware, APK, PackageManager, AMS or Java-capability attestation.

#### Scenario: An unauthenticated catalog names a payload path

- **WHEN** signature verification fails over the bounded exact catalog bytes
- **THEN** the daemon opens no catalog payload path and grants no target authority

# Gate: make verify-producer-agent-catalog PRODUCER_AGENT_CATALOG=<producer-agents.json> PRODUCER_AGENT_CATALOG_SIG=<producer-agents.sig> PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM=<producer-public.pem>
Gate contract: Producer catalog authentication compatibility.
Maps: Requirement `Agent catalog trust is selected before payload parsing or file use`; Scenario `An unauthenticated catalog names a payload path`.
Preconditions: The release caller supplies the exact immutable producer catalog, detached signature and matching public role root; the Make target rejects every missing input and executes the standalone verifier binary with three exact paths.
Observable result: The exact producer bytes authenticate and validate before any payload closure is returned.
Evidence boundary: Host fixture authentication; release publication and target file opening are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml trust::tests::verify_signature_rejects_wrong_length -- --exact
Gate contract: Raw catalog signature length admission.
Maps: Requirement `Agent catalog trust is selected before payload parsing or file use`; Scenario `An unauthenticated catalog names a payload path`.
Preconditions: The exact Rust test submits non-64-byte signatures for bounded catalog bytes.
Observable result: Verification rejects each signature before granting catalog authority.
Evidence boundary: Host cryptographic seam; payload filesystem access is not observed.

### Requirement: Agent-catalog root is immutable at runtime

Every signed schema-2 catalog SHALL contain only the exact closed catalog fields and SHALL NOT contain a mutable trust selector. The `agent-catalog` root is replaced only by updating every verifier together; no device-local signing-key state or transition journal exists.

Fresh installation SHALL verify the catalog with the immutable embedded `agent-catalog` root. No alternate catalog schema is accepted.

#### Scenario: Catalog signed by another product role

- **WHEN** a catalog carries a valid signature from another product role
- **THEN** verification rejects that catalog without trying another key

# Gate: cargo test --manifest-path daemon/Cargo.toml trust::tests::role_keys_are_distinct_and_not_interchangeable -- --exact
Gate contract: Exact product-role root selection.
Maps: Requirement `Agent-catalog root is immutable at runtime`; Scenario `Catalog signed by another product role`.
Preconditions: Distinct embedded fixture roots are available.
Observable result: A signature valid for another product role is rejected by the agent-catalog verifier.
Evidence boundary: Host cryptographic evidence; protected production keys are not exercised.

### Requirement: Agent catalog schema binds exact runtime authority

After authentication, the daemon SHALL strictly parse the sole first-release schema version 2 and reject unknown fields, duplicate agent IDs, duplicate targets, unsafe basenames, invalid counts, unsupported ABI, invalid cross-references, invalid SemVer and a mismatched pinned AgentEntry ABI digest. Each agent SHALL declare between one and 64 unique exact targets containing only `process`, `file`, `size`, `sha256`, `platform`, `domain`, `entryAbi`, optional Android `entryClass` and `boot`, and `boot` SHALL be false. An empty list, wildcard process, duplicate process, `boot=true`, `package`, `baseApkPaths`, `signerCertificateSha256`, firmware identity, build fingerprint or version allowlist SHALL reject the complete catalog. The catalog SHALL bind exact process names and exact Voboost core, module and artifact size and SHA-256 integrity. Any other schema version SHALL be rejected.

#### Scenario: A signed catalog contains an unknown field

- **WHEN** signature verification succeeds but strict parsing observes that field
- **THEN** the complete transaction is rejected

#### Scenario: Schema 1 carries OEM identity

- **WHEN** authenticated schema-2 bytes contain an OEM package, APK path, certificate, firmware,
  build fingerprint or version allowlist field
- **THEN** strict parsing rejects the field instead of treating it as runtime attestation

#### Scenario: One agent declares the maximum process set

- **WHEN** an authenticated catalog declares 63 or 64 unique exact process names for one agent
- **THEN** target-count validation accepts that agent authority

#### Scenario: One agent exceeds the process limit

- **WHEN** an authenticated catalog declares 65 process names for one agent
- **THEN** strict parsing rejects the complete catalog

#### Scenario: One agent declares an ambiguous process set

- **WHEN** an authenticated catalog declares no target, repeats a process, uses a wildcard process name, or declares `boot=true`
- **THEN** strict parsing rejects the complete catalog

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::unknown_and_duplicate_fields_fail_closed -- --exact
Gate contract: Strict catalog field admission.
Maps: Requirement `Agent catalog schema binds exact runtime authority`; Scenario `A signed catalog contains an unknown field`.
Preconditions: The exact Rust test injects unknown fields and duplicate identities into authenticated catalog documents.
Observable result: Strict parsing rejects the complete catalog.
Evidence boundary: Host JSON/schema parsing; signature verification is covered separately.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::schema_1_has_no_firmware_or_apk_identity_fields -- --exact
Gate contract: Schema-1 OEM identity exclusion.
Maps: Requirement `Agent catalog schema binds exact runtime authority`; Scenario `Schema 1 carries OEM identity`.
Preconditions: The exact Rust test adds each forbidden OEM identity field to an otherwise valid schema-2 target or catalog.
Observable result: Strict parsing rejects every forbidden field.
Evidence boundary: Host schema parsing only; signed publication and Android runtime behavior are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::agent_target_count_enforces_n_minus_one_n_and_n_plus_one -- --exact
Gate contract: Per-agent target-count admission.
Maps: Requirement `Agent catalog schema binds exact runtime authority`; Scenarios `One agent declares the maximum process set` and `One agent exceeds the process limit`.
Preconditions: The exact Rust test submits otherwise valid schema-2 catalogs with 63, 64 and 65 unique process targets for one agent.
Observable result: The parser accepts 63 and 64 targets and rejects 65 targets.
Evidence boundary: Host catalog parsing; process discovery and Android identity attestation are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::agent_targets_remain_non_empty_unique_and_exact -- --exact
Gate contract: Exact per-agent target identity admission.
Maps: Requirement `Agent catalog schema binds exact runtime authority`; Scenario `One agent declares an ambiguous process set`.
Preconditions: The exact Rust test submits otherwise valid schema-2 catalogs with an empty target list, a duplicate process, a wildcard process and `boot=true`.
Observable result: The parser rejects every ambiguous or boot target set.
Evidence boundary: Host catalog parsing; process discovery and Android identity attestation are not exercised.

### Requirement: Agent catalog carries only target-owned DEX identities

Schema 2 SHALL contain Android `agent-common.dex`. Android targets SHALL declare the exact `android/android/android-java-v1` platform/domain/entryAbi tuple and a versionless `agent-*` DEX identity with `entryClass`. QNX targets SHALL declare `qnx/cluster/voboost-agent3-v1`, exact process `gauge`, a `libagent-<id>.so` identity and no `entryClass`. The root `clusterRuntime` identity SHALL exist exactly when QNX targets exist and name `libvoboost-runtime-cluster.so`. Schema 1 SHALL be rejected without migration. Targets of one logical agent MAY repeat the same exact-case filename only when size, SHA-256 and entry class are identical. The catalog SHALL reject cross-agent sharing, conflicting aliases, case-folded filename collisions, core or reserved filename collisions and duplicate process rows. Release size accounting SHALL count each unique module once. Schema-2 Android targets MAY use distinct DEX basenames; readers SHALL NOT require one producer basename per logical agent. A logical agent row SHALL NOT contain file, size, SHA-256, entry class or required resource artifacts. Top-level `artifacts`, `bundleVersion`, UI APKs and resource geometry SHALL reject the complete catalog.

#### Scenario: A schema-2 catalog carries a legacy UI artifact

- **WHEN** a catalog adds the old top-level Android resource artifact inventory
- **THEN** strict parsing rejects the complete catalog

#### Scenario: One logical agent shares a DEX across target processes

- **WHEN** distinct process rows repeat one exact DEX identity for the same logical agent
- **THEN** catalog validation accepts the aliases and counts the module bytes once
- **AND** schema-2 distinct-file target catalogs remain accepted

#### Scenario: A repeated module identity is ambiguous

- **WHEN** aliases differ in size, SHA-256, entry class, filename case or logical agent, collide with a reserved filename, or repeat a process
- **THEN** catalog validation rejects the complete catalog

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::schema_1_rejects_legacy_embedded_artifact_contract -- --exact
Gate contract: Target-owned external DEX schema.
Maps: Requirement `Agent catalog carries only target-owned DEX identities`; Scenario `A schema-2 catalog carries a legacy UI artifact`.
Preconditions: The exact Rust test adds the old top-level Android resource artifact field to an otherwise valid target-owned catalog.
Observable result: Strict schema parsing rejects the complete catalog.
Evidence boundary: Host catalog parser only; DEX byte contents and Android injection are separate evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::shared_agent_module_accepts_exact_aliases_and_counts_unique_bytes -- --exact
Gate contract: Shared and legacy module identity admission.
Maps: Requirement `Agent catalog carries only target-owned DEX identities`; Scenario `One logical agent shares a DEX across target processes`.
Preconditions: Five process rows share one module whose repeated size would exceed the release bound; a legacy catalog carries 51 distinct module names.
Observable result: Both catalogs parse and shared bytes count once.
Evidence boundary: Host catalog validation only; Android execution and an older native verifier accepting a new shared catalog are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::shared_agent_module_rejects_conflicting_identity_and_foreign_aliases -- --exact
Gate contract: Shared module aliases fail closed.
Maps: Requirement `Agent catalog carries only target-owned DEX identities`; Scenario `A repeated module identity is ambiguous`.
Preconditions: Otherwise valid target rows receive identity conflicts, foreign owners, reserved names, case collisions or duplicate process.
Observable result: Every invalid catalog is rejected.
Evidence boundary: Host catalog validation only.

### Requirement: Stable agent ID allowlist is exact

A stable schema-2 entry SHALL use one of exactly seven allowed IDs: `settings`, `vehicle-drive-forced-ev`, `vehicle-drive-pedestrian-warning`, `keyboard-ru`, `keyboard-en`, `font-cyrillic` or `launcher`. The current producer catalog SHALL use that complete seven-ID set, while another bounded schema-2 catalog MAY contain a subset.

#### Scenario: A stable schema-2 agent uses an unlisted ID

- **WHEN** an otherwise valid stable entry names an agent outside the seven-ID allowlist
- **THEN** strict parsing rejects the complete catalog

# Gate: make verify-producer-agent-catalog PRODUCER_AGENT_CATALOG=<producer-agents.json> PRODUCER_AGENT_CATALOG_SIG=<producer-agents.sig> PRODUCER_AGENT_CATALOG_PUBLIC_KEY_PEM=<producer-public.pem>
Gate contract: Stable agent ID allowlist.
Maps: Requirement `Stable agent ID allowlist is exact`; Scenario `A stable schema-2 agent uses an unlisted ID`.
Preconditions: The mandatory cross-repository gate receives the exact producer catalog, detached signature and producer public key. Its ignored exact Rust test fails when any input is missing, authenticates the exact catalog bytes and compares the producer stable set with the seven allowed IDs. Hermetic parser tests separately reject an unlisted stable ID.
Observable result: The producer set is exact and the unlisted stable entry is rejected.
Evidence boundary: Host catalog parsing; agent implementation availability is not proven.

### Requirement: Selected generation closure is exact

Core, modules and artifacts SHALL use safe unique regular-file basenames and match catalog size and lowercase SHA-256. After authenticating the catalog and verifying the canonical unsigned selection receipt against root facts, the daemon SHALL derive the exact payload closure as core, every `supported` or `unknown` module and the union of their `requiresArtifacts`. Exact-set validation SHALL reject missing, extra or duplicate members, including unsupported modules and unrequired artifacts.

#### Scenario: Selected generation closure has an extra artifact

- **WHEN** staging contains an unsupported module, unrequired artifact or omits one required closure member
- **THEN** exact-set validation rejects the generation before import

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::required_artifact_closure_accepts_exact_and_rejects_missing_or_extra -- --exact
Gate contract: Exact selected generation closure.
Maps: Requirement `Selected generation closure is exact`; Scenario `Selected generation closure has an extra artifact`.
Preconditions: The exact Rust test varies supported, unknown and unsupported modules plus required, missing and extra artifacts.
Observable result: Only the exact selected payload closure is admitted.
Evidence boundary: Host closure derivation; imported file bytes are covered separately.

### Requirement: Imported generation members retain exact file identity

The daemon SHALL reject symlinked, hard-linked, device, FIFO or mutable members. It SHALL import the exact verified receipt bytes and re-open and reverify payloads while copying them to fresh trusted inodes, then repeat descriptor-relative owner, mode, single-link, signed-size and SHA-256 verification for every core, selected module and selected artifact immediately before building a bootstrap envelope.

#### Scenario: A staged module is replaced by a symlink

- **WHEN** import opens the hostile transaction
- **THEN** it rejects the transaction without following the link

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::exact_inventory_rejects_missing_extra_and_linked_entries -- --exact
Gate contract: Imported member filesystem identity.
Maps: Requirement `Imported generation members retain exact file identity`; Scenario `A staged module is replaced by a symlink`.
Preconditions: The exact Rust test supplies missing, extra, symlinked and hard-linked staging members.
Observable result: Import rejects every non-exact inventory without following links.
Evidence boundary: Host filesystem import; Android ownership and SELinux labels are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::bootstrap_use_time_read_rejects_absent_symlink_mode_size_hash_and_tamper -- --exact
Gate contract: Bootstrap use-time member re-verification.
Maps: Requirement `Imported generation members retain exact file identity`; Scenario `A staged module is replaced by a symlink`.
Preconditions: The exact Rust test removes, links, changes mode, size, digest and bytes after import before bootstrap read.
Observable result: Every changed member is rejected before envelope construction.
Evidence boundary: Host generation filesystem; target memfd creation is not exercised.

### Requirement: Chinese catalog text preserves legacy locale compatibility

Localized catalog text SHALL retain required ordered `en` and `ru` fields and MAY include third ordered `zh`. Absent `zh` SHALL preserve the legacy serialized shape. Present Chinese text SHALL be nonempty and bounded; null, duplicate, unknown and out-of-order fields SHALL reject runtime parsing.

#### Scenario: A catalog adds Chinese localized text

- **WHEN** a locale map adds canonical `zh` after its required English and Russian fields
- **THEN** Chinese text is retained while legacy two-language maps continue to parse without a serialized null field

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::chinese_locale_preserves_legacy_maps_and_rejects_malformed_extensions -- --exact

Gate contract: Runtime Chinese catalog locale compatibility.
Maps: Requirement `Chinese catalog text preserves legacy locale compatibility`; Scenario `A catalog adds Chinese localized text`.
Preconditions: Legacy and three-language maps, null, empty, duplicate, unknown and reordered locale inputs.
Observable result: Valid Chinese text is retained, legacy serialization is unchanged and malformed extensions fail.
Evidence boundary: Host runtime parser; payload signature verification and rendered Chinese UI remain separate gates.

# Gate: cargo test -p voboost-daemon --bin voboost-inject catalog::tests::mixed_targets_are_one_agent_and_native_never_enters_android_dispatch -- --exact
Gate contract: Strict mixed-platform target admission.
Maps: Requirement `Agent catalog carries only target-owned DEX identities`; Scenario `One logical agent shares a DEX across target processes`.
Preconditions: One verified catalog has Android and QNX implementations with one logical agent ID.
Observable result: Valid native identity is admitted, native rows never enter ART process discovery, and invalid tuples, native entryClass or missing runtime fail closed.
Evidence boundary: Host parser and target routing; native execution is not inferred.
