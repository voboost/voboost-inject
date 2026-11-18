# Release native trust specification

## Purpose

Define the daemon's product-manifest, native-executable and descriptor trust boundaries.

## Requirements

### Requirement: Product artifacts have one installed authority mapping

Every canonical `voboost.json` artifact role SHALL map to exactly one root-flat, installed-APK or active-generation authority. Root-flat executable modes SHALL be `0700`; root-flat data modes SHALL be `0644`; the product manifest pair SHALL be `0600`. Runtime verification SHALL retain one opened inode and reject missing, linked, substituted, wrong-mode, wrong-size or wrong-digest members.

#### Scenario: A runtime library is substituted

- **WHEN** either ABI runtime member is missing, linked, wrong-mode, wrong-hash or selected for the wrong ABI
- **THEN** daemon product verification rejects it before injection

# Gate: cargo test --manifest-path daemon/Cargo.toml installed_product::tests::runtime_pair_rejects_missing_mode_hash_symlink_hardlink_and_abi_substitution -- --exact
Gate contract: Exact installed runtime authority.
Maps: Requirement `Product artifacts have one installed authority mapping`; Scenario `A runtime library is substituted`.
Preconditions: The host test materializes both ABI rows and mutates each filesystem identity property.
Observable result: Only the exact manifest-bound regular files verify.
Evidence boundary: Host filesystem metadata; Android SELinux labels are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml installed_product::tests::every_product_role_has_one_flat_apk_or_generation_authority -- --exact
Gate contract: Total installed-authority mapping.
Maps: Requirement `Product artifacts have one installed authority mapping`; Scenario `A runtime library is substituted`.
Preconditions: The host test enumerates every schema-one product artifact role.
Observable result: Every role has exactly one installed authority class and mode.
Evidence boundary: Host mapping logic; target files are not inspected.

### Requirement: Product manifest verification uses one immutable embedded root

The daemon SHALL verify exact canonical `voboost.json` bytes with the embedded `release-catalog` public root before reading release identity or artifact rows. That root SHALL differ from `agent-catalog`, `native-executable` and `restore`. No verifier, key ID, epoch or fallback SHALL be loaded from device storage. The detached signature SHALL be raw 64-byte Ed25519 over the exact manifest bytes.

#### Scenario: Product bytes carry another role signature

- **WHEN** exact `voboost.json` bytes are signed by agent-catalog, native-executable or restore authority
- **THEN** product verification rejects that signature

# Gate: cargo test --manifest-path daemon/Cargo.toml trust::tests::release_catalog_signature_is_not_accepted_by_any_other_role -- --exact
Gate contract: Product manifest role separation.
Maps: Requirement `Product manifest verification uses one immutable embedded root`; Scenario `Product bytes carry another role signature`.
Preconditions: The host test signs the same bytes with each fixture role key.
Observable result: Only the release-catalog signature verifies as a product manifest.
Evidence boundary: Host embedded fixture roots; protected key custody is outside scope.

# Gate: cargo test --manifest-path contract/Cargo.toml release::tests::product_manifest_signature_is_raw_and_exact_byte_bound -- --exact
Gate contract: Raw exact product signature.
Maps: Requirement `Product manifest verification uses one immutable embedded root`; Scenario `Product bytes carry another role signature`.
Preconditions: The contract test signs canonical bytes and supplies whitespace, transcript and length variants.
Observable result: Only the raw signature over exact canonical bytes verifies.
Evidence boundary: Host cryptographic contract; protected signing is not exercised.

### Requirement: Product manifest schema mirrors the producer corpus

The daemon SHALL use `voboost-contract` for strict canonical schema-one parsing. `releaseIdentity` SHALL be canonical SemVer text. Duplicate, unknown and reordered fields SHALL fail. Artifact filename, role, activation, ABI, size, SHA-256, APK metadata and DEX/catalog identity SHALL obey the shared product schema and bounds.

#### Scenario: Product fixture bytes differ from the canonical schema

- **WHEN** a product fixture contains an unknown field, reordered field, invalid SemVer or noncanonical digest
- **THEN** the shared parser rejects the exact bytes

# Gate: cargo test --manifest-path contract/Cargo.toml release::tests::shared_product_fixture_corpus_matches_canonical_parser -- --exact
Gate contract: Shared product fixture corpus.
Maps: Requirement `Product manifest schema mirrors the producer corpus`; Scenario `Product fixture bytes differ from the canonical schema`.
Preconditions: The contract test reads the shared valid and invalid producer fixture corpus.
Observable result: Only canonical schema-one bytes parse.
Evidence boundary: Host fixture equality; cross-repository artifact transfer is not exercised.

### Requirement: Native executable signatures bind one of five exact roles

The appended `VOBOOST` trailer SHALL authenticate the unchanged ELF prefix through exactly one transcript role: `daemon`, `install`, `restore`, `uninstall` or `selinux`. The transcript SHALL contain no product SemVer. Role, prefix, offset, magic and raw signature SHALL be exact; cross-role verification SHALL fail.

#### Scenario: One signed prefix is checked under all roles

- **WHEN** the same appended signature is verified as each native executable role
- **THEN** only its declared role succeeds

# Gate: cargo test --manifest-path daemon/Cargo.toml native_binary::tests::appended_signature_is_role_separated_and_exact -- --exact
Gate contract: Appended native role verification.
Maps: Requirement `Native executable signatures bind one of five exact roles`; Scenario `One signed prefix is checked under all roles`.
Preconditions: The host test signs a daemon prefix and checks a different role plus tampered bytes.
Observable result: Only the exact daemon transcript succeeds.
Evidence boundary: Host fixture signature; release signing custody is outside scope.

### Requirement: App proposal wire is manifest-digest-bound

The app-to-daemon request SHALL carry an opaque transaction ID, canonical release identity, exact manifest SHA-256 and the ordered changed artifact identities from that manifest. The local transport SHALL pass the manifest, signature and changed bodies only as retained descriptors. Missing, extra, reordered, reused or non-CLOEXEC descriptors and trailing request bytes SHALL fail before admission.

#### Scenario: Descriptor handoff differs from the proposal

- **WHEN** the descriptor list or any declared size, digest, inode or close-on-exec property differs
- **THEN** the daemon rejects the request without retaining candidate bytes

# Gate: cargo test --manifest-path contract/Cargo.toml status::tests::open_descriptor_handoff_binds_manifest_signature_and_changed_bodies -- --exact
Gate contract: Descriptor handoff identity.
Maps: Requirement `App proposal wire is manifest-digest-bound`; Scenario `Descriptor handoff differs from the proposal`.
Preconditions: The contract test mutates every descriptor identity field.
Observable result: Only exact ordered descriptors validate.
Evidence boundary: Host descriptor contract; Android peer authentication is separate.

# Gate: cargo test -p voboost-daemon ota_transport::tests::peer_credentials_are_socket_bound_and_uid_mismatch_is_hostile -- --exact
Gate contract: Local OTA peer authentication.
Maps: Requirement `App proposal wire is manifest-digest-bound`; Scenario `Descriptor handoff differs from the proposal`.
Preconditions: The host transport test supplies matching and foreign socket credentials.
Observable result: Foreign UID is rejected before request parsing or descriptor admission.
Evidence boundary: Host Unix credentials; Android app UID discovery is fixture-backed.

### Requirement: Daemon build consumes no product version or native-manifest root

The daemon build SHALL consume only stable protocol/schema/ABI source, native sources and the four public trust roots it verifies: `agent-catalog`, `release-catalog`, `native-executable` and `restore`. It SHALL not consume product release channel, base version, beta, a native-manifest key or `voboost-inject.json`. Two product definitions with different SemVer and unchanged daemon inputs therefore select the same daemon build graph.

#### Scenario: Product SemVer changes alone

- **WHEN** release composition changes only `voboost.json.releaseIdentity`
- **THEN** no daemon source or build environment input changes

# Gate: node tools/test-daemon-versionless.ts
Gate contract: Versionless daemon input graph.
Maps: Requirement `Daemon build consumes no product version or native-manifest root`; Scenario `Product SemVer changes alone`.
Preconditions: The source gate inspects build script, Make recipe, wrapper and compiled module graph.
Observable result: Product identity and retired native-manifest inputs are absent; product candidate remains reachable.
Evidence boundary: Source/build-input proof; clean Android byte reproducibility is exercised by a separate NDK gate.

# Gate: make test-daemon-versionless-reproducible

Gate contract: Product SemVer does not perturb unchanged daemon bytes.
Maps: Requirement `Daemon build consumes no product version or native-manifest root`; Scenario `Product SemVer changes alone`.
Preconditions: NDK r29, cargo-ndk and the same four public roots are available to two isolated production daemon builds.
Observable result: Two clean Android cross-builds in distinct target directories receive deliberately different retired product-version environment values and produce byte-identical `voboost-daemon` ELF files by `cmp`.
Evidence boundary: Local build reproducibility for one host, toolchain and source tree; protected CI rebuild, signature bytes and physical-device execution remain separate gates.

# Gate: node tools/test-build-key-minimality.ts
Gate contract: Minimal daemon verifier roots.
Maps: Requirement `Daemon build consumes no product version or native-manifest root`; Scenario `Product SemVer changes alone`.
Preconditions: The tooling test inspects every privileged component build script and the product-neutral export adapter.
Observable result: Every privileged consumer excludes native-manifest authority and retains its required product roots.
Evidence boundary: Source build-input topology; final ELF marker inspection is separate.
