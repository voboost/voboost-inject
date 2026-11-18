# Update activation specification

## Purpose

Define activation of one signed product candidate across generation, APK, native and protected-system roles.

## Requirements

### Requirement: Product identity comes only from the active signed manifest

The daemon SHALL derive the installed release identity from the canonical SemVer string in the verified active `voboost.json` and SHALL bind it to the SHA-256 of those exact manifest bytes. Status, OTA freshness, operation projection and post-activation decisions SHALL use that pair. The daemon binary SHALL contain no build-time product release channel, base version or beta and SHALL not publish a component version.

#### Scenario: Product versions change without native source or trust-root changes

- **WHEN** two product source definitions select different canonical SemVer values but use the same daemon sources and public trust roots
- **THEN** the daemon build input graph is identical and contains neither product version

# Gate: node tools/test-daemon-versionless.ts
Gate contract: Versionless daemon build and topology.
Maps: Requirement `Product identity comes only from the active signed manifest`; Scenario `Product versions change without native source or trust-root changes`.
Preconditions: The source gate inspects daemon build inputs, the wrapper, module graph, runtime polling and product publication order.
Observable result: No product-version build input exists, legacy native update modules are unreachable and `product_candidate` remains the product owner.
Evidence boundary: Deterministic input-graph evidence; byte-for-byte Android rebuild equality still requires two clean cross-builds with identical toolchains.

### Requirement: Generation-only activation needs no reboot

A candidate whose changed artifacts require only agent-generation and restore-authority activation SHALL prepare and switch one verified immutable generation, publish the updated uninstall inventory, then publish the product manifest pair last. Any APK, native executable, runtime library, init or SELinux change SHALL reject this plan before live mutation.

#### Scenario: One agent and restore authority change

- **WHEN** the changed subset contains one agent DEX plus `restore.json` and `restore.json.sig`
- **THEN** one no-reboot product transaction commits the complete new product

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::realistic_one_agent_release_keeps_restore_pair_atomic_without_reboot -- --exact
Gate contract: Generation-only product activation.
Maps: Requirement `Generation-only activation needs no reboot`; Scenario `One agent and restore authority change`.
Preconditions: The host test builds a realistic signed product candidate with one changed agent and restore pair.
Observable result: Activation uses only generation and restore classes and verifies the complete committed product.
Evidence boundary: Host filesystem transaction; target agent loading is not exercised.

### Requirement: APK activation uses observed package identity

An APK plan SHALL return `install-apk` before root mutation and SHALL wait for one authenticated result bound to the exact transaction, APK path, certificate SHA-256, versionCode, size and SHA-256. Cancellation SHALL retire the inactive transaction. A successful observation SHALL continue the same WAL and may combine with generation or native roles without committing an intermediate product manifest.

#### Scenario: Package installation result is substituted

- **WHEN** any observed APK identity field differs from the candidate `voboost.json` row
- **THEN** the daemon rejects the result and does not commit the product

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::apk_only_wrong_path_certificate_version_size_and_hash_fail_closed -- --exact
Gate contract: Exact APK activation acknowledgement.
Maps: Requirement `APK activation uses observed package identity`; Scenario `Package installation result is substituted`.
Preconditions: The host test mutates each path, signer, version, size and digest field.
Observable result: Every substituted identity is rejected.
Evidence boundary: Host package-observation fixture; Android PackageManager is not exercised.

### Requirement: Native activation uses manifest artifacts and one reboot

For changed daemon or runtime-library rows, `product_candidate` SHALL verify the complete candidate manifest, each exact changed body and every appended native role signature, preserve the previous native bytes, switch non-daemon members before the daemon, publish `reboot-required`, and request one init-owned multimedia reboot. After boot it SHALL verify `/proc/self/exe`, the complete installed candidate closure and the uninstall inventory before publishing the manifest pair last. Unchanged artifacts SHALL never be copied or renamed.

#### Scenario: Native and agent roles change together

- **WHEN** one product candidate changes native runtime and agent-generation members
- **THEN** one shared product transaction switches both roles and commits no mixed intermediate release

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::agent_native_and_apk_native_mixed_transactions_commit_one_product -- --exact
Gate contract: Mixed product activation.
Maps: Requirement `Native activation uses manifest artifacts and one reboot`; Scenario `Native and agent roles change together`.
Preconditions: The host test builds agent-native and APK-native candidate combinations.
Observable result: Each combination commits exactly one complete product or rolls back through the same WAL.
Evidence boundary: Host filesystem and reboot fixtures; target reboot and injection are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::native_wrong_signer_hash_abi_and_boot_id_fail_closed -- --exact
Gate contract: Native activation authentication.
Maps: Requirement `Native activation uses manifest artifacts and one reboot`; Scenario `Native and agent roles change together`.
Preconditions: The host test substitutes executable role signer, digest, ABI and boot identity.
Observable result: Every substituted native authority fails closed.
Evidence boundary: Host signature, manifest and boot-ID fixtures; Android init is not exercised.

### Requirement: Native executable signatures remain role-separated

Every executable SHALL retain an appended Ed25519 transcript for exactly one of `daemon`, `install`, `restore`, `uninstall` or `selinux`. Product SemVer SHALL not enter that transcript. A valid signature for one role SHALL fail under every other role.

#### Scenario: A daemon signature is checked as Restore

- **WHEN** exact daemon bytes and trailer are verified with the Restore role
- **THEN** verification rejects the cross-role signature

# Gate: cargo test --manifest-path daemon/Cargo.toml native_binary::tests::appended_signature_is_role_separated_and_exact -- --exact
Gate contract: Native executable role separation.
Maps: Requirement `Native executable signatures remain role-separated`; Scenario `A daemon signature is checked as Restore`.
Preconditions: The host test signs one exact prefix with the daemon transcript and verifies both daemon and Restore roles plus a tampered prefix.
Observable result: Only exact bytes under the daemon role verify.
Evidence boundary: Host fixture key; protected signing custody is outside scope.

### Requirement: Protected Init and SELinux activation uses one helper baton

A candidate that changes `voboost.rc`, `voboost-selinux` or the resulting policy SHALL use the fixed init-owned product-system helper and the same `product-proposal.json`. The helper SHALL receive no host path or command. Candidate init and policy identities, boot transitions and receipts SHALL stay manifest- and transaction-bound. Product recovery SHALL poll a delayed valid receipt with bounded backoff and SHALL keep generation runtime and OTA admission unavailable while startup recovery is degraded.

#### Scenario: A protected-system receipt arrives after daemon restart

- **WHEN** the helper receipt is initially absent or invalid and later becomes exact for the same WAL
- **THEN** bounded recovery resumes the same transaction without admitting unrelated runtime work

# Gate: cargo test --manifest-path daemon/Cargo.toml lifecycle::reboot_tests::persistent_invalid_receipt_has_no_generation_runtime_or_network_path -- --exact
Gate contract: Protected-system degraded recovery isolation.
Maps: Requirement `Protected Init and SELinux activation uses one helper baton`; Scenario `A protected-system receipt arrives after daemon restart`.
Preconditions: The host lifecycle test scripts invalid receipts and records every reachable action.
Observable result: Only bounded product recovery and reboot handoff remain reachable.
Evidence boundary: Host lifecycle model; Android policy loading is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::system_helper_wrong_receipt_correction_progresses_same_wal -- --exact
Gate contract: Corrected helper receipt resumes one WAL.
Maps: Requirement `Protected Init and SELinux activation uses one helper baton`; Scenario `A protected-system receipt arrives after daemon restart`.
Preconditions: The host test replaces a hostile helper receipt with the exact canonical receipt.
Observable result: The corrected receipt advances the same product transaction.
Evidence boundary: Host filesystem and receipt parsing; target helper scheduling is not exercised.

# Unverified: Target multimedia reboot and post-boot commit

## Unverified

### Unverified: Target multimedia reboot and post-boot commit

Maps: Requirement `Native activation uses manifest artifacts and one reboot`; Scenario `Native and agent roles change together`.
Unavailable observation: Android init performs the reboot and the successor daemon verifies and commits the same product transaction.
Reason: Host crash-cut and boot-ID fixtures do not exercise Android init, kernel reboot or SELinux Enforcing.
Required environment or artifact: Frozen emulator cycle followed by production-device SELinux evidence.
