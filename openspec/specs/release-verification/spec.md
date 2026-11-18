# Release verification specification

## Purpose

Define repository gates and prevent evidence from crossing environment boundaries.

## Requirements

### Requirement: Host verification covers all implementation languages

The host gate SHALL run workspace Rust formatting, Clippy with warnings denied, workspace tests, C/C++ formatting checks, injector and implant harnesses, product-manifest and appended native-signature tests, the versionless daemon topology gate, the read-only CI ownership contract, strict OpenSpec validation and the English-only OpenSpec gate.

#### Scenario: Rust formatting differs

- **WHEN** `cargo fmt --all -- --check` reports a diff
- **THEN** the host gate fails

#### Scenario: A crash boundary yields a mixed release

- **WHEN** the update failure-injection suite observes mixed live identities
- **THEN** the workspace test gate fails

# Unverified: Aggregate host verification

### Requirement: Native coverage executes production translation units

Linux CI SHALL compile and execute the actual `injector.c`, `elf_resolve.c` and `implant.cpp` translation units with LLVM line and branch instrumentation. The gate SHALL require named production entrypoints and nonzero line/branch execution in each file instead of accepting an aggregate percentage. Android ARM register, linker namespace and ART/JNI branches MAY remain outside the host gate only while their exact OpenSpec target limitations remain explicit.

#### Scenario: A helper-only harness drops a production translation unit

- **WHEN** coverage no longer contains one required production file or named entrypoint
- **THEN** the coverage policy fails even if aggregate helper coverage remains high

# Gate: make coverage

Gate contract: Production native line and branch execution.
Maps: Requirement `Native coverage executes production translation units`; Scenario `A helper-only harness drops a production translation unit`.
Preconditions: Linux Clang builds the required native host harnesses with LLVM coverage instrumentation.
Observable result: Actual injector, target-memory and implant exported entrypoints execute, and every required production file reports covered lines and branches without an aggregate percentage threshold.
Evidence boundary: Linux host production entry and pre-Android boundaries; ARM remote execution, Android linker namespace, ART/JNI, SELinux Enforcing and vehicle behavior remain outside this gate.

### Requirement: Required component gates are reachable from read-only CI

Ordinary CI SHALL execute the complete `npm run check:tooling` graph through one canonical Make target after lockfile installation. It SHALL fetch recursive pinned submodules without retained checkout credentials, then run lint, workspace and native tests, Linux native coverage, and a host validation build in canonical order. Component CI SHALL contain no product signing, release request, release event, artifact upload, tag, channel or publication authority.

#### Scenario: A tooling test exists only in package.json

- **WHEN** CI no longer invokes the complete canonical tooling target
- **THEN** the workflow contract test rejects the gate graph

#### Scenario: Release coordination returns to the component workflow

- **WHEN** CI receives a private role, write permission, release event, artifact upload or additional release workflow
- **THEN** the repository workflow contract rejects the graph

# Gate: node tools/test-release-workflow.ts

Gate contract: Required component gate wiring and release authority exclusion.
Maps: Requirement `Required component gates are reachable from read-only CI`; Scenarios `A tooling test exists only in package.json`, `Release coordination returns to the component workflow`.
Preconditions: The named test reads the exact workflow inventory, canonical CI and product-neutral native export adapter.
Observable result: CI reaches the complete component verification sequence while release, signing, upload, event and write-authority mutations are rejected.
Evidence boundary: Host repository topology; hosted execution, Android cross-build, product signing and publication are not observed.

### Requirement: Native assembly has one production SELinux path

The installer, daemon, Restore and uninstaller feature sets SHALL be empty. Ordinary build, signing, inventory, AVD and publication adapters SHALL use the same production SELinux and init path. The unsigned exporter SHALL reject any retired emulator marker, unsafe input or extra output before signing.

#### Scenario: A retired emulator marker enters native assembly

- **WHEN** a native input contains a retired emulator marker
- **THEN** the unsigned exporter rejects the input before signing

# Gate: node tools/test-prepare-beta1-unsigned.ts
Gate contract: The production native export rejects retired profile bytes.
Maps: Requirement `Native assembly has one production SELinux path`; Scenario `A retired emulator marker enters native assembly`.
Preconditions: Production native inputs and the NDK readelf tool are available.
Observable result: Ten canonical inputs are accepted and an injected marker is rejected.
Evidence boundary: Host artifact export; Android runtime enforcement is established separately.

### Requirement: Uninstall host verification pins the terminal init services

The uninstall host gate SHALL pin the terminal rc bytes, fixed executable path, restartable successor, one-shot watchdog and `voboost_uninstall` domain. The permanent rc SHALL predeclare both services before terminal cleanup begins.

#### Scenario: A terminal service changes path or domain

- **WHEN** the terminal rc changes a fixed path, domain or restart contract
- **THEN** the uninstall host verification gate fails that contract

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_hook_is_exact_fixed_path_and_loaded_teardown_domain -- --exact
Gate contract: Exact named verification for Uninstall host verification pins the terminal init services.
Maps: Requirement `Uninstall host verification pins the terminal init services`; Scenario `A terminal service changes path or domain`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification pins invocation authority

The uninstall host gate SHALL pin the permanent authority inventory, the single stable `/data/voboost/voboost-uninstall` path, root identity, exact argv and init parent.

#### Scenario: Recovery invocation comes from a shell

- **WHEN** root invokes the stable uninstaller with the correct argument but a non-init parent
- **THEN** the host authorization test rejects mutation

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::marker_and_closed_operation_guards_are_exact -- --exact
Gate contract: Exact named verification for Uninstall host verification pins invocation authority.
Maps: Requirement `Uninstall host verification pins invocation authority`; Scenario `Recovery invocation comes from a shell`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::primary_invocation_pins_marker_path_root_init_parent_and_empty_argv -- --exact
Gate contract: Exact named verification for Uninstall host verification pins invocation authority.
Maps: Requirement `Uninstall host verification pins invocation authority`; Scenario `Recovery invocation comes from a shell`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::watchdog_invocation_requires_fixed_path_root_init_and_exact_argv -- --exact
Gate contract: Exact named verification for Uninstall host verification pins invocation authority.
Maps: Requirement `Uninstall host verification pins invocation authority`; Scenario `Recovery invocation comes from a shell`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification pins the cleanup boot

The uninstall host gate SHALL admit terminal cleanup only while the observed boot ID equals the bound cleanup boot. A changed boot before exact zero SHALL fail closed because the loaded patched-policy teardown domain is no longer proven.

#### Scenario: The boot changes before cleanup

- **WHEN** terminal proof observes a different boot ID
- **THEN** the host transition test rejects terminal authority

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_cleanup_requires_the_bound_current_boot_and_zero_preconditions -- --exact
Gate contract: Exact named verification for Uninstall host verification pins the cleanup boot.
Maps: Requirement `Uninstall host verification pins the cleanup boot`; Scenario `The boot changes before cleanup`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification pins monotonic recovery phases

The uninstall host gate SHALL cover the complete ordered recovery phase model and prove that every interruption resumes the same phase or its exact successor without returning to an earlier phase.

#### Scenario: Recovery restarts at every phase boundary

- **WHEN** the host model interrupts each ordered recovery phase
- **THEN** every restart resumes monotonically and reaches terminal proof

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::every_terminal_operation_cut_repeats_before_successor_publication -- --exact
Gate contract: Exact named verification for Uninstall host verification pins monotonic recovery phases.
Maps: Requirement `Uninstall host verification pins monotonic recovery phases`; Scenario `Recovery restarts at every phase boundary`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification rejects substituted recovery authority

The uninstall host gate SHALL bind the signed stable uninstaller, correlated transaction state and root-zone inode and SHALL reject a substituted path, link or identity.

#### Scenario: Recovery authority is substituted

- **WHEN** a fixed recovery member, bound inode or executable identity differs
- **THEN** the host authority test rejects teardown progress

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::recovery_authority_is_strict_and_binds_the_zone_inode -- --exact
Gate contract: Exact named verification for Uninstall host verification rejects substituted recovery authority.
Maps: Requirement `Uninstall host verification rejects substituted recovery authority`; Scenario `Recovery authority is substituted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::trusted_context_is_bound_to_the_already_opened_inode -- --exact
Gate contract: Exact named verification for Uninstall host verification rejects substituted recovery authority.
Maps: Requirement `Uninstall host verification rejects substituted recovery authority`; Scenario `Recovery authority is substituted`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification rejects a substituted recovery hook

The uninstall host gate SHALL pin the complete recovery hook bytes and reject an appended, truncated or otherwise substituted hook.

#### Scenario: Recovery hook bytes are replaced

- **WHEN** the installed hook differs from the fixed recovery-only bytes
- **THEN** the host hook test rejects recovery progress

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::substituted_recovery_hook_bytes_are_rejected -- --exact
Gate contract: Exact named verification for Uninstall host verification rejects a substituted recovery hook.
Maps: Requirement `Uninstall host verification rejects a substituted recovery hook`; Scenario `Recovery hook bytes are replaced`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Uninstall host verification pins terminal zero inventory

The uninstall host gate SHALL admit terminal completion only after the complete fixed temporary, package-data and product inventory is absent.

#### Scenario: One terminal inventory member remains

- **WHEN** the host model retains any fixed temporary or managed product member
- **THEN** terminal cleanup remains incomplete

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_cleanup_requires_the_bound_current_boot_and_zero_preconditions -- --exact
Gate contract: Exact named verification for Uninstall host verification pins terminal zero inventory.
Maps: Requirement `Uninstall host verification pins terminal zero inventory`; Scenario `One terminal inventory member remains`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_absence_contract_names_every_fixed_temp_and_app_data_alias -- --exact
Gate contract: Exact named verification for Uninstall host verification pins terminal zero inventory.
Maps: Requirement `Uninstall host verification pins terminal zero inventory`; Scenario `One terminal inventory member remains`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Release native payloads are present and use static C++ linkage

Release verification SHALL require an actual `libimplant.so` and `liblsplant.so` ELF for both `arm64-v8a` and `armeabi-v7a`. Each file SHALL be ET_DYN, identify the expected target machine, expose a dynamic section, carry its exact SONAME and contain only its closed NEEDED set. That set SHALL exclude `libc++_shared.so`.

#### Scenario: One ABI payload is absent

- **WHEN** an ABI payload is absent, is renamed ET_REL, has the wrong machine or changes its dynamic-link identity
- **THEN** native payload verification fails

# Gate: make test-built-native-payload
Gate contract: Exact two-ABI native payload identity.
Maps: Requirement `Release native payloads are present and use static C++ linkage`; Scenario `One ABI payload is absent`.
Preconditions: Release-mode `libimplant.so` and `liblsplant.so` artifacts exist at both fixed ABI paths and NDK r29 supplies `llvm-readelf`.
Observable result: The dedicated artifact test rejects a missing file, ET_REL input, wrong target machine, missing dynamic section, wrong SONAME, unexpected NEEDED entry or `libc++_shared.so` dependency.
Evidence boundary: Exact host inspection of already-built ELF artifacts; compilation, device loading, ART integration and vehicle behavior are not inferred.

### Requirement: Restore bootstrap is a distinct hardened Android PIE artifact

Release verification SHALL require one ARM64 Android PIE `voboost-restore`. It SHALL be ET_DYN, identify AArch64, use `/system/bin/linker64`, require only `libc.so` and `libdl.so`, enable BIND_NOW, PIE and GNU_RELRO, keep a non-executable stack, remain within the bootstrap signature size bound and be published under the distinct `restore` manifest role. The artifact SHALL NOT be a renamed `voboost-uninstall` binary.

#### Scenario: The restore executable violates the PIE contract

- **WHEN** the restore input is absent, has the wrong machine or interpreter, is not hardened PIE ET_DYN, has an extra dynamic dependency, lacks BIND_NOW/GNU_RELRO/NX stack or exceeds the bootstrap bound
- **THEN** release verification fails before signing

# Gate: make test-built-restore
Gate contract: Exact ARM64 restore bootstrap identity.
Maps: Requirement `Restore bootstrap is a distinct hardened Android PIE artifact`; Scenario `The restore executable violates the PIE contract`.
Preconditions: `make build-restore` has produced the fixed unsigned Android artifact, `make build-uninstall` has produced its comparison artifact, and NDK r29 supplies `llvm-readelf`.
Observable result: The gate accepts only a bounded hardened AArch64 Android PIE and rejects byte identity with `voboost-uninstall`.
Evidence boundary: Host inspection of built unsigned ELF files; appended signature, protected CI execution, installation, stock-policy execution and restore are not inferred.

### Requirement: Restore document is product-owned and firmware-independent

This native repository SHALL NOT author `restore.json`. Product release tooling alone SHALL derive the canonical shared `RestoreDocument` from the exact source definition and restorable rows of `voboost.json`, then sign its exact bytes with the restore role. Native Install, Restore, daemon inspection and Uninstall SHALL consume the same strict document containing only `schemaVersion`, product `releaseIdentity`, `sourceDefinitionSha256` and `restorableClosureSha256`. The document SHALL contain no operation field, APK/catalog projection, component release identity, firmware version, model fingerprint, stock-policy size or digest, vehicle identity, or device-derived value. The device restore operation SHALL observe and adopt the current stock policy as its new baseline.

#### Scenario: Restore document contains a firmware fingerprint

- **WHEN** authoring receives a firmware identity, stock-policy digest, or other device-derived compatibility field
- **THEN** it rejects the input before the restore document is signed

# Gate: cargo test --manifest-path contract/Cargo.toml release::tests::restore_fixture_is_canonical_but_requires_exact_product_binding -- --exact
Gate contract: Exact product-owned restore document and canonical bytes.
Maps: Requirement `Restore document is product-owned and firmware-independent`; Scenario `Restore document contains a firmware fingerprint`.
Preconditions: The shared contract receives the product fixture and a field-expanded or product-mismatched variant.
Observable result: The production parser accepts only the exact four-field canonical document and its product binding.
Evidence boundary: Host contract behavior only; product authoring, protected signing, current-policy adoption, reboot, and vehicle behavior remain separate evidence.

### Requirement: Native repository exports versionless product inputs

This repository SHALL export only the fixed unsigned native input set consumed by product-owned `voboost.json` composition. It SHALL NOT author or sign `voboost-inject.json`, assign product SemVer to a daemon build, or own a native release channel. The export SHALL preserve the exact daemon, role executables, runtime libraries and init bytes produced by their source builds.

#### Scenario: Product SemVer changes while native inputs do not

- **WHEN** product composition selects another release identity without changing native source or public roots
- **THEN** the native export and daemon build input graph contain no product version value

# Gate: node tools/test-daemon-versionless.ts
Gate contract: Versionless daemon and product-owned manifest topology.
Maps: Requirement `Native repository exports versionless product inputs`; Scenario `Product SemVer changes while native inputs do not`.
Preconditions: The source gate inspects daemon build inputs, module reachability, runtime polling and product manifest publication.
Observable result: No product version or legacy native-manifest input reaches the daemon build or runtime owner.
Evidence boundary: Source and build-input topology; independent Android rebuild byte equality and product composition run separately.

# Gate: make test-prepare-beta1-unsigned
Gate contract: Exact unsigned native export.
Maps: Requirement `Native repository exports versionless product inputs`; Scenario `Product SemVer changes while native inputs do not`.
Preconditions: All required Android native artifacts have been built from the same source and public roots.
Observable result: The adapter exports the exact fixed native input inventory without signing or version authoring.
Evidence boundary: Host export verification; protected product signing, device installation and publication are not exercised.

### Requirement: Native release artifacts do not embed the build host path

Every Android Rust, C and C++ build entry point SHALL map the repository root to `/src/voboost-inject`. Rust SHALL use `--remap-path-prefix`; Clang, ndk-build and CMake SHALL receive file, debug and macro prefix maps. Signed or unsigned release inputs SHALL NOT contain the developer workspace path or ephemeral role-key directory path.

#### Scenario: One native build omits prefix remapping

- **WHEN** a built daemon, installer, uninstaller, restore executable or SELinux program contains the workspace or temporary role-key path
- **THEN** release verification fails before signing or assembly

# Gate: make test-native-reproducible-paths
Gate contract: Native host-prefix remapping.
Maps: Requirement `Native release artifacts do not embed the build host path`; Scenario `One native build omits prefix remapping`.
Preconditions: Android build artifacts exist for the Rust and C native roles.
Observable result: Every build entry point carries the required remap flags and every inspected artifact omits host and temporary-key prefixes.
Evidence boundary: Host artifact string inspection; byte-for-byte reproducibility across independent hosts and protected CI signing are not inferred.

### Requirement: Evidence levels remain separate

Host tests, Android cross-build, packaged release, protected-key CI, rooted-device Enforcing, live injection and vehicle behavior SHALL be reported as separate evidence levels.

#### Scenario: Host and cross-build gates pass

- **WHEN** no packaged or target run was performed
- **THEN** the result does not claim publication, production activation, target injection or vehicle safety

# Unverified: External runtime evidence

### Requirement: Production project sources cross-build for both target ABIs

Only after `check-ndk` proves NDK r29, `build-injector` and `build-implant` SHALL compile project-owned production sources for both `arm64-v8a` and `armeabi-v7a`. The production `injector.c` SHALL compile for both ABIs. The production `implant.cpp` SHALL compile and link with `c++_static` for both ABIs.

#### Scenario: One ABI no longer compiles

- **WHEN** the NDK r29 production cross-build runs
- **THEN** the native gate fails before release assembly

# Unverified: Production Android cross-build

### Requirement: Third-party native provenance has one armv7 Dobby exception

The release build SHALL use reachable pinned upstream Dobby and LSPlant submodule identities. Before compilation it SHALL accept only the clean pinned checkout or the byte-exact state produced by each SHA-256-pinned parent patch, and SHALL apply that patch only in a Git-identified build copy under `build/third-party-source/`, leaving the live source checkout unchanged. Unexpected tracked, untracked or nested build-copy drift SHALL fail before compilation. It SHALL build Dobby for `arm64-v8a` and LSPlant for both target ABIs from those prepared sources. Because the pinned upstream Dobby ARM port does not build for `armeabi-v7a`, that ABI SHALL use only the committed `prebuilt/armeabi-v7a/libdobby.a` exception whose exact SHA-256, Git blob and honest unknown-source-commit record are pinned in the repository. The exception SHALL NOT be described as a from-source build.

#### Scenario: The committed armv7 Dobby exception changes

- **WHEN** its archive identity, tracked status or provenance record differs from the pinned exception
- **THEN** release verification fails before assembly

# Gate: make test-third-party-source-contract
Gate contract: Third-party native provenance has one armv7 Dobby exception host contract.
Maps: Requirement `Third-party native provenance has one armv7 Dobby exception`; Scenario `The committed armv7 Dobby exception changes`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: release verification fails before assembly.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.


# Gate: make test-clean-checkout-contract
Gate contract: Third-party native provenance has one armv7 Dobby exception host contract.
Maps: Requirement `Third-party native provenance has one armv7 Dobby exception`; Scenario `The committed armv7 Dobby exception changes`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: release verification fails before assembly.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.


# Gate: make test-armv7-dobby-prebuilt
Gate contract: Third-party native provenance has one armv7 Dobby exception host contract.
Maps: Requirement `Third-party native provenance has one armv7 Dobby exception`; Scenario `The committed armv7 Dobby exception changes`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: release verification fails before assembly.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.
## Unverified

### Unverified: External runtime evidence

Maps: Requirement `Evidence levels remain separate`; Scenario `Host and cross-build gates pass`.
Unavailable observation: Packaged release verification, protected-key publication, rooted-device behavior, SELinux Enforcing operation, live OEM injection and vehicle behavior.
Reason: Host and cross-build checks cannot observe those external environments.
Required environment or artifact: Exact packaged bytes, protected workflow evidence, a named rooted Android target and the named vehicle firmware environment.

### Unverified: Aggregate host verification

Maps: Requirement `Host verification covers all implementation languages`; Scenarios `Rust formatting differs` and `A crash boundary yields a mixed release`.
Unavailable observation: The complete aggregate host gate across formatting, lint, all language suites and OpenSpec checks.
Reason: The commands are broad suites or non-behavioral checks, not exact named behavioral tests.
Required environment or artifact: A clean host workspace running the complete repository verification sequence.

### Unverified: Production Android cross-build

Maps: Requirement `Production project sources cross-build for both target ABIs`; Scenario `One ABI no longer compiles`.
Unavailable observation: Successful NDK r29 production compilation and linkage for both ABIs.
Reason: The Make targets are build operations rather than exact named tests and mutate outputs.
Required environment or artifact: NDK r29, a clean isolated workspace and an exact cross-build test.
