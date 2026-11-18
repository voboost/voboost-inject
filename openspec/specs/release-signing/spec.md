# Release signing specification

## Purpose

Define the native artifact signing boundary without giving the component repository product release or publication authority.

## Requirements

### Requirement: The component exports only unsigned product inputs

`tools/prepare-beta1-unsigned.sh <output-dir>` SHALL export exactly ten flat inputs named `voboost-daemon`, `voboost-install`, `voboost-restore`, `voboost-uninstall`, `voboost-selinux`, `voboost.rc`, `libimplant-arm64-v8a.so`, `libimplant-armeabi-v7a.so`, `liblsplant-arm64-v8a.so`, and `liblsplant-armeabi-v7a.so`. The output directory SHALL be absent or empty, and the adapter SHALL never overwrite or retain an extra member. Every source SHALL be a single-link regular non-symlink. ELF inputs SHALL have their exact AArch64 or ARM machine, no debug section, no host or temporary-key path, and the complete hardening contract. Executables and libraries SHALL be unsigned inputs without an appended `VOBOOST` role trailer. Output modes SHALL be `0755` for executables and `0644` for libraries and `voboost.rc`.

The adapter SHALL read no signing secret, invoke no signer, depend on no product-repository path, and perform no checkout, upload, tag, release, channel or event action. Product release tooling SHALL author and sign `restore.json`, `voboost.json` and all protected native role transcripts after it combines the app, agents and native inputs.

#### Scenario: A canonical Android release build emits native inputs

- **WHEN** the complete native release inventory has been built
- **THEN** every final ELF contains no `.debug_*` section and passes its hardening contract before collection

#### Scenario: Native beta1 inputs are collected twice

- **WHEN** the adapter receives the same complete canonical Android build twice
- **THEN** both output directories contain the exact ten flat names with byte-identical files and canonical modes

#### Scenario: One native input is hostile or output is not empty

- **WHEN** an input is missing, symlinked, wrong-ABI, debug-bearing, path-leaking, already role-signed, or the output contains an extra member
- **THEN** the adapter fails without publishing or signing output

# Gate: make test-release-elf
Gate contract: Native release ELF bytes are final before signing.
Maps: Requirement `The component exports only unsigned product inputs`; Scenario `A canonical Android release build emits native inputs`.
Preconditions: The canonical NDK r29 build produced the complete unsigned inventory with disposable public roots.
Observable result: The named gate rejects debug sections, wrong ELF type, missing RELRO, executable stack, missing immediate binding or a shared dependency in the static SELinux program.
Evidence boundary: Local unsigned Android ELF bytes; protected signing, artifact transport, device execution and publication are not observed.

# Gate: make test-prepare-beta1-unsigned
Gate contract: Deterministic product-neutral native export.
Maps: Requirement `The component exports only unsigned product inputs`; Scenarios `Native beta1 inputs are collected twice`, `One native input is hostile or output is not empty`.
Preconditions: Canonical Android outputs and the pinned NDK inspection tools are available.
Observable result: Two valid exports are byte-identical with ten exact flat names and modes, while missing, extra, linked, wrong-ABI, debug, host-path and appended-signature inputs are rejected.
Evidence boundary: Local build bytes and host filesystem execution; protected signing, publication, device and vehicle behavior are not observed.

### Requirement: Product release and publication authority remain outside this repository

`voboost-inject` SHALL contain only a read-only verification workflow. It SHALL contain no workflow or tool that accepts a protected private signing key, coordinates a product release request, creates a tag or release, uploads a product release artifact, publishes a channel, or emits a cross-repository release event. Ordinary CI SHALL run on `main`, pull requests and manual verification with repository contents read-only, immutable action pins, recursive pinned submodules and no retained checkout credentials.

#### Scenario: Untrusted component source runs CI

- **WHEN** CI evaluates a pull request or `main` commit
- **THEN** that source can run verification but cannot receive a private release role or write product state

#### Scenario: A component publication path is introduced

- **WHEN** the repository gains a release workflow, write permission, signing secret, mutable action tag or publication command
- **THEN** the release ownership gate rejects the repository graph

# Gate: node tools/test-release-workflow.ts
Gate contract: Product release ownership is external.
Maps: Requirement `Product release and publication authority remain outside this repository`; Scenarios `Untrusted component source runs CI`, `A component publication path is introduced`.
Preconditions: The named host test reads the exact workflow inventory, `ci.yml` and unsigned adapter.
Observable result: Only read-only pinned CI and the product-neutral unsigned adapter are accepted; write, signing, release, event and extra-workflow mutations are rejected.
Evidence boundary: Host repository topology; hosted CI configuration, protected product keys and publication are not executed.

### Requirement: Local Android cross-build roles are disposable

The local development wrapper SHALL create five distinct Ed25519 role pairs in a private temporary directory, expose them only to one child command, and remove every public and private role file when that child exits. Repository initialization and host tests SHALL not create or require a persistent development private key.

#### Scenario: A local Android build command exits

- **WHEN** the wrapped child succeeds or fails
- **THEN** all ten temporary key files are absent

# Gate: node tools/test-ephemeral-native-role-keys.ts
Gate contract: Local Android cross-build roles are disposable.
Maps: Requirement `Local Android cross-build roles are disposable`; Scenario `A local Android build command exits`.
Preconditions: The named host test starts a child with five generated role pairs in one private temporary directory.
Observable result: All generated public and private key files are absent after the child returns.
Evidence boundary: Host temporary-key lifecycle; Android execution and protected product signing are not observed.
