## MODIFIED Requirements

### Requirement: Provision via make init, lint, test, build on push and PR

The CI pipeline SHALL run on every push and pull request: provision the runner
by calling `make init` (which installs the Rust toolchain pinned by
`rust-toolchain.toml`, verifies NDK r29, and provisions the native build tools
— see `build-and-signing`, `provisioning`), run `make lint` (`cargo clippy` +
uncrustify) and `make test`, and build the daemon release-only on the host
(`make build`) as a validation build. The host validation build links
dynamically and is not stripped; the fully-static, stripped device build is
the release artifact owned by `ci-signing`.

#### Scenario: Push or PR triggers the pipeline

- **WHEN** a commit is pushed or a pull request is opened
- **THEN** CI runs `make init` to provision the Rust toolchain and NDK r29,
  runs `make lint` (`cargo clippy` + uncrustify) and `make test`, and performs
  a release-only host build for validation

#### Scenario: A step fails

- **WHEN** lint, tests, or the build fails
- **THEN** the pipeline fails and the failing step is reported

### Requirement: Cache the make init result

CI SHALL cache the result of `make init` — the Rust toolchain (from
`rust-toolchain.toml`), the fetched NDK r29, and the Cargo registry/`target/`
prefix — keyed on the Rust toolchain pin and the NDK version, and SHALL restore
it from cache instead of rebuilding it every run.

#### Scenario: Cache hit

- **WHEN** a run finds the cached `make init` result for the current Rust
  toolchain pin and NDK version
- **THEN** it restores the Rust toolchain, the NDK, and the Cargo prefix from
  cache without re-provisioning them

#### Scenario: Cache miss

- **WHEN** the cache is empty or the Rust toolchain pin or NDK version changed
- **THEN** CI re-provisions the tools at the same pins, then repopulates the
  cache
