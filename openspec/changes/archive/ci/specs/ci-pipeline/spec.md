## ADDED Requirements

### Requirement: Provision via make init, lint, test, build on push and PR
The CI pipeline SHALL run on every push and pull request: provision the runner by calling
`make init` (which installs the toolchain, builds `io.elementary.vala-lint` from its pinned source
revision, builds the frida-patched `valac`, and fetches the pinned frida wrap), run `make lint` and
`make test`, and build the daemon release-only on the host (`make build`: `release`, LTO) as a
validation build. The host validation build links dynamically and is not stripped; the fully-static,
stripped device build is the release artifact owned by `ci-signing`.

#### Scenario: Push or PR triggers the pipeline
- **WHEN** a commit is pushed or a pull request is opened
- **THEN** CI runs `make init` to provision the environment, runs `make lint` and `make test`, and
  performs a release-only host build (`release`, LTO) for validation

#### Scenario: A step fails
- **WHEN** lint, tests, or the build fails
- **THEN** the pipeline fails and the failing step is reported

### Requirement: No debug build job
The pipeline SHALL build release-only and SHALL NOT define a debug build job.

#### Scenario: Pipeline configuration is inspected
- **WHEN** the CI workflow is examined
- **THEN** it builds with the release configuration and has no debug build target

### Requirement: Cache the make init result
CI SHALL cache the result of `make init` — the project-local `.tools/` prefix containing the
source-built `io.elementary.vala-lint` and the frida-patched `valac`, and the fetched
`subprojects/` frida checkout — keyed on the pinned frida and vala-lint revisions, and SHALL
restore it from cache instead of rebuilding it every run.

#### Scenario: Cache hit
- **WHEN** a run finds the cached `make init` result for the current pinned revisions
- **THEN** it restores the installed tools (vala-lint and the frida-patched valac) and the frida
  checkout from cache without rebuilding them or re-fetching frida

#### Scenario: Cache miss
- **WHEN** the cache is empty or the pinned revisions changed
- **THEN** CI reinstalls the tools, rebuilds `io.elementary.vala-lint` and the frida-patched `valac`,
  and re-fetches frida at the same pinned revisions, then repopulates the cache
