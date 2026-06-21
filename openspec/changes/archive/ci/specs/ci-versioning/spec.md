## ADDED Requirements

### Requirement: Semantic version in meson.build
The project SHALL carry a semantic version in the `meson.build` `project()` `version` field as the
single source of truth, with the baseline value `1.0.0-beta1` (set by the `inject` change). CI SHALL
consume this value and SHALL NOT define the version elsewhere.

#### Scenario: Version is inspected
- **WHEN** `meson.build` is examined
- **THEN** its `project()` version is a semver value, starting at `1.0.0-beta1`

### Requirement: Manual pre-release postfix bump
During early development the pre-release postfix SHALL be bumped manually on each release so that
successive signed builds are distinguishable as the project approaches `1.0.0`
(`1.0.0-beta1` → `1.0.0-beta2` → … → `1.0.0-rc1` → `1.0.0`).

#### Scenario: A new pre-release is cut
- **WHEN** a new release is prepared during early development
- **THEN** the `meson.build` pre-release postfix is incremented (e.g. `1.0.0-beta1` → `1.0.0-beta2`)

### Requirement: Release tag matches the version — CI gate
A release tag SHALL match the semver version recorded in `meson.build` exactly. This is enforced
as a CI gate in the release workflow: if the tag does not equal `v$version`, the release job fails
before any signing or publishing occurs.

#### Scenario: Tag and version agree — release proceeds
- **WHEN** a tag is pushed and `tag == v$version` (e.g. tag `v1.0.0-beta2`, meson version `1.0.0-beta2`)
- **THEN** the release job passes the version gate and continues to build, sign, and publish

#### Scenario: Tag and version disagree — CI gate fails
- **WHEN** a tag is pushed and `tag != v$version` (e.g. tag `v1.0.0-beta2`, meson version `1.0.0-beta1`)
- **THEN** the release job fails at the version-validation step with a clear error message and
  does NOT proceed to signing or publishing
