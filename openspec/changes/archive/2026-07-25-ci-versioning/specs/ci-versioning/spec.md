## MODIFIED Requirements

### Requirement: Semantic version in meson.build

The project SHALL carry a semantic version in `Cargo.toml`
`[package].version` as the single source of truth, with the baseline value
`1.0.0-beta1`. CI SHALL consume this value (e.g. via `cargo metadata` or by
parsing `Cargo.toml`) and SHALL NOT define the version elsewhere.

#### Scenario: Version is inspected

- **WHEN** `Cargo.toml` is examined
- **THEN** its `[package].version` is a semver value, starting at
  `1.0.0-beta1`

### Requirement: Release tag matches the version — CI gate

A release tag SHALL match the semver version recorded in `Cargo.toml`
`[package].version` exactly. This is enforced as a CI gate in the release
workflow: if the tag does not equal `v$version` (where `$version` is read from
`Cargo.toml`), the release job fails before any signing or publishing occurs.

#### Scenario: Tag and version agree — release proceeds

- **WHEN** a tag is pushed and `tag == v$version` (e.g. tag `v1.0.0-beta2`,
  Cargo.toml version `1.0.0-beta2`)
- **THEN** the release job passes the version gate and continues to build,
  sign, and publish

#### Scenario: Tag and version disagree — CI gate fails

- **WHEN** a tag is pushed and `tag != v$version` (e.g. tag `v1.0.0-beta2`,
  Cargo.toml version `1.0.0-beta1`)
- **THEN** the release job fails at the version-validation step with a clear
  error message and does NOT proceed to signing or publishing
