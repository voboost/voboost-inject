## Why

The `ci-versioning` spec treats `meson.build`'s `project().version` as the
single source of truth for the project version, with a CI gate that the
release tag matches `v$version`. The build moved to Cargo (see
`build-and-signing`): `meson.build` is gone, and the version now lives in
`Cargo.toml` `[package].version`. The CI gate must read from `Cargo.toml` or
it will compare the tag against a file that no longer exists.

## What Changes

- **MODIFIED**:
  - "Semantic version in meson.build" — the version source of truth moves to
    `Cargo.toml` `[package].version`; CI consumes that value.
  - "Release tag matches the version — CI gate" — the gate compares the tag
    against `v$version` where `$version` is read from `Cargo.toml`.
- **Unchanged**: "Manual pre-release postfix bump" (the bump workflow is the
  same; only the file that holds the version changes).

## Capabilities

### Modified Capabilities

- `ci-versioning`: the semantic version's single source of truth moves from
  `meson.build` to `Cargo.toml` `[package].version`; the tag-matches-version CI
  gate reads from `Cargo.toml`.
