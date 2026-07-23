## 1. Version source moves to Cargo.toml

- [ ] 1.1 `Cargo.toml` `[package].version` is the single source of truth
      (baseline `1.0.0-beta1`)
- [ ] 1.2 CI consumes the version from `Cargo.toml`; no version defined elsewhere

## 2. Tag-matches-version gate reads Cargo.toml

- [ ] 2.1 Release gate: tag == `v$version` where `$version` is from `Cargo.toml`
- [ ] 2.2 Mismatch fails the release job before signing/publishing

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate ci-versioning --strict`
