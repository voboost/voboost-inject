## 1. Lint over Rust + C/C++

- [ ] 1.1 `make lint` runs `cargo clippy` (deny warnings) over Rust + `uncrustify
      --check` over C/C++ sources (not vala-lint over Vala)
- [ ] 1.2 `make lint-fix` runs `cargo fmt` (Rust) + `uncrustify --replace` (C/C++)
- [ ] 1.3 `make lint` guards presence of `cargo`/`clippy` and `uncrustify`
      (not `io.elementary.vala-lint`)

## 2. Test over Rust

- [ ] 2.1 `make test` runs `cargo test` (not `meson test`); silent on success

## 3. Line-length + style (restated)

- [ ] 3.1 100-char cap via `.editorconfig` + `rustfmt`/`clippy` + `uncrustify`
- [ ] 3.2 Inherited style rules unchanged (English, trailing newline, no
      commented-out code)

## 4. Validate

- [ ] 4.1 `npx @fission-ai/openspec validate quality-gates --strict`
