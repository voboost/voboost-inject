# Voboost Inject Code Style

## Global
- Follows ALL common rules from ../voboost-codestyle/AGENTS.md
- Root Vala binary embedding frida-core, runs as root, injects signed agents

## Language
- Chat in Russian; source, comments, and docs in English (ASCII)

## OpenSpec
- Spec-driven; truth is openspec, no code without an applied change, invariants live in specs
- propose -> apply -> archive
- npx @fission-aiopenspec validate <change> --strict

## Development
- Lines <= 100 chars
- Vala: idiomatic GObject + async/yield on a GMainLoop
- `make init`
- `make lint-fix`
