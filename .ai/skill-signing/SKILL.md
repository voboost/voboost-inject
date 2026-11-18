---
name: skill-signing
description: "Signs and verifies voboost-inject artifacts. Covers Ed25519 trust, receipts, and ELF signatures. Use when signing releases or reviewing trust paths; not for general code work."
---

# Trust and Signing

- Authenticate the exact bytes consumed: detached Ed25519 signatures cover manifests; SHA-256 covers declared payloads.
- Protected product signing and publication belong to `voboost`; this repository provides unsigned native bytes, role-bound transcript primitives, verification code, and disposable test keys only.
- Authenticate schema-1 `agents.json` before reading the unsigned machine-specific `agents-selected.json`; verify that canonical schema-1 receipt against root-owned `vehicle.json` and import only its exact selected payload closure.
- `make sign-elf` appends the `VOBOOST` trailer and raw 64-byte Ed25519 signature to an unchanged ELF prefix; `make test-sign-elf` gates the layout and verification.
- Never add a skip-verification path or normalize signed JSON between verification and parsing.
