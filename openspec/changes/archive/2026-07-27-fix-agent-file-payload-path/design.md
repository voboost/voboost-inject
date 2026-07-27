## Context

`daemon/src/main.rs::verify_self()` verifies every manifest agent's file
sha256 before the daemon leaves DEGRADED mode. It built the file path as
`{ROOT_ZONE}/{agent.file}`. The manifest's `file` field is a bare relative
name (`"agents.dex"`), meant to resolve under the payload directory — where
`voboost-install` actually pushes it and where the implant reads it from
(`implant/implant.cpp` hardcodes `/data/voboost-inject/payload/agents.dex`).
`config::PAYLOAD_DIR` already exists and is used for exactly this purpose
elsewhere (`ota.rs`, `release_manifest.rs`), so this is a one-constant fix,
not a new mechanism.

## Goals / Non-Goals

**Goals:**
- Make `verify_self()`'s agent-file path match where the file is actually
  deployed, so the daemon reaches READY instead of permanent DEGRADED.
- Add a regression test so this specific path construction has a gate.

**Non-Goals:**
- Not touching the release-manifest / native-payload verification path
  (`verify_payload_before_inject`) — that already correctly uses
  `PAYLOAD_DIR` and is out of scope for this change.
- Not changing the manifest JSON format or the `file` field's semantics.

## Decisions

- **Use `config::PAYLOAD_DIR` instead of introducing a new constant or a
  templated path.** It already means exactly "where deployed runtime files
  live" and is used the same way for the native payload; reusing it keeps one
  convention for "where do deployed files live" instead of two.
- **Add a unit test that stages a fake `PAYLOAD_DIR` layout and asserts
  `verify_self`'s (or an extracted pure helper's) path construction**, rather
  than only relying on the emulator run as the gate — the emulator is the
  end-to-end confirmation, but a fast host-side test is what actually blocks
  a regression in CI (`cargo test`, no device required).

## Risks / Trade-offs

- [Risk] The fix only touches the daemon-manifest (agents.dex) path; if a
  future manifest ever lists a `file` that intentionally lives outside
  `PAYLOAD_DIR` (e.g. a bundle split across directories), this fix would
  need revisiting. → Mitigation: the manifest's `file` field is documented
  (native-payload / release-manifest specs) as resolving under the payload
  directory; no such split exists today, and the new test pins the current
  contract so a future change to it is a deliberate, visible edit.
