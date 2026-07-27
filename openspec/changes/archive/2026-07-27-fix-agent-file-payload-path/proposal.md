## Why

The daemon's startup self-verification (`main.rs::verify_self`) resolves each
manifest agent's file (`agents.dex`) under `ROOT_ZONE`
(`/data/voboost-inject/agents.dex`), but the file is actually deployed under
`PAYLOAD_DIR` (`/data/voboost-inject/payload/agents.dex`) — the path
`voboost-install` pushes it to and the path the implant hardcodes for its own
`InMemoryDexClassLoader` read (`implant/implant.cpp`). Because of this
mismatch the sha256 check always failed (`sha256_file` on a nonexistent path
returns `None`), so the daemon always logged `sha256 mismatch: <agent-id>` and
fell back to DEGRADED (observe-only) mode — no agent was ever injected. This
was invisible until the first real end-to-end emulator run in this change's
verification pass; there is no existing gate (unit test) covering this path
construction.

## What Changes

- Fix `verify_self()`'s per-agent file path to resolve under `PAYLOAD_DIR`
  instead of `ROOT_ZONE`, matching where the file is actually deployed and
  read by the implant.
- Clarify the `trust-verification` spec's "Per-agent hash verification"
  requirement to state where the verified agent file lives on disk (it was
  previously silent on this, which is the spec gap that let the bug ship
  unnoticed).
- Add a daemon-side unit test covering the agent-file path construction, since
  none existed before (every SHALL needs a gate).

## Capabilities

### New Capabilities
(none)

### Modified Capabilities
- `trust-verification`: "Per-agent hash verification" now specifies that the
  verified agent file is resolved under the payload directory
  (`PAYLOAD_DIR/<agent.file>`), not the root zone, mirroring how native
  payload files are already resolved (see "Native payload verification via
  the release manifest" in the same spec).

## Impact

- `daemon/src/main.rs` (`verify_self`): one-line path fix
  (`config::ROOT_ZONE` → `config::PAYLOAD_DIR`).
- `daemon/src/main.rs` tests: new unit test for the fixed path construction.
- No API/ABI change, no impact on the manifest format or the injector/implant
  contract. Verified fix on `emulator-5554`: daemon moved from permanent
  DEGRADED to READY, both MVP agents (`pedestrian-warning`, `settings-menu`)
  injected successfully.
