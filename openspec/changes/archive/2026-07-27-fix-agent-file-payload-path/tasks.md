## 1. Fix the path resolution

- [x] 1.1 Change `verify_self()` in `daemon/src/main.rs` to build the
  per-agent file path as `config::PAYLOAD_DIR/<agent.file>` instead of
  `config::ROOT_ZONE/<agent.file>`.

## 2. Gate the fix

- [x] 2.1 Extract `agent_file_path(file: &str) -> String` from `verify_self`
  and add a unit test (`agent_file_path_resolves_under_payload_dir`) pinning
  it to `PAYLOAD_DIR`, not `ROOT_ZONE` (regression guard for this exact bug).
- [x] 2.2 Run `cargo test` in `daemon/` — 27 tests pass (26 existing + the
  new regression test from 2.1).
- [x] 2.3 Verify end-to-end on `emulator-5554` (`make emulator-run` +
  relaunching the stub target processes): daemon reaches `state: ready`
  (was permanently `degraded` before the fix), both MVP agents
  (`pedestrian-warning`, `settings-menu`) show `state: active` in
  `inject-status.json` and start in logcat.

## 3. Spec sync

- [x] 3.1 Update `trust-verification`'s "Per-agent hash verification"
  requirement to pin the agent-file path under `PAYLOAD_DIR` (this change's
  spec delta).
