# Design: launcher-echo test fixture agent

## D1. Why a fixture manifest entry, not a plan-only change

The daemon verifies every plan-requested agent id against the signed manifest
(`Supervisor.verify_self` + `Manifest.load_verified`); an id absent from the
manifest is rejected and logged as "rejected unknown agent id". So the
`attach-launcher` scenario's plan (`{"id":"launcher-echo", ...}`) is rejected
unless `launcher-echo` is in the fixture manifest. The fix belongs in the
fixture manifest (and its generator), not in the plan or the daemon.

## D2. Why gen-fixtures.sh, not hand-edited manifest.json

`gen-fixtures.sh` is the single source of the fixture manifest: it emits each
agent (file + sha256 + entry), writes `manifest.json`, signs it to `manifest.sig`
with `config/key-dev-private.pem`, and regenerates the APK/release-manifest
fixtures that embed it. Hand-editing `manifest.json` would desync it from the
generator and the signed `.sig` (and from the APK fixtures that embed the
manifest). Adding one `emit_agent` call keeps everything consistent and
idempotent.

## D3. Stub payload

`launcher-echo.js` is a one-liner `send({ ok: true, agent: 'launcher-echo' })`,
matching the other fixture stubs (`settings-menu`, `low-speed-sound`). The
scenario asserts `state: active` (the agent loaded), not any RPC contract, so a
bare `send` is sufficient — no `rpc.exports.init` needed for `attach-launcher`.

## D4. Why this is its own change

The fixture change is what makes `attach-launcher` exercisable; the
`find-pid-package-match` change is what makes the pid resolve. Both are needed
for the scenario to pass, but they are independent layers (test fixture vs
daemon code) and commit/validate separately.
