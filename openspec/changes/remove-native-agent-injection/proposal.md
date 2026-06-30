## Why

The daemon carries a `native` agent kind (`AgentKind.NATIVE`, `inject_native`,
`inject_library_blob`, the manifest `kind`/`entrypoint` fields, and the
"Per-agent runtime routing and per-process lazy runtime" requirement) that is
dead code in practice and cannot be exercised by any shipped agent.

Every agent in `voboost-script` hooks **Java methods** through Frida's
`Java.use()` (frida-java-bridge), which runs on the QuickJS runtime. The
frida-gum native C API (`gum_interceptor_replace_function`,
`gum_module_find_export_by_name`) only intercepts native ELF symbols; it has
no bridge to Java/ART methods. Reimplementing frida-java-bridge in C (ART
internals, JNI reflection, method patching) is out of scope and would amount to
rewriting Frida. There is therefore no realistic path to a `native` agent for
any current target, and the `kind`/`entrypoint` routing, the
`inject_library_blob` path, and the per-process lazy-QuickJS optimization
exist only to serve a migration that will not happen.

Keeping the dead branch has a real cost: extra manifest fields, an extra
`AgentKind` enum value, a parallel injection path with its own timeout/sha256
handling, spec text and scenarios that describe behavior nothing exercises, and
comments throughout `frida_controller.vala` that hedge on a "JS->native
migration". This change deletes all of it so the daemon has a single,
JavaScript-only injection path.

## What Changes

- **`src/manifest.vala`** — remove the `AgentKind` enum and the `kind`/
  `entrypoint` properties from `AgentDef`; drop the `kind`/`entrypoint` parsing
  in `Manifest.parse`. Agents are JavaScript by definition.
- **`src/frida_controller.vala`** — delete `inject_native` and the
  `agent.kind == AgentKind.NATIVE` branch in `attach_and_load`; every agent now
  goes through `load_js`. Simplify the `process_crashed` handler (no
  native-only crash path) and the lazy-QuickJS comments (QuickJS is always
  loaded when a target is injected). Drop the `attach_failed` short-circuit
  that existed only to skip remaining js agents while still letting native
  agents through.
- **`src/plan_reader.vala`** — drop the "native: data arg" half of the config
  comment; config is delivered only via `rpc.exports.init`.
- **`test/manifest_test.vala`** — drop the `AgentKind.JS` / `entrypoint`
  assertions (the fields no longer exist).
- **`test/fixtures/manifest.json`, `manifest-multi.json`, `gen-fixtures.sh`** —
  drop the `kind` and `entrypoint` fields from the fixture manifests.
- **`test/integration-tests.md`** — drop the "js / native routing" integration
  note; describe the single js path.
- **`openspec/specs/injection-control/spec.md`** — replace the "Per-agent
  runtime routing and per-process lazy runtime" requirement with a
  JavaScript-only requirement; drop the native scenarios and the native
  config-delivery scenario.
- **`openspec/specs/trust-verification/spec.md`** — drop `native` from the
  enumerated `kind` values.

## Capabilities

### Modified Capabilities
- `injection-control`: the daemon now has a single JavaScript-only injection
  path. The `native` agent kind, the `inject_library_blob` path, the
  `entrypoint` manifest field, and the per-process lazy-QuickJS optimization
  are removed. Every agent runs on QuickJS via a per-process session script.
- `trust-verification`: the manifest `kind` field is removed; an agent's
  `process` is taken exclusively from the verified manifest (the `kind`
  enumeration is gone).
