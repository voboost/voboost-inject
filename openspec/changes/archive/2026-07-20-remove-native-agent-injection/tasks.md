## 1. Manifest: drop the native kind and entrypoint

- [x] 1.1 Remove the `AgentKind` enum and the `kind`/`entrypoint` properties
      from `AgentDef` in `src/manifest.vala`
- [x] 1.2 Drop the `kind`/`entrypoint` parsing in `Manifest.parse` and the
      `AgentKind.parse` call
- [x] 1.3 Update `test/manifest_test.vala` to drop the `AgentKind.JS` and
      `entrypoint` assertions
- [x] 1.4 Drop the `kind`/`entrypoint` fields from `test/fixtures/manifest.json`,
      `test/fixtures/manifest-multi.json`, and `test/fixtures/gen-fixtures.sh`

## 2. FridaController: single JavaScript injection path

- [x] 2.1 Delete `inject_native` from `src/frida_controller.vala`
- [x] 2.2 Remove the `agent.kind == AgentKind.NATIVE` branch in
      `attach_and_load`; every agent now goes through `load_js`
- [x] 2.3 Drop the `attach_failed` short-circuit that existed only to let
      native agents through after a failed attach
- [x] 2.4 Simplify the `process_crashed` handler: remove the native-only crash
      path and the PID-reuse hedge comments that referenced the JS->native
      migration
- [x] 2.5 Simplify the lazy-QuickJS comments: QuickJS is always loaded when a
      target is injected

## 3. Plan reader and integration docs

- [x] 3.1 Drop the "native: data arg" half of the config comment in
      `src/plan_reader.vala`
- [x] 3.2 Drop the "js / native routing" note from `test/integration-tests.md`
      and describe the single js path

## 4. Specs

- [x] 4.1 `injection-control`: replace "Per-agent runtime routing and
      per-process lazy runtime" with a JavaScript-only requirement; drop the
      native scenarios and the native config-delivery scenario
- [x] 4.2 `trust-verification`: drop `native` from the enumerated `kind`
      values (the `kind` field is removed entirely)

## 5. Validate

- [x] 5.1 `npx @fission-ai/openspec validate remove-native-agent-injection
      --strict`
- [x] 5.2 Build the daemon and run the host test suite
