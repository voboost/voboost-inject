## 1. OpenSpec change (inject-log-level)

- [x] 1.1 `proposal.md`: why (operator needs verbose diagnostics at runtime, no
      rebuild; inject.json is the existing watched config), what (log_level
      field, Log.debug), impact
- [x] 1.2 `design.md`: D1 why inject.json not a new file; D2 plan field in
      load_plan; D3 tag/file; D4 find_pid diagnostics; D5 what not to log
- [x] 1.3 `specs/app-interface/spec.md`: MODIFIED inject.json requirement
      (adds log_level + scenarios)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-02`

## 2. Code

- [x] 2.1 `src/log.vala`: `LogTag.DEBUG` (symbol `#`), `Log.set_debug` /
      `Log.get_debug`, `Log.debug` (writes only when flag on)
- [x] 2.2 `src/plan_reader.vala`: `Plan.log_level` (default "info"); parsed
      from `inject.json` `log_level` (safe_string, unknown -> "info")
- [x] 2.3 `src/supervisor.vala`: `Log.set_debug(plan.log_level == "debug")`
      in `load_plan` right after validate
- [x] 2.4 `src/frida_controller.vala` `find_pid`: `Log.debug` for enumerate
      count, name match, `/proc` match, `/proc` scan size

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate inject-log-level --strict` passes
- [x] 3.2 `make build`, `make test`, `make lint` pass (host)
- [x] 3.3 `make build-android` passes
- [x] 3.4 Emulator: `inject.json` with `"log_level":"debug"` emits `[#]`
      `find_pid` lines; `"info"` (or absent) emits none
