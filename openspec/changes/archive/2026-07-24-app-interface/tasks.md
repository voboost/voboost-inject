## 1. Zone path rename

- [ ] 1.1 Root zone `/data/voboost` → `/data/voboost-inject` (trust boundary,
      logging)
- [ ] 1.2 Log path `/data/voboost/logs/` → `/data/voboost-inject/logs/`

## 2. Version source + frida-free status

- [ ] 2.1 `daemon` version field sourced from `Cargo.toml` (not `meson.build`)
- [ ] 2.2 DEGRADED cause restated without frida-core (self-verification or
      payload verification failure)
- [ ] 2.3 Debug-log examples reference `/proc` scans + ptrace/injector
      diagnostics (not frida `find_pid`/`enumerate`)

## 3. Channel-B status aggregation

- [ ] 3.1 `injections` status aggregates per-process agent statuses from
      channel B (see `update-planes`)

## 4. Validate

- [ ] 4.1 `npx @fission-ai/openspec validate app-interface --strict`
