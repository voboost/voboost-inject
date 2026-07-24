## 1. Boot trigger and single-instance

- [ ] 1.1 `config/voboost-inject.rc` — init service triggered `on nonencrypted`
      (fallback `on boot`); domain entry owned by `selinux-domain`
- [ ] 1.2 `main.rs` — pidfile + `flock` single-instance (port 1:1 from Vala);
      second instance logs and exits

## 2. Startup gate

- [ ] 2.1 `main.rs` — read `inject.json` `startup` from the app zone; `none` →
      exit; absent/other → continue; never read `config.yaml`

## 3. State machine

- [ ] 3.1 Implement INIT → VERIFY_SELF → READY/DEGRADED; no GATE state
- [ ] 3.2 On READY, reconcile (`/proc/<pid>/maps` marker) before injecting
- [ ] 3.3 DEGRADED on verify-self failure or `libinjector` load/init failure

## 4. Async runtime and shutdown

- [ ] 4.1 Run on an async Rust runtime; bound the ptrace inject with a timeout;
      no error terminates the loop
- [ ] 4.2 SIGTERM: stop new injections, release pidfile, exit — do NOT tear down
      live injections

## 5. Boot-readiness and BootState

- [ ] 5.1 `boot: true` agents wait on `sys.boot_completed` AND daemon READY;
      others inject immediately; poll while waiting
- [ ] 5.2 `BootState` module — hatch-first, monotonic positive cache, negative
      re-poll; host-testable without the injector; supervisor delegates
      `boot_completed()` to it

## 6. Remove frida lifecycle code

- [ ] 6.1 Delete the `Frida.init()` ordering and the emulator `gum_query_page_size`
      / `frida-gum.wrap` fix

## 7. Validate

- [ ] 7.1 `npx @fission-ai/openspec validate daemon-lifecycle --strict`
- [ ] 7.2 Host test: `BootState` cases; device test: daemon resident before
      system_server, SIGTERM leaves hooks running
