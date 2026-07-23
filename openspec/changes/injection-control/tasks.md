## 1. Remove frida driving from the supervisor

- [ ] 1.1 Delete the `frida_controller.vala` driving path (in-process local
      device, `create_script`, sessions); the Rust supervisor no longer
      constructs any frida object
- [ ] 1.2 Remove global spawn-gating, the non-target immediate-resume path, and
      the `VOBOOST_SKIP_SPAWN_GATING` emulator hatch
- [ ] 1.3 Remove the per-process QuickJS routing / lazy-runtime logic

## 2. Ptrace injection via libinjector

- [ ] 2.1 `injector.rs` — `extern "C"` FFI to `vbi_inject(pid, so_path,
      init_sym)` (see `native-payload`); pass the matching-ABI `libimplant.so`
      path and `"implant_init"`
- [ ] 2.2 Map `vbi_inject` return codes (ok / denied / target-gone /
      dlopen-failed / init-failed) into the device-safety accounting
- [ ] 2.3 Confirm the daemon links only `libinjector` and no LSPlant/Dobby/implant
      symbol

## 3. Reconciliation by the maps marker

- [ ] 3.1 `reconcile.rs` — read `/proc/<pid>/maps`, detect the real
      `libimplant.so` path (the `native-payload` marker)
- [ ] 3.2 On startup and on every plan change: marker present → do not
      re-inject, update config over channel B only
- [ ] 3.3 Ensure a daemon restart / OTA self-update reconciles instead of
      re-injecting and never tears hooks down
- [ ] 3.4 Route teardown through a "no agents" plan over channel B (agent
      self-`teardown()`), never through daemon exit

## 4. Process watching (polling)

- [ ] 4.1 `process_watcher.rs` — poll `/proc`; inject on target appearance
      (guarded by the marker)
- [ ] 4.2 Detect death by `/proc/<pid>` disappearance; reinject on reappearance
      within the device-safety budget
- [ ] 4.3 Tolerate `/proc/<pid>` entries vanishing mid-scan

## 5. pid resolution

- [ ] 5.1 `find_pid` — scan `/proc`, take `/proc/<pid>/cmdline` bytes up to the
      first NUL as `argv[0]`, compare directly against manifest `process`
- [ ] 5.2 Verify app targets (package id) and native/system targets
      (`system_server`) both resolve; drop the frida `enumerate_processes` match

## 6. Config delivery over channel B

- [ ] 6.1 On injection, write the validated per-process config to the target's
      channel-B config file and pass its path to `implant_init`
- [ ] 6.2 On plan change for an injected target, rewrite the config file
      atomically (write-tmp+rename); do not re-inject
- [ ] 6.3 Keep config opaque — no parse/schema, only the plan-validation size
      bound

## 7. ABI carriage

- [ ] 7.1 Daemon carries both ABIs of `libimplant.so` (+ hooker prebuilts) and
      passes the matching-ABI path per detected bitness
- [ ] 7.2 Missing-ABI target: report failure, never inject a mismatched-ABI
      payload

## 8. Validate

- [ ] 8.1 `npx @fission-ai/openspec validate injection-control --strict`
- [ ] 8.2 Device test: inject 32- and 64-bit targets, confirm marker in
      `/proc/<pid>/maps`, restart daemon and confirm no teardown/re-inject
