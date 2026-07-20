## 1. OpenSpec change (find-pid-cmdline-nul-split)

- [x] 1.1 `proposal.md`: why (g_strsplit NUL crash), what (remove split,
      cmdline is already argv[0]), impact
- [x] 1.2 `design.md`: D1 crash root cause, D2 NUL-termination gives
      argv[0], D3 empty cmdline edge case, D4 rejected alternative

## 2. Code

- [x] 2.1 `src/frida_controller.vala` `find_pid`: replace
      `cmdline.split("\0", 2)[0]` with direct `cmdline` comparison
      (applied: `find_pid` compares `cmdline == process` directly, no split)

## 3. Validate

- [x] 3.1 `make build`, `make test`, `make lint` pass (host)
- [x] 3.2 `make build-android` passes
- [x] 3.3 Emulator: daemon does not crash on find_pid /proc fallback;
      `attach-launcher` resolves pid and injects (`state: active`)
