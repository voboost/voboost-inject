# Tasks — fix-32bit-injector-regset-thumb

## 1. Spec changes

- [x] 1.1 `openspec/changes/fix-32bit-injector-regset-thumb/proposal.md`
- [x] 1.2 `openspec/changes/fix-32bit-injector-regset-thumb/design.md`
- [x] 1.3 `openspec/changes/fix-32bit-injector-regset-thumb/tasks.md`
- [x] 1.4 delta `native-payload` spec (`user_regs_32` is 4-byte fields;
      Thumb mode via CPSR.T, not the PC LSB)

## 2. Injector fixes

- [x] 2.1 `struct user_regs_32 { uint32_t uregs[18]; }` (was `unsigned long`)
- [x] 2.2 `remote_call32`: set CPSR.T (`uregs[16] & 0x20`) for Thumb symbols,
      even PC, drop the orig-PC Thumb-bit OR
- [x] 2.3 32-bit SP read in `vbi_inject` simplified (uregs[13] already 32-bit)
- [x] 2.4 opt-in `VBI_DBG` debug logging added around attach/bitness/dlopen/
      dlsym/init and every `remote_call32`/`remote_call64` register set,
      defaulting to `0` (production silent)

## 3. Verification (real device `1234567`, f0506h, Android 9)

- [x] 3.1 32-bit `com.android.settings` (`app_process32`) injection completes
      `implant_init`, real dex agent (`stub-agent.dex`) executes
- [x] 3.2 64-bit `system_server` (`app_process64`) injection unaffected,
      same dex agent executes
- [x] 3.3 no `cannot locate symbol` on either bitness

## 4. Gates

- [x] 4.1 `make lint` (uncrustify C/C++, cargo fmt/clippy)
- [x] 4.2 `make test` (daemon unit tests + injector/implant host tests)
- [x] 4.3 `npx @fission-ai/openspec validate fix-32bit-injector-regset-thumb
      --strict` passes

## 5. Apply + finalize

- [x] 5.1 apply + archive change
- [ ] 5.2 commit (on user confirmation)
