## Why

The 32-bit injection path in the C injector (`injector/injector.c`) was never
exercised end-to-end — the PoC injector (`voboost-inject-new/poc/poc1_injector/`)
only supported 64-bit targets. On a real Android 9 device with 32-bit target
processes (`com.android.settings`, `app_process32`), injection failed at the
first remote-call with two latent bugs:

1. `struct user_regs_32 { unsigned long uregs[18]; }` — `unsigned long` is 8
   bytes on the 64-bit host/NDK, but the 32-bit ARM regset uses 4-byte fields.
   The kernel's `PTRACE_GETREGSET NT_PRSTATUS` returns `iov_len=72` (18×4); we
   read `sizeof=144` (18×8), so every field read two adjacent 32-bit slots as
   one 64-bit value (`uregs[13]`/SP read back as a >32-bit garbage address,
   `target_write_mem` then failed with an out-of-range address).
2. `remote_call32` set the PC to a Thumb symbol's address (LSB=1, as the linker
   hands it back) and OR-ed in the orig-PC Thumb bit. Under an ARM64-host kernel
   ptracing a 32-bit tracee, the PC field does **not** carry the Thumb bit in
   its LSB — the kernel writes back an even PC, the CPU decodes ARM (A-state)
   instructions, and every Thumb function (all of `__loader_dlopen`/`dlsym`)
   traps with `SIGILL` (sig=4) at its first instruction. The "call" never ran;
   the return value read back was the unchanged argument register.

Thumb mode is selected by the **CPSR.T bit** (bit 5 = 0x20) in `uregs[16]`
(CPSR), not by the PC LSB. The `native-payload` spec's claim "(including the
Thumb bit; `uregs[15]`=pc)" is wrong and led directly to bug #2.

## What Changes

- **`injector/injector.c`** — `struct user_regs_32 { uint32_t uregs[18]; }`
  (4-byte fields, matching the kernel's 72-byte regset). In `remote_call32`,
  set `uregs[15]` to the even function address and set/clear the CPSR.T bit
  (`uregs[16] |= 0x20u` for Thumb symbols, `&= ~0x20u` for ARM) before
  `PTRACE_SETREGSET`. Drop the orig-PC Thumb-bit OR. The 32-bit SP read in
  `vbi_inject` simplifies (uregs[13] is already 32-bit, no masking needed).
- **`native-payload` spec** — fix the cross-bitness regset description:
  `user_regs_32` uses 4-byte fields (`uint32_t uregs[18]`, iov_len=72); Thumb
  mode is selected via CPSR.T (`uregs[16]` bit 0x20), NOT via the PC LSB;
  `uregs[0]`=return, `uregs[13]`=sp, `uregs[14]`=lr, `uregs[15]`=pc (even),
  `uregs[16]`=cpsr.

## Capabilities

### Modified Capabilities

- `native-payload`: the injector's 32-bit remote-call now correctly switches
  Thumb mode via CPSR.T and reads the 32-bit regset with the right field width;
  the spec's regset/Thumb description is corrected.
