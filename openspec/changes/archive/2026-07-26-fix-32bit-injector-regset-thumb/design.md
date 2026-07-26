# Design — fix-32bit-injector-regset-thumb

## Context

The injector's 32-bit path was untested — the PoC injector only did 64-bit.
On a real Android 9 device (`1234567`, `f0506h`, ABIs `arm64-v8a,armeabi-v7a`)
injecting into a 32-bit process (`com.android.settings`, `app_process32`)
failed at the first remote call. Debug logging (an opt-in `VBI_DBG` macro in
`injector.c`) pinpointed two independent bugs, both in the 32-bit-only path;
64-bit injection was unaffected.

## Bug 1: regset field width (`unsigned long` vs `uint32_t`)

`struct user_regs_32 { unsigned long uregs[18]; }`. On the 64-bit host/NDK,
`unsigned long` is 8 bytes. The kernel's `PTRACE_GETREGSET NT_PRSTATUS` for a
32-bit ARM target returns `iov_len=72` (18 × 4-byte fields). With `sizeof=144`
we read 8 bytes per slot, so each `uregs[i]` actually held two adjacent 32-bit
fields concatenated:

```
DBG: 32-bit raw uregs[13]=0x269000020 ...   ← SP read as 36-bit (two slots)
DBG: path string @ 0x268ffe020 (sp-based)   ← str_addr > 32-bit
DBG: target_write_mem for path FAILED: I/O error
```

(When we additionally memset the struct, the high half is zero and `uregs[13]`
reads as 0 — `str_addr = 0 - 8192` wraps to `0xffffffffffffe000`.)

**Fix:** `uint32_t uregs[18]` — `sizeof=72` matches `iov_len`, fields read
correctly. Verified on-device: `uregs[13](sp)=0xff985c80`, `str_addr=0xff983c80`,
write succeeds.

## Bug 2: Thumb mode selection (PC LSB vs CPSR.T)

For a 32-bit ARM tracee under an ARM64-host kernel, the PC register field
(`uregs[15]`) does **not** carry the Thumb bit in its LSB — the kernel writes
back an even PC regardless of what we set. The CPU then decodes ARM (A-state)
instructions. All of `__loader_dlopen` / `__loader_dlsym` are Thumb symbols
(linker hands back LSB=1 addresses), so the first instruction trapped with
`SIGILL` (sig=4) and the call never ran. The "return value" we read from `r0`
was the unchanged argument register (e.g. `init_addr == handle == args[0]`),
which then sent execution into a data address and `SIGSEGV`'d.

```
DBG: rc32: SET pc=0xf6bb05b9 sp=... lr=0 r0=0xff983c80 ...   ← Thumb addr, LSB=1
DBG: rc32: waited status=0x47f (WIFSTOPPED=1 sig=4 ...)       ← SIGILL
DBG: rc32: result r0=0xff983c80 (pc now=0xf6bb05b8)           ← even PC, call never ran
```

Thumb/ARM mode is selected by the **CPSR.T bit** (bit 5 = 0x20) in `uregs[16]`
(CPSR). The pre-fix code OR-ed the orig-PC Thumb bit into the new PC, which
the kernel discarded — useless.

**Fix** (in `remote_call32`):
```c
int is_thumb = (uint32_t)func_addr & 1;
regs.uregs[15] = (uint32_t)func_addr & ~(uint32_t)1;  /* even PC */
if (is_thumb) regs.uregs[16] |= 0x20u;   /* CPSR.T → Thumb decoding */
else          regs.uregs[16] &= ~0x20u;
```

Verified on-device:
```
DBG: rc32: SET pc=0xf6bb05b8 sp=0xff985b80 lr=0 cpsr=0x20870030 (T=1) r0=0xff983c80 ...
   → dlopen succeeded, handle=0xff983c80
DBG: rc32: SET pc=0xf6bb06fc ... r0=0x7308649b ...
   → dlsym(handle, implant_init) -> init_addr=0xd22514f1   ← real address, not handle
DBG: rc32: SET pc=0xd22514f0 ...
   → VoboostImplant: implant_init: start → complete
```

## End-to-end verification (real device `1234567`)

With both fixes, the full chain runs in **both bitnesses**, with a real dex
agent (`stub-agent.dex`, class `ru.voboost.agents.AgentEntry`):

- **32-bit** `com.android.settings` (`app_process32`, pid 11342):
  `VoboostImplant: implant_init: start` → `voboost-stub-agent: AgentEntry.init
  seam called` → `VoboostImplant: implant_init: complete`. Process stable.
- **64-bit** `system_server` (`app_process64`, pid 12138): same chain, same
  `AgentEntry.init seam called`. Process stable.

No `cannot locate symbol` on either bitness (the c++_static fix from the
`fix-build-native-wired-source` change holds for both ABIs).

## Production-logging posture

`VBI_DBG` defaults to 0 (production silent — the daemon's own log file is the
canonical trace). The only logcat output in production is the ERROR-level
dlerror string when a remote `dlopen` fails (preserved, in `vbi_inject`).
Flip `VBI_DBG` to 1 to diagnose on-device.

## Out of scope

- The armeabi-v7a Dobby from-source migration (the `## Unverified` item in the
  archived `fix-build-native-wired-source` change) is unchanged by this fix.
  Maven prebuilt `libdobby.a` armv7 is what got verified at runtime above and
  stays as-is; full armv7-from-source is a separate backlog item.
- `configPath=őz|` cosmetic garbage on the 64-bit `AgentEntry.init` call (the
  injector passes the `.so` path as `cfg`; the real per-agent config delivery
  is the channel-B work, a separate change).
