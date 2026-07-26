## MODIFIED Requirements

### Requirement: Hybrid ptrace remote-call mechanism

The injector SHALL perform remote calls in the target via `PTRACE_CONT` with a
return trap set by pointing the link register at address `0` (`LR=0`), catching
the resulting fault as the call-return signal. It SHALL use cross-bitness
regsets: `arm64_regs` for 64-bit targets, `user_regs_32` for 32-bit targets.
`user_regs_32` SHALL use 4-byte fields (`uint32_t uregs[18]`), matching the
kernel's 72-byte `PTRACE_GETREGSET NT_PRSTATUS` regset for a 32-bit ARM
target (`uregs[0]`=return, `uregs[13]`=sp, `uregs[14]`=lr, `uregs[15]`=pc,
`uregs[16]`=cpsr). Thumb mode for the 32-bit remote call SHALL be selected via
the CPSR.T bit (`uregs[16]` bit `0x20`), NOT via the PC LSB: the kernel writes
back an even PC regardless of the LSB of the value set, so the injector SHALL
clear the LSB of the target function address before writing `uregs[15]` and
SHALL set (Thumb) or clear (ARM) `uregs[16] & 0x20` based on that LSB.

`PTRACE_SINGLESTEP` and hardware breakpoints SHALL NOT be used: they do not work
on the target kernel (`4.14.156-perf+`), which is why a single-step-based
injector (AndKittyInjector) is rejected despite building and detecting bitness
correctly.

#### Scenario: Remote call returns via the LR=0 trap

- **WHEN** the injector invokes a remote function in the target
- **THEN** it sets `LR=0`, resumes with `PTRACE_CONT`, and treats the fault at
  address `0` as the return of the call, reading the result from the return
  register of the ABI-appropriate regset

#### Scenario: 32-bit regset uses 4-byte fields

- **WHEN** the injector reads or writes registers of a 32-bit ARM target via
  `PTRACE_GETREGSET`/`PTRACE_SETREGSET`
- **THEN** it uses a regset struct whose fields are `uint32_t` (18 fields,
  `sizeof`=72 bytes), matching the kernel's `iov_len` for that regset

#### Scenario: 32-bit Thumb calls set CPSR.T, not the PC LSB

- **WHEN** the injector remote-calls a Thumb-mode function in a 32-bit target
  (function address has LSB=1, as handed back by the linker)
- **THEN** it writes the even address to `uregs[15]` (pc) and sets bit `0x20`
  in `uregs[16]` (cpsr) before resuming, rather than relying on the PC's LSB
  to select Thumb decoding

#### Scenario: Single-step path is not used

- **WHEN** the injector runs on kernel `4.14.156-perf+`
- **THEN** it does not rely on `PTRACE_SINGLESTEP` or hardware breakpoints for
  remote-call return detection (they do not fire on this kernel)
