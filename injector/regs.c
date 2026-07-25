/*
 * regs.c — cross-bitness register sets for ptrace remote calls.
 *
 * 64-bit targets use arm64_regs (x0..x30, sp, pc, pstate) via NT_PRSTATUS=1
 * with PTRACE_GETREGSET/SETREGSET.
 *
 * 32-bit targets use user_regs (ARM EABI): uregs[18] where
 *   uregs[0..12]  = r0..r12 (general purpose)
 *   uregs[13]     = sp
 *   uregs[14]     = lr (link register)
 *   uregs[15]     = pc (with Thumb bit 0x1 if in Thumb mode)
 *   uregs[16]     = cpsr
 * The return value is in uregs[0].
 */

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "injector.h"

/* ---- 64-bit register set ---- */

#define ARM64_NUM_REGS 31

struct arm64_regs {
    unsigned long long regs[ARM64_NUM_REGS]; /* x0..x30 */
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

/* NT_PRSTATUS = 1 for both 32 and 64-bit */
#define NT_PRSTATUS 1

/*
 * Save the current 64-bit registers of the target.
 * Returns 0 on success, -1 on error.
 */
int regs_get64(int pid, struct arm64_regs *out) {
    struct iovec iov = { out, sizeof(*out) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    return 0;
}

/*
 * Set 64-bit registers in the target.
 * Returns 0 on success, -1 on error.
 */
int regs_set64(int pid, const struct arm64_regs *regs) {
    struct iovec iov = { (void *)regs, sizeof(*regs) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    return 0;
}

/* ---- 32-bit register set ---- */

/*
 * ARM 32-bit user_regs structure (EABI).  This matches the kernel's
 * struct user_regs_struct for ARM (see arch/arm/include/uapi/asm/ptrace.h).
 * 18 unsigned longs: r0..r15 + cpsr + orig_r0 + (padding).
 */
struct user_regs_32 {
    unsigned long uregs[18];
};

#define ARM32_R0   0
#define ARM32_SP  13
#define ARM32_LR  14
#define ARM32_PC  15
#define ARM32_CPSR 16

/*
 * Save the current 32-bit registers of the target.
 * Returns 0 on success, -1 on error.
 */
int regs_get32(int pid, struct user_regs_32 *out) {
    struct iovec iov = { out, sizeof(*out) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    return 0;
}

/*
 * Set 32-bit registers in the target.
 * Returns 0 on success, -1 on error.
 */
int regs_set32(int pid, const struct user_regs_32 *regs) {
    struct iovec iov = { (void *)regs, sizeof(*regs) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    return 0;
}
