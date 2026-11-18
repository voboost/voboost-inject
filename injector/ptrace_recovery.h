#ifndef VOBOOST_PTRACE_RECOVERY_H
#define VOBOOST_PTRACE_RECOVERY_H

#include "regset_restore.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct vbi_arm64_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct vbi_arm32_regs {
    uint32_t uregs[18];
};

struct vbi_ptrace_health {
    unsigned long restore_attempts;
    unsigned long restore_failures;
    unsigned long detach_attempts;
    unsigned long detach_failures;
};

struct vbi_ptrace_syscalls {
    long (*getregset)(pid_t pid, void *registers, size_t *length);
    long (*setregset)(pid_t pid, const void *registers, size_t length);
    long (*detach)(pid_t pid, int signal_number);
};

/* Test-only installation point around the production register and detach
 * syscalls. Passing NULL restores the real ptrace implementation. */
void vbi_ptrace_install_test_syscalls(const struct vbi_ptrace_syscalls *syscalls);
void vbi_ptrace_reset_health(void);
struct vbi_ptrace_health vbi_ptrace_read_health(void);
struct vbi_restore_diag vbi_ptrace_read_restore_diag(void);

int vbi_get_regset_exact(pid_t pid, void *registers, size_t expected);
int vbi_set_regset(pid_t pid, const void *registers, size_t length);
int vbi_restore_arm64_until_safe(pid_t pid, const struct vbi_arm64_regs *saved);
int vbi_restore_arm32_until_safe(pid_t pid, const struct vbi_arm32_regs *saved);
int vbi_detach_until_safe(pid_t pid, int signal_number);
/* Bounded variant: gives up after budget_ms of failed detach attempts and
 * returns -1. An unbounded retry loop is how a helper was left spinning in
 * nanosleep while the target stayed frozen in ptrace_stop (live ANR,
 * 2026-09-18): when detach cannot succeed the helper must RETURN so it can
 * exit, and tracer death makes the kernel auto-detach the tracee. */
int vbi_detach_until_safe_bounded(pid_t pid, int signal_number,
                                  unsigned budget_ms);

#endif
