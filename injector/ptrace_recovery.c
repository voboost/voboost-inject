#define _GNU_SOURCE
#include "ptrace_recovery.h"

#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <time.h>

static long system_getregset(pid_t pid, void *registers, size_t *length) {
#if defined(__linux__)
    struct iovec iov = {registers, *length};
    long result = ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
    *length = iov.iov_len;
    return result;
#else
    (void)pid; (void)registers; (void)length;
    errno = ENOTSUP;
    return -1;
#endif
}

static long system_setregset(pid_t pid, const void *registers, size_t length) {
#if defined(__linux__)
    struct iovec iov = {(void *)registers, length};
    return ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
#else
    (void)pid; (void)registers; (void)length;
    errno = ENOTSUP;
    return -1;
#endif
}

static long system_detach(pid_t pid, int signal_number) {
#if defined(__linux__)
    return ptrace(PTRACE_DETACH, pid, NULL, (void *)(intptr_t)signal_number);
#else
    (void)pid; (void)signal_number;
    errno = ENOTSUP;
    return -1;
#endif
}

static const struct vbi_ptrace_syscalls SYSTEM_SYSCALLS = {
    system_getregset, system_setregset, system_detach,
};
static _Thread_local const struct vbi_ptrace_syscalls *g_syscalls = &SYSTEM_SYSCALLS;
static _Thread_local struct vbi_ptrace_health g_health;
static _Thread_local struct vbi_restore_diag g_restore_diag;

void vbi_ptrace_install_test_syscalls(const struct vbi_ptrace_syscalls *syscalls) {
    g_syscalls = syscalls ? syscalls : &SYSTEM_SYSCALLS;
}

void vbi_ptrace_reset_health(void) {
    memset(&g_health, 0, sizeof(g_health));
}

struct vbi_ptrace_health vbi_ptrace_read_health(void) {
    return g_health;
}

struct vbi_restore_diag vbi_ptrace_read_restore_diag(void) {
    return g_restore_diag;
}

static long restore_set(void *context, pid_t pid, unsigned int note,
                        const void *bytes, size_t length) {
    (void)context;
    (void)note;
    return g_syscalls->setregset(pid, bytes, length);
}
static long restore_get(void *context, pid_t pid, unsigned int note,
                        void *bytes, size_t *length) {
    (void)context;
    (void)note;
    return g_syscalls->getregset(pid, bytes, length);
}
static const struct vbi_restore_ops RESTORE_OPS = {restore_set, restore_get};

int vbi_get_regset_exact(pid_t pid, void *registers, size_t expected) {
    memset(registers, 0, expected);
    size_t length = expected;
    if (g_syscalls->getregset(pid, registers, &length) < 0 || length != expected) {
        memset(registers, 0, expected);
        return -1;
    }
    return 0;
}

int vbi_set_regset(pid_t pid, const void *registers, size_t length) {
    return g_syscalls->setregset(pid, registers, length) == 0 ? 0 : -1;
}

static unsigned long recovery_backoff_ms(unsigned long failures) {
    unsigned long shift = failures > 7 ? 7 : failures;
    return 1UL << shift;
}

static void recovery_backoff(unsigned long failures) {
    long milliseconds = (long)recovery_backoff_ms(failures);
    struct timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {
    }
}

/* Same bounded-return discipline as detach: a register restore that can never
 * succeed must give up (budget, ms) and let the caller fail the injection.
 * Returns 0 restored, 1 tracee gone (ESRCH), -1 budget exhausted. */
static int restore_until_safe(pid_t pid, const void *saved, size_t size) {
    const struct vbi_restore_regset part = {VBI_RESTORE_GPR, VBI_NT_PRSTATUS, saved, size};
    unsigned long elapsed_ms = 0;
    const unsigned long budget_ms = 2000;
    for (;;) {
        ++g_health.restore_attempts;
        errno = 0;
        if (vbi_restore_regsets_once(pid, &part, 1, &RESTORE_OPS, NULL, &g_restore_diag) == 0) {
            return 0;
        }
        if (errno == ESRCH) {
            return 1;
        }
        ++g_health.restore_failures;
        if (elapsed_ms >= budget_ms) {
            return -1;
        }
        unsigned long delay_ms = recovery_backoff_ms(g_health.restore_failures);
        recovery_backoff(g_health.restore_failures);
        elapsed_ms += delay_ms;
    }
}

int vbi_restore_arm64_until_safe(pid_t pid, const struct vbi_arm64_regs *saved) {
    return restore_until_safe(pid, saved, sizeof(*saved));
}

int vbi_restore_arm32_until_safe(pid_t pid, const struct vbi_arm32_regs *saved) {
    return restore_until_safe(pid, saved, sizeof(*saved));
}

/* Total detach budget for the production (unbounded-looking) entry point.
 * Detach normally succeeds on the first attempt; the budget only caps the
 * pathological case so the helper always returns and can exit (tracer death
 * auto-detaches the tracee). */
#define VBI_DETACH_BUDGET_MS 2000

int vbi_detach_until_safe(pid_t pid, int signal_number) {
    return vbi_detach_until_safe_bounded(pid, signal_number, VBI_DETACH_BUDGET_MS);
}

int vbi_detach_until_safe_bounded(pid_t pid, int signal_number,
                                  unsigned budget_ms) {
    unsigned long elapsed_ms = 0;
    for (;;) {
        ++g_health.detach_attempts;
        errno = 0;
        if (g_syscalls->detach(pid, signal_number) == 0) {
            return 0;
        }
        if (errno == ESRCH) {
            return 1;
        }
        ++g_health.detach_failures;
        if (elapsed_ms >= (unsigned long)budget_ms) {
            return -1;
        }
        unsigned long delay_ms = recovery_backoff_ms(g_health.detach_failures);
        recovery_backoff(g_health.detach_failures);
        elapsed_ms += delay_ms;
    }
}
