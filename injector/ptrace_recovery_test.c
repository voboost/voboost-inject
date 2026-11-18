#include "ptrace_recovery.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
                             fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); return 1; \
                         } } while (0)

static unsigned char kernel_regs[sizeof(struct vbi_arm64_regs)];
static size_t kernel_regs_size;
static int set_failures;
static int detach_failures;
static int esrch_on_detach;
static int detached;
static int detached_signal;

static long fake_get(pid_t pid, void *registers, size_t *length) {
    (void)pid;
    if (*length != kernel_regs_size) {
        errno = EIO; return -1;
    }
    memcpy(registers, kernel_regs, kernel_regs_size);
    return 0;
}

static long fake_set(pid_t pid, const void *registers, size_t length) {
    (void)pid;
    if (set_failures-- > 0) {
        errno = EIO; return -1;
    }
    kernel_regs_size = length;
    memcpy(kernel_regs, registers, length);
    return 0;
}

static long fake_detach(pid_t pid, int signal_number) {
    (void)pid;
    if (esrch_on_detach) {
        errno = ESRCH; return -1;
    }
    if (detach_failures-- > 0) {
        errno = EBUSY; return -1;
    }
    detached = 1;
    detached_signal = signal_number;
    return 0;
}

static int exercise_arm64(void) {
    struct vbi_arm64_regs saved;
    for (size_t i = 0; i < 31; ++i) {
        saved.regs[i] = 0x100000000ULL + i;
    }
    saved.sp = 0x7fff12345000ULL;
    saved.pc = 0x700012345678ULL;
    saved.pstate = 0x600003c5ULL;
    struct vbi_arm64_regs temporary = saved;
    temporary.regs[0] ^= 0x55aaULL;
    temporary.regs[30] = 0;
    temporary.sp -= 256;
    temporary.pc = 0;
    memcpy(kernel_regs, &temporary, sizeof(temporary));
    kernel_regs_size = sizeof(temporary);
    set_failures = 2; detach_failures = 2; detached = 0;
    vbi_ptrace_reset_health();
    CHECK(vbi_restore_arm64_until_safe(42, &saved) == 0);
    CHECK(!detached && memcmp(kernel_regs, &saved, sizeof(saved)) == 0);
    struct vbi_restore_diag diag = vbi_ptrace_read_restore_diag();
    CHECK(diag.part == VBI_RESTORE_GPR && diag.operation == VBI_RESTORE_COMPLETE);
    CHECK(vbi_detach_until_safe(42, SIGUSR1) == 0 && detached);
    CHECK(detached_signal == SIGUSR1);
    struct vbi_ptrace_health health = vbi_ptrace_read_health();
    CHECK(health.restore_failures == 2 && health.detach_failures == 2);
    return 0;
}

static int exercise_arm32(void) {
    struct vbi_arm32_regs saved;
    for (size_t i = 0; i < 18; ++i) {
        saved.uregs[i] = 0x81000000U + (uint32_t)i;
    }
    struct vbi_arm32_regs temporary = saved;
    temporary.uregs[0] ^= 0xaa55U;
    temporary.uregs[13] -= 256U;
    temporary.uregs[14] = 0;
    temporary.uregs[15] = 0;
    memcpy(kernel_regs, &temporary, sizeof(temporary));
    kernel_regs_size = sizeof(temporary);
    set_failures = 3; detach_failures = 1; detached = 0;
    vbi_ptrace_reset_health();
    CHECK(vbi_restore_arm32_until_safe(43, &saved) == 0);
    CHECK(!detached && memcmp(kernel_regs, &saved, sizeof(saved)) == 0);
    struct vbi_restore_diag diag = vbi_ptrace_read_restore_diag();
    CHECK(diag.part == VBI_RESTORE_GPR && diag.operation == VBI_RESTORE_COMPLETE);
    CHECK(vbi_detach_until_safe(43, 0) == 0 && detached);
    CHECK(detached_signal == 0);
    struct vbi_ptrace_health health = vbi_ptrace_read_health();
    CHECK(health.restore_failures == 3 && health.detach_failures == 1);
    return 0;
}

static int exercise_bounded_detach_gives_up(void) {
    /* Regression guard for the helper stuck in nanosleep (live ANR
     * 2026-09-18): a detach that keeps failing must exhaust its budget and
     * return -1 instead of retrying forever. */
    detach_failures = 1000000; /* every attempt fails with EBUSY */
    detached = 0;
    vbi_ptrace_reset_health();
    CHECK(vbi_detach_until_safe_bounded(42, 0, 5) == -1);
    CHECK(!detached);
    struct vbi_ptrace_health health = vbi_ptrace_read_health();
    CHECK(health.detach_failures > 0);
    CHECK(health.detach_attempts == health.detach_failures);

    /* ESRCH still proves the tracee gone without burning the budget. */
    detach_failures = 1000000;
    esrch_on_detach = 1;
    vbi_ptrace_reset_health();
    CHECK(vbi_detach_until_safe_bounded(42, 0, 5000) == 1);
    esrch_on_detach = 0;
    return 0;
}

int main(void) {
    const struct vbi_ptrace_syscalls syscalls = {fake_get, fake_set, fake_detach};
    vbi_ptrace_install_test_syscalls(&syscalls);
    CHECK(exercise_arm64() == 0);
    CHECK(exercise_arm32() == 0);
    CHECK(exercise_bounded_detach_gives_up() == 0);
    vbi_ptrace_install_test_syscalls(NULL);
    return 0;
}
