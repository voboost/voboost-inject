#include "pstate_admission.h"
#include "ptrace_recovery.h"
#include <assert.h>
#include <string.h>

static struct vbi_arm64_regs kernel;
static unsigned writes;
static long old_kernel_set(void *ctx, pid_t pid, unsigned note,
                           const void *bytes, size_t length) {
    (void)ctx; (void)pid; (void)note;
    assert(length == sizeof(kernel));
    memcpy(&kernel, bytes, length);
    kernel.pstate &= ~UINT64_C(0xc00);
    writes++;
    return 0;
}
static long old_kernel_get(void *ctx, pid_t pid, unsigned note,
                           void *bytes, size_t *length) {
    (void)ctx; (void)pid; (void)note;
    assert(*length == sizeof(kernel));
    memcpy(bytes, &kernel, *length);
    return 0;
}
int main(void) {
    struct vbi_arm64_regs saved = {.pstate = UINT64_C(0x20000400)};
    const struct vbi_restore_ops ops = {old_kernel_set, old_kernel_get};
    struct vbi_restore_regset part = {
        VBI_RESTORE_GPR, VBI_NT_PRSTATUS, &saved, sizeof(saved)
    };
    struct vbi_restore_diag diag;
    kernel = saved;
    /* Reproduce the exact cycle118 expected/observed/offset mismatch using
    * production restore code and the verified old-kernel SET semantics. */
    assert(vbi_restore_regsets_once(42, &part, 1, &ops, 0, &diag) == -1);
    assert(diag.first_mismatch == 265);
    assert(diag.pstate_expected == UINT64_C(0x20000400));
    assert(diag.pstate_observed == UINT64_C(0x20000000));
    assert(diag.pstate_changed == UINT64_C(0x400));

    kernel = saved;
    writes = 0;
    if (vbi_pstate_admissible(saved.pstate)) {
        old_kernel_set(0, 42, VBI_NT_PRSTATUS, &saved, sizeof(saved));
    }
    assert(writes == 0);
    assert(memcmp(&kernel, &saved, sizeof(saved)) == 0);
    assert(!vbi_pstate_admissible(UINT64_C(0x20000800)));
    assert(!vbi_pstate_admissible(UINT64_C(0x20000c00)));
    /* Model release and natural reacquisition without a SET probe. */
    kernel.pstate = UINT64_C(0x20000000);
    saved = kernel;
    assert(vbi_pstate_admissible(saved.pstate));
    assert(vbi_restore_regsets_once(42, &part, 1, &ops, 0, &diag) == 0);
    assert(memcmp(&kernel, &saved, sizeof(saved)) == 0);
    return 0;
}
