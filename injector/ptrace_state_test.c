#define _GNU_SOURCE
#include "ptrace_state.h"

#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>

#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif

#define CHECK(expr) do { if (!(expr)) { \
                             fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); return 1; \
                         } } while (0)

int main(void) {
    CHECK(vbi_detach_signal_for_remote_stop(SIGSEGV, 1) == 0);
    CHECK(vbi_detach_signal_for_remote_stop(SIGTRAP, 0) == SIGTRAP);
    CHECK(vbi_detach_signal_for_remote_stop(SIGBUS, 0) == SIGBUS);
    CHECK(vbi_detach_signal_for_remote_stop(0, 0) == 0);
    int clone_stop = (SIGTRAP << 8) | 0x7f | (PTRACE_EVENT_CLONE << 16);
    int real_trap = (SIGTRAP << 8) | 0x7f;
    CHECK(vbi_ptrace_event_from_status(clone_stop) == PTRACE_EVENT_CLONE);
    CHECK(vbi_remote_stop_signal_for_detach(clone_stop, 0) == 0);
    CHECK(vbi_ptrace_event_from_status(real_trap) == 0);
    CHECK(vbi_remote_stop_signal_for_detach(real_trap, 0) == SIGTRAP);
    struct vbi_cleanup_plan normal =
        vbi_cleanup_plan_for(VBI_REMOTE_RETURN_TRAP, 1, 1);
    CHECK(!normal.request_stop && normal.restore_registers && normal.detach_permitted);

    struct vbi_cleanup_plan unexpected =
        vbi_cleanup_plan_for(VBI_REMOTE_UNEXPECTED_STOP, 1, 1);
    CHECK(unexpected.restore_registers && unexpected.detach_permitted);

    struct vbi_cleanup_plan timeout_running =
        vbi_cleanup_plan_for(VBI_REMOTE_TIMEOUT, 0, 0);
    CHECK(timeout_running.request_stop && !timeout_running.restore_registers);
    CHECK(!timeout_running.detach_permitted);

    struct vbi_cleanup_plan timeout_stopped =
        vbi_cleanup_plan_for(VBI_REMOTE_TIMEOUT, 1, 1);
    CHECK(timeout_stopped.request_stop && timeout_stopped.restore_registers);
    CHECK(timeout_stopped.detach_permitted);

    struct vbi_cleanup_plan restore_failure =
        vbi_cleanup_plan_for(VBI_REMOTE_UNEXPECTED_STOP, 1, 0);
    CHECK(restore_failure.restore_registers && !restore_failure.detach_permitted);

    struct vbi_cleanup_plan gone =
        vbi_cleanup_plan_for(VBI_REMOTE_TARGET_GONE, 0, 0);
    CHECK(gone.target_gone && !gone.detach_permitted);

    struct vbi_cleanup_plan wait_error =
        vbi_cleanup_plan_for(VBI_REMOTE_WAIT_ERROR, 0, 0);
    CHECK(wait_error.request_stop && !wait_error.target_gone);
    CHECK(!wait_error.restore_registers && !wait_error.detach_permitted);

    struct vbi_cleanup_plan wait_error_recovered =
        vbi_cleanup_plan_for(VBI_REMOTE_WAIT_ERROR, 1, 1);
    CHECK(wait_error_recovered.request_stop && wait_error_recovered.restore_registers);
    CHECK(wait_error_recovered.detach_permitted);

    struct vbi_cleanup_plan wait_error_restore_fault =
        vbi_cleanup_plan_for(VBI_REMOTE_WAIT_ERROR, 1, 0);
    CHECK(wait_error_restore_fault.request_stop && wait_error_restore_fault.restore_registers);
    CHECK(!wait_error_restore_fault.detach_permitted);
    return 0;
}
