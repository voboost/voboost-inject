#define _GNU_SOURCE
#include "ptrace_state.h"

#include <signal.h>
#include <sys/wait.h>

unsigned int vbi_ptrace_event_from_status(int status) {
    return WIFSTOPPED(status) ? (unsigned int)status >> 16 : 0;
}

int vbi_remote_stop_signal_for_detach(int status, int exact_return_trap) {
    if (!WIFSTOPPED(status) || vbi_ptrace_event_from_status(status) != 0) {
        return 0;
    }
    return vbi_detach_signal_for_remote_stop(WSTOPSIG(status), exact_return_trap);
}

int vbi_detach_signal_for_remote_stop(int stop_signal, int exact_return_trap) {
    if (exact_return_trap || stop_signal <= 0 || stop_signal >= NSIG) {
        return 0;
    }
    return stop_signal;
}

struct vbi_cleanup_plan vbi_cleanup_plan_for(enum vbi_remote_event event,
                                             int stop_proven,
                                             int restore_succeeded) {
    struct vbi_cleanup_plan plan = {0, 0, 0, 0};
    if (event == VBI_REMOTE_TARGET_GONE) {
        plan.target_gone = 1;
        return plan;
    }
    if (event == VBI_REMOTE_WAIT_ERROR) {
        plan.request_stop = 1;
        if (stop_proven) {
            plan.restore_registers = 1;
            plan.detach_permitted = restore_succeeded;
        }
        return plan;
    }

    plan.request_stop = event == VBI_REMOTE_TIMEOUT;
    if (!stop_proven) {
        return plan;
    }

    plan.restore_registers = 1;
    plan.detach_permitted = restore_succeeded;
    return plan;
}
