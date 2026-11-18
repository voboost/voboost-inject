#ifndef VOBOOST_PTRACE_STATE_H
#define VOBOOST_PTRACE_STATE_H

enum vbi_remote_event {
    VBI_REMOTE_RETURN_TRAP,
    VBI_REMOTE_UNEXPECTED_STOP,
    VBI_REMOTE_TIMEOUT,
    VBI_REMOTE_TARGET_GONE,
    VBI_REMOTE_WAIT_ERROR,
};

struct vbi_cleanup_plan {
    int request_stop;
    int restore_registers;
    int detach_permitted;
    int target_gone;
};

struct vbi_cleanup_plan vbi_cleanup_plan_for(enum vbi_remote_event event,
                                             int stop_proven,
                                             int restore_succeeded);
int vbi_detach_signal_for_remote_stop(int stop_signal, int exact_return_trap);
unsigned int vbi_ptrace_event_from_status(int status);
int vbi_remote_stop_signal_for_detach(int status, int exact_return_trap);

#endif
