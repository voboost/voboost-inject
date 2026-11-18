#ifndef VOBOOST_REMOTE_CALL_H
#define VOBOOST_REMOTE_CALL_H

#include <stdint.h>
#include <stddef.h>

/* Transport outcome is independent of the callee's return value. */
enum vbi_remote_stage {
    VBI_CALL_PREPARE,
    VBI_CALL_SET,
    VBI_CALL_CONTINUE,
    VBI_CALL_WAIT,
    VBI_CALL_TIMEOUT,
    VBI_CALL_STOP,
    VBI_CALL_READ,
    VBI_CALL_RESTORE,
    VBI_CALL_GONE,
    VBI_CALL_RETURNED
};

struct vbi_remote_origin {
    uint64_t pc;
    uint64_t lr;
    int valid;
};

struct vbi_remote_result {
    enum vbi_remote_stage stage;
    struct vbi_remote_origin origin;
    uint64_t value;
    uint64_t pc;
    uint64_t lr;
    int wait_status;
    int error;
    int executed;
    int restored;
    int registers_read;
    int restore_attempted;
    int ok;
};

struct vbi_remote_ops {
    int (*set)(void *context);
    int (*resume)(void *context);
    /* 0: status available, 1: timeout, -1: wait error. */
    int (*wait)(void *context, int *status);
    /* 0: stopped, 1: target gone, -1: stop not established. */
    int (*stop)(void *context, int *status);
    int (*read)(void *context, uint64_t *value, uint64_t *pc, uint64_t *lr);
    int (*restore)(void *context);
    void (*retain_signal)(void *context, int signal_number);
    void (*gone)(void *context);
    void (*capture_signal)(void *context, const struct vbi_remote_result *result);
    /* Verify an owned genuine delivery stop, then forward without resetting the call. */
    int (*verify_sigchld)(void *context);
    int (*forward_sigchld)(void *context);
};

/* Capture only saved PC/LR after the caller's exact successful register read. */
int vbi_remote_capture_origin(struct vbi_remote_origin *origin, int bitness,
                              const void *registers, size_t length);
struct vbi_remote_result vbi_remote_execute(
    const struct vbi_remote_ops *ops, void *context, int require_zero_lr);
/* One failed transport fences all following calls in this injection. */
int vbi_remote_checked(int *failed,
                       struct vbi_remote_result (*call)(void *context), void *context, uint64_t *value);
const char *vbi_remote_stage_name(enum vbi_remote_stage stage);

#endif
