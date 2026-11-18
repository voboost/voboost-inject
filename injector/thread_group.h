#ifndef VOBOOST_THREAD_GROUP_H
#define VOBOOST_THREAD_GROUP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define VBI_TG_MAX_THREADS 1024
#define VBI_TG_MAX_STABILIZATION_PASSES 8

enum vbi_tg_result {
    VBI_TG_OK = 0,
    VBI_TG_DENIED = -1,
    VBI_TG_GONE = -2,
    VBI_TG_IDENTITY_MISMATCH = -7,
    VBI_TG_UNSAFE_CLEANUP = -8,
};

enum vbi_tg_op_result {
    VBI_TG_OP_OK = 0,
    VBI_TG_OP_GONE = 1,
    VBI_TG_OP_DENIED = 2,
    VBI_TG_OP_ERROR = -1,
};

struct vbi_tg_task {
    pid_t tid;
    int attached;
    int stopped;
    int gone;
    int detach_signal;
};

struct vbi_thread_group {
    pid_t tgid;
    pid_t execution_tid;
    uint64_t starttime;
    struct vbi_tg_task tasks[VBI_TG_MAX_THREADS];
    size_t count;
    int stabilized;
    int managed;
};

struct vbi_tg_ops {
    int (*identity)(void *context, pid_t tid, pid_t *tgid, uint64_t *starttime);
    int (*inventory)(void *context, pid_t tgid, pid_t *tids, size_t capacity,
                     size_t *count);
    int (*attach)(void *context, pid_t tid);
    int (*wait_stopped)(void *context, pid_t tid);
    int (*set_options)(void *context, pid_t tid, int trace_clones);
    int (*detach)(void *context, pid_t tid, int signal_number);
};

int vbi_thread_group_attach_with_ops(pid_t input_tid, struct vbi_thread_group *group,
                                     const struct vbi_tg_ops *ops, void *context);
/* Keep the execution TID stopped/owned; release peers before linker or ART work. */
int vbi_thread_group_loader_ready(const struct vbi_thread_group *group);
int vbi_thread_group_enter_managed_with_ops(struct vbi_thread_group *group,
                                            const struct vbi_tg_ops *ops, void *context);
int vbi_thread_group_enter_managed(struct vbi_thread_group *group);

int vbi_thread_group_detach_with_ops(struct vbi_thread_group *group,
                                     const struct vbi_tg_ops *ops, void *context);

int vbi_thread_group_attach(pid_t input_tid, struct vbi_thread_group *group);
int vbi_thread_group_detach(struct vbi_thread_group *group);
int vbi_thread_group_verify_expected_identity(const struct vbi_thread_group *group,
                                              uint32_t expected_uid,
                                              const char *expected_selinux_context);

/* Record the automatically traced child from a PTRACE_EVENT_CLONE stop. */
int vbi_thread_group_capture_clone(struct vbi_thread_group *group, pid_t parent_tid,
                                   int parent_status);
void vbi_thread_group_retain_stop_signal(struct vbi_thread_group *group, pid_t tid,
                                         int signal_number);

/* Pure errno classification used by the bounded wait wrapper and host tests. */
int vbi_tg_classify_wait_error(int error_number);
int vbi_tg_uid_fields_match(const char *status, size_t length, uint32_t expected_uid);
int vbi_tg_selinux_context_matches(const char *actual, size_t actual_length,
                                   const char *expected);

#endif
