#include "thread_group.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                                    \
        do {                                                                                     \
            if (!(expression)) {                                                                 \
                fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expression);       \
                return 1;                                                                        \
            }                                                                                    \
        } while (0)

struct fake_context {
    pid_t tgid;
    uint64_t starttime;
    pid_t snapshots[20][20];
    size_t snapshot_counts[20];
    size_t snapshot_count;
    size_t inventory_calls;
    pid_t gone_on_attach;
    pid_t denied_on_attach;
    pid_t wait_error_tid;
    pid_t mismatch_tid;
    pid_t detach_failure_tid;
    pid_t attached[32];
    size_t attach_count;
    pid_t detached[32];
    int detached_signals[32];
    size_t detach_count;
};

static int fake_identity(void *opaque, pid_t tid, pid_t *tgid, uint64_t *starttime) {
    struct fake_context *context = opaque;
    *tgid = context->tgid;
    *starttime = tid == context->mismatch_tid ? context->starttime + 1
                                              : context->starttime;
    return VBI_TG_OP_OK;
}

static int fake_inventory(void *opaque, pid_t tgid, pid_t *tids, size_t capacity,
                          size_t *count) {
    struct fake_context *context = opaque;
    if (tgid != context->tgid || context->snapshot_count == 0) {
        return VBI_TG_OP_ERROR;
    }
    size_t snapshot = context->inventory_calls++;
    if (snapshot >= context->snapshot_count) {
        snapshot = context->snapshot_count - 1;
    }
    *count = context->snapshot_counts[snapshot];
    if (*count > capacity) {
        return VBI_TG_OP_ERROR;
    }
    memcpy(tids, context->snapshots[snapshot], *count * sizeof(*tids));
    return VBI_TG_OP_OK;
}

static int fake_attach(void *opaque, pid_t tid) {
    struct fake_context *context = opaque;
    if (tid == context->gone_on_attach) {
        return VBI_TG_OP_GONE;
    }
    if (tid == context->denied_on_attach) {
        return VBI_TG_OP_DENIED;
    }
    context->attached[context->attach_count++] = tid;
    return VBI_TG_OP_OK;
}

static int fake_wait_stopped(void *opaque, pid_t tid) {
    struct fake_context *context = opaque;
    return tid == context->wait_error_tid ? VBI_TG_OP_ERROR : VBI_TG_OP_OK;
}

static int fake_set_options(void *opaque, pid_t tid, int trace_clones) {
    (void)opaque;
    (void)tid;
    (void)trace_clones;
    return VBI_TG_OP_OK;
}

static int fake_detach(void *opaque, pid_t tid, int signal_number) {
    struct fake_context *context = opaque;
    context->detached[context->detach_count] = tid;
    context->detached_signals[context->detach_count++] = signal_number;
    return tid == context->detach_failure_tid ? VBI_TG_OP_ERROR : VBI_TG_OP_OK;
}

static const struct vbi_tg_ops FAKE_OPS = {
    fake_identity, fake_inventory, fake_attach,
    fake_wait_stopped, fake_set_options, fake_detach,
};

static void init_context(struct fake_context *context) {
    memset(context, 0, sizeof(*context));
    context->tgid = 100;
    context->starttime = 777;
}

static int stable_non_leader_input(void) {
    struct fake_context context;
    init_context(&context);
    pid_t stable[] = {100, 101, 102};
    memcpy(context.snapshots[0], stable, sizeof(stable));
    memcpy(context.snapshots[1], stable, sizeof(stable));
    context.snapshot_counts[0] = 3;
    context.snapshot_counts[1] = 3;
    context.snapshot_count = 2;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(102, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    CHECK(group.tgid == 100 && group.execution_tid == 102 && group.count == 3);
    CHECK(context.attach_count == 3);
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context) == VBI_TG_OK);
    CHECK(context.detach_count == 3);
    CHECK(context.detached[0] == 101 && context.detached[2] == 102);
    CHECK(context.detached_signals[0] == 0 && context.detached_signals[2] == 0);
    return 0;
}

static int unexpected_execution_stop_is_redelivered_only_on_exact_detach(void) {
    struct fake_context context;
    init_context(&context);
    pid_t stable[] = {100};
    memcpy(context.snapshots[0], stable, sizeof(stable));
    memcpy(context.snapshots[1], stable, sizeof(stable));
    context.snapshot_counts[0] = 1;
    context.snapshot_counts[1] = 1;
    context.snapshot_count = 2;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    vbi_thread_group_retain_stop_signal(&group, 100, SIGBUS);
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context) == VBI_TG_OK);
    CHECK(context.detach_count == 1 && context.detached_signals[0] == SIGBUS);
    return 0;
}

static int clone_and_exit_races_stabilize(void) {
    struct fake_context context;
    init_context(&context);
    pid_t first[] = {100, 101};
    pid_t cloned[] = {100, 101, 102};
    memcpy(context.snapshots[0], first, sizeof(first));
    memcpy(context.snapshots[1], cloned, sizeof(cloned));
    memcpy(context.snapshots[2], cloned, sizeof(cloned));
    memcpy(context.snapshots[3], cloned, sizeof(cloned));
    context.snapshot_counts[0] = 2;
    context.snapshot_counts[1] = 3;
    context.snapshot_counts[2] = 3;
    context.snapshot_counts[3] = 3;
    context.snapshot_count = 4;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    CHECK(context.attach_count == 3);
    CHECK(group.execution_tid == 100);
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context) == VBI_TG_OK);

    init_context(&context);
    pid_t before_exit[] = {100, 101};
    pid_t after_exit[] = {100};
    memcpy(context.snapshots[0], before_exit, sizeof(before_exit));
    memcpy(context.snapshots[1], after_exit, sizeof(after_exit));
    context.snapshot_counts[0] = 2;
    context.snapshot_counts[1] = 1;
    context.snapshot_count = 2;
    context.gone_on_attach = 101;
    CHECK(vbi_thread_group_attach_with_ops(101, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    CHECK(group.execution_tid == 100);
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context) == VBI_TG_OK);
    CHECK(context.detach_count == 1 && context.detached[0] == 100);
    return 0;
}

static int partial_attach_and_detach_failures_clean_every_task(void) {
    struct fake_context context;
    init_context(&context);
    pid_t stable[] = {100, 101, 102};
    memcpy(context.snapshots[0], stable, sizeof(stable));
    context.snapshot_counts[0] = 3;
    context.snapshot_count = 1;
    context.denied_on_attach = 101;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_DENIED);
    CHECK(context.attach_count == 1 && context.attached[0] == 100);
    CHECK(context.detach_count == 1 && context.detached[0] == 100);

    init_context(&context);
    memcpy(context.snapshots[0], stable, sizeof(stable));
    context.snapshot_counts[0] = 3;
    context.snapshot_count = 1;
    context.wait_error_tid = 101;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_UNSAFE_CLEANUP);
    CHECK(context.attach_count == 2);
    /* Both attached tasks are detached; the unproven one (101) with no
    * signal but it IS detached — no attached orphan remains. Reverse task
    * order: the unproven 101 is handled first (signal 0), then 100. */
    CHECK(context.detach_count == 2);
    CHECK(context.detached[0] == 101 && context.detached[1] == 100);
    CHECK(context.detached_signals[0] == 0);

    init_context(&context);
    memcpy(context.snapshots[0], stable, sizeof(stable));
    memcpy(context.snapshots[1], stable, sizeof(stable));
    context.snapshot_counts[0] = 3;
    context.snapshot_counts[1] = 3;
    context.snapshot_count = 2;
    context.detach_failure_tid = 101;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context)
          == VBI_TG_UNSAFE_CLEANUP);
    CHECK(context.detach_count == 3);
    return 0;
}

static int clone_during_operation_is_captured_for_cleanup(void) {
    struct fake_context context;
    init_context(&context);
    context.snapshots[0][0] = 100;
    context.snapshots[1][0] = 100;
    context.snapshot_counts[0] = 1;
    context.snapshot_counts[1] = 1;
    context.snapshot_count = 2;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    context.snapshots[2][0] = 100;
    context.snapshots[2][1] = 101;
    context.snapshot_counts[2] = 2;
    context.snapshot_count = 3;
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context) == VBI_TG_OK);
    CHECK(context.detach_count == 2);
    CHECK(context.detached[0] == 101 && context.detached[1] == 100);

    init_context(&context);
    context.snapshots[0][0] = 100;
    context.snapshots[1][0] = 100;
    context.snapshot_counts[0] = 1;
    context.snapshot_counts[1] = 1;
    context.snapshot_count = 2;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    context.snapshots[2][0] = 100;
    context.snapshots[2][1] = 101;
    context.snapshot_counts[2] = 2;
    context.snapshot_count = 3;
    context.wait_error_tid = 101;
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context)
          == VBI_TG_UNSAFE_CLEANUP);
    /* The unproven-stop task (101) must STILL be detached (signal 0), never
     * left ptrace-attached after an unsafe cleanup (live ANR 2026-09-18).
     * Reverse task order: 101 (unproven, signal 0) then 100. */
    CHECK(context.detach_count == 2);
    CHECK(context.detached[0] == 101 && context.detached[1] == 100);
    CHECK(context.detached_signals[0] == 0);
    return 0;
}

static int unproven_stop_task_is_detached_with_no_signal(void) {
    /* Regression guard for the orphaned ptrace_stop: an attached task whose
     * stop was never proven is reported UNSAFE_CLEANUP but is detached with
     * signal 0 rather than skipped and left attached to the target. */
    struct fake_context context;
    init_context(&context);
    context.snapshots[0][0] = 100;
    context.snapshots[1][0] = 100;
    context.snapshot_counts[0] = 1;
    context.snapshot_counts[1] = 1;
    context.snapshot_count = 2;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_OK);
    /* Simulate a clone captured mid-call whose wait never proved a stop. */
    context.snapshots[2][0] = 100;
    context.snapshots[2][1] = 101;
    context.snapshot_counts[2] = 2;
    context.snapshot_count = 3;
    context.wait_error_tid = 101;
    CHECK(vbi_thread_group_detach_with_ops(&group, &FAKE_OPS, &context)
          == VBI_TG_UNSAFE_CLEANUP);
    CHECK(context.detach_count == 2);
    for (size_t index = 0; index < context.detach_count; ++index) {
        CHECK(context.detached_signals[index] == 0);
    }
    return 0;
}

static int identity_change_fails_closed(void) {
    struct fake_context context;
    init_context(&context);
    pid_t stable[] = {100, 101};
    memcpy(context.snapshots[0], stable, sizeof(stable));
    context.snapshot_counts[0] = 2;
    context.snapshot_count = 1;
    context.mismatch_tid = 101;

    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_IDENTITY_MISMATCH);
    CHECK(context.detach_count == 1 && context.detached[0] == 100);

    return 0;
}

static int unstable_inventory_fails_closed_and_cleans_attached_tasks(void) {
    struct fake_context context;
    struct vbi_thread_group group;

    init_context(&context);
    context.snapshot_count = 20;
    for (size_t snapshot = 0; snapshot < context.snapshot_count; ++snapshot) {
        size_t count = (snapshot + 1) / 2 + 1;
        context.snapshot_counts[snapshot] = count;
        for (size_t index = 0; index < count; ++index) {
            context.snapshots[snapshot][index] = (pid_t)(100 + index);
        }
    }
    int unstable_result =
        vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context);
    CHECK(unstable_result == VBI_TG_IDENTITY_MISMATCH);
    CHECK(context.detach_count == context.attach_count);
    return 0;
}

static int uid_and_selinux_identity_are_exact_and_bounded(void) {
    const char exact[] = "Name:\tsetting\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
    CHECK(vbi_tg_uid_fields_match(exact, sizeof(exact) - 1, 1000));
    const char mixed[] = "Uid:\t1000\t1000\t1001\t1000\n";
    CHECK(!vbi_tg_uid_fields_match(mixed, sizeof(mixed) - 1, 1000));
    const char signed_uid[] = "Uid:\t+1000\t1000\t1000\t1000\n";
    CHECK(!vbi_tg_uid_fields_match(signed_uid, sizeof(signed_uid) - 1, 1000));
    const char overflow[] = "Uid:\t4294967296\t1000\t1000\t1000\n";
    CHECK(!vbi_tg_uid_fields_match(overflow, sizeof(overflow) - 1, 1000));
    const char duplicate[] = "Uid:\t1000\t1000\t1000\t1000\nUid:\t1000\t1000\t1000\t1000\n";
    CHECK(!vbi_tg_uid_fields_match(duplicate, sizeof(duplicate) - 1, 1000));

    const char expected[] = "u:r:system_app:s0";
    CHECK(vbi_tg_selinux_context_matches(expected, sizeof(expected) - 1, expected));
    const char newline[] = "u:r:system_app:s0\n";
    CHECK(vbi_tg_selinux_context_matches(newline, sizeof(newline) - 1, expected));
    const char nul[] = {'u', ':', 'r', ':', 's', 'y', 's', 't', 'e', 'm', '_', 'a', 'p',
                        'p', ':', 's', '0', '\0'};
    CHECK(vbi_tg_selinux_context_matches(nul, sizeof(nul), expected));
    const char space[] = "u:r:system_app:s0 ";
    CHECK(!vbi_tg_selinux_context_matches(space, sizeof(space) - 1, expected));
    const char two_newlines[] = "u:r:system_app:s0\n\n";
    CHECK(!vbi_tg_selinux_context_matches(two_newlines, sizeof(two_newlines) - 1,
                                          expected));
    return 0;
}

static int malformed_inventories_fail_before_attach(void) {
    struct fake_context context;
    init_context(&context);
    context.snapshots[0][0] = 100;
    context.snapshots[0][1] = 100;
    context.snapshot_counts[0] = 2;
    context.snapshot_count = 1;
    struct vbi_thread_group group;
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &FAKE_OPS, &context)
          == VBI_TG_IDENTITY_MISMATCH);
    CHECK(context.attach_count == 0);

    init_context(&context);
    context.snapshots[0][0] = 102;
    context.snapshot_counts[0] = 1;
    context.snapshot_count = 1;
    CHECK(vbi_thread_group_attach_with_ops(102, &group, &FAKE_OPS, &context)
          == VBI_TG_IDENTITY_MISMATCH);
    CHECK(context.attach_count == 0);
    return 0;
}

struct named_test {
    const char *name;
    int (*run)(void);
};

static const struct named_test NAMED_TESTS[] = {
    {"stable_non_leader_input", stable_non_leader_input},
    {"unexpected_execution_stop_is_redelivered_only_on_exact_detach",
     unexpected_execution_stop_is_redelivered_only_on_exact_detach},
    {"clone_and_exit_races_stabilize", clone_and_exit_races_stabilize},
    {"partial_attach_and_detach_failures_clean_every_task",
     partial_attach_and_detach_failures_clean_every_task},
    {"clone_during_operation_is_captured_for_cleanup",
     clone_during_operation_is_captured_for_cleanup},
    {"unproven_stop_task_is_detached_with_no_signal",
     unproven_stop_task_is_detached_with_no_signal},
    {"identity_change_fails_closed", identity_change_fails_closed},
    {"unstable_inventory_fails_closed_and_cleans_attached_tasks",
     unstable_inventory_fails_closed_and_cleans_attached_tasks},
    {"uid_and_selinux_identity_are_exact_and_bounded",
     uid_and_selinux_identity_are_exact_and_bounded},
    {"malformed_inventories_fail_before_attach", malformed_inventories_fail_before_attach},
};

static int run_named_test(const char *name) {
    for (size_t index = 0; index < sizeof(NAMED_TESTS) / sizeof(NAMED_TESTS[0]); ++index) {
        if (strcmp(name, NAMED_TESTS[index].name) == 0) {
            return NAMED_TESTS[index].run();
        }
    }
    fprintf(stderr, "unknown thread-group test: %s\n", name);
    return 2;
}

int main(int argc, char **argv) {
    if (argc == 2) {
        return run_named_test(argv[1]);
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [named-test]\n", argv[0]);
        return 2;
    }
    CHECK(vbi_tg_classify_wait_error(ESRCH) == VBI_TG_OP_GONE);
    CHECK(vbi_tg_classify_wait_error(ECHILD) == VBI_TG_OP_ERROR);
    CHECK(vbi_tg_classify_wait_error(EINTR) == VBI_TG_OP_ERROR);
    CHECK(stable_non_leader_input() == 0);
    CHECK(unexpected_execution_stop_is_redelivered_only_on_exact_detach() == 0);
    CHECK(clone_and_exit_races_stabilize() == 0);
    CHECK(partial_attach_and_detach_failures_clean_every_task() == 0);
    CHECK(clone_during_operation_is_captured_for_cleanup() == 0);
    CHECK(unproven_stop_task_is_detached_with_no_signal() == 0);
    CHECK(identity_change_fails_closed() == 0);
    CHECK(unstable_inventory_fails_closed_and_cleans_attached_tasks() == 0);
    CHECK(uid_and_selinux_identity_are_exact_and_bounded() == 0);
    CHECK(malformed_inventories_fail_before_attach() == 0);
    return 0;
}
