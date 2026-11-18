#define _GNU_SOURCE

#include "thread_group.h"
#include "ptrace_recovery.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Stage-blind failure diagnosis: attach/wait errno values collapse into the
* single VBI_TG_UNSAFE_CLEANUP return and hide the real kernel refusal
* (observed on the free-09-chinese 6.0.3 emulator: every inject ends -8). */
#include "native_diagnostic.h"
#define TGDBG(...) vbi_native_diagnostic("error", "injector.threadgroup", __VA_ARGS__)

#define VBI_TG_WAIT_TIMEOUT_MS 15000
#define VBI_TG_WAIT_STEP_MS 5

static struct vbi_tg_task *find_task(struct vbi_thread_group *group, pid_t tid) {
    for (size_t index = 0; index < group->count; ++index) {
        if (group->tasks[index].tid == tid) {
            return &group->tasks[index];
        }
    }
    return NULL;
}

int vbi_tg_classify_wait_error(int error_number) {
    return error_number == ESRCH ? VBI_TG_OP_GONE : VBI_TG_OP_ERROR;
}

static int parse_u32_token(const char **cursor, const char *end, uint32_t *value) {
    if (*cursor >= end || **cursor < '0' || **cursor > '9') {
        return 0;
    }
    uint32_t parsed = 0;
    do {
        unsigned int digit = (unsigned int)(**cursor - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) {
            return 0;
        }
        parsed = parsed * 10U + digit;
        ++*cursor;
    } while (*cursor < end && **cursor >= '0' && **cursor <= '9');
    *value = parsed;
    return 1;
}

int vbi_tg_uid_fields_match(const char *status, size_t length, uint32_t expected_uid) {
    if (!status || length == 0) {
        return 0;
    }
    const char key[] = "Uid:";
    const char *cursor = status;
    const char *end = status + length;
    int matches = 0;
    while (cursor < end) {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!line_end) {
            line_end = end;
        }
        if ((size_t)(line_end - cursor) >= sizeof(key) - 1
            && memcmp(cursor, key, sizeof(key) - 1) == 0) {
            if (matches) {
                return 0;
            }
            const char *field = cursor + sizeof(key) - 1;
            for (int index = 0; index < 4; ++index) {
                if (field >= line_end || (*field != ' ' && *field != '\t')) {
                    return 0;
                }
                while (field < line_end && (*field == ' ' || *field == '\t')) {
                    ++field;
                }
                uint32_t value = 0;
                if (!parse_u32_token(&field, line_end, &value) || value != expected_uid) {
                    return 0;
                }
            }
            while (field < line_end && (*field == ' ' || *field == '\t')) {
                ++field;
            }
            if (field != line_end) {
                return 0;
            }
            matches = 1;
        }
        cursor = line_end < end ? line_end + 1 : end;
    }
    return matches;
}

int vbi_tg_selinux_context_matches(const char *actual, size_t actual_length,
                                   const char *expected) {
    enum { MAX_SELINUX_CONTEXT_BYTES = 255 };
    if (!actual || !expected || actual_length == 0
        || actual_length > MAX_SELINUX_CONTEXT_BYTES + 1) {
        return 0;
    }
    size_t expected_length = strnlen(expected, MAX_SELINUX_CONTEXT_BYTES + 1);
    if (expected_length == 0 || expected_length > MAX_SELINUX_CONTEXT_BYTES) {
        return 0;
    }
    if (actual_length == expected_length
        && memcmp(actual, expected, expected_length) == 0) {
        return 1;
    }
    return actual_length == expected_length + 1
           && memcmp(actual, expected, expected_length) == 0
           && (actual[expected_length] == '\n' || actual[expected_length] == '\0');
}

static struct vbi_tg_task *add_task(struct vbi_thread_group *group, pid_t tid) {
    struct vbi_tg_task *existing = find_task(group, tid);
    if (existing) {
        return existing;
    }
    if (group->count >= VBI_TG_MAX_THREADS) {
        return NULL;
    }
    struct vbi_tg_task *task = &group->tasks[group->count++];
    memset(task, 0, sizeof(*task));
    task->tid = tid;
    return task;
}

static int inventory_contains(const pid_t *tids, size_t count, pid_t tid) {
    for (size_t index = 0; index < count; ++index) {
        if (tids[index] == tid) {
            return 1;
        }
    }
    return 0;
}

static int valid_inventory(pid_t tgid, const pid_t *tids, size_t count) {
    if (count == 0 || count > VBI_TG_MAX_THREADS
        || !inventory_contains(tids, count, tgid)) {
        return 0;
    }
    for (size_t index = 0; index < count; ++index) {
        if (tids[index] <= 0) {
            return 0;
        }
        for (size_t other = index + 1; other < count; ++other) {
            if (tids[index] == tids[other]) {
                return 0;
            }
        }
    }
    return 1;
}

static int verify_task_identity(const struct vbi_thread_group *group,
                                const struct vbi_tg_ops *ops, void *context, pid_t tid);

int vbi_thread_group_detach_with_ops(struct vbi_thread_group *group,
                                     const struct vbi_tg_ops *ops, void *context) {
    int result = VBI_TG_OK;
    if (group->stabilized && !group->managed) {
        pid_t inventory[VBI_TG_MAX_THREADS];
        size_t inventory_count = 0;
        int listed = ops->inventory(context, group->tgid, inventory,
                                    VBI_TG_MAX_THREADS, &inventory_count);
        if (listed == VBI_TG_OP_OK
            && valid_inventory(group->tgid, inventory, inventory_count)) {
            for (size_t index = 0; index < inventory_count; ++index) {
                if (find_task(group, inventory[index])) {
                    continue;
                }
                struct vbi_tg_task *task = add_task(group, inventory[index]);
                if (!task) {
                    result = VBI_TG_UNSAFE_CLEANUP;
                    continue;
                }
                task->attached = 1;
                if (verify_task_identity(group, ops, context, task->tid) != VBI_TG_OP_OK
                    || ops->wait_stopped(context, task->tid) != VBI_TG_OP_OK) {
                    result = VBI_TG_UNSAFE_CLEANUP;
                    continue;
                }
                task->stopped = 1;
            }
        } else if (listed != VBI_TG_OP_GONE) {
            result = VBI_TG_UNSAFE_CLEANUP;
        }
    }
    for (int execution_pass = 0; execution_pass < 2; ++execution_pass) {
        for (size_t index = group->count; index > 0; --index) {
            struct vbi_tg_task *task = &group->tasks[index - 1];
            int is_execution = task->tid == group->execution_tid;
            if (!task->attached || task->gone || is_execution != execution_pass) {
                continue;
            }
            if (!task->stopped) {
                /* The stop was never proven, so a detach here cannot be called
                 * safe — but it MUST still be attempted. Skipping the detach
                 * is how a helper previously exited while a task stayed
                 * ptrace-ATTACHED, freezing the target in ptrace_stop (live
                 * ANR, 2026-09-18). Deliver no signal: we never observed a
                 * stop-signal delivery stop for this task. */
                result = VBI_TG_UNSAFE_CLEANUP;
                int detached = ops->detach(context, task->tid, 0);
                if (detached == VBI_TG_OP_OK || detached == VBI_TG_OP_GONE) {
                    task->attached = 0;
                    task->stopped = 0;
                    task->gone = detached == VBI_TG_OP_GONE;
                }
                continue;
            }
            int detached = ops->detach(context, task->tid, task->detach_signal);
            if (detached == VBI_TG_OP_OK || detached == VBI_TG_OP_GONE) {
                task->attached = 0;
                task->stopped = 0;
                task->gone = detached == VBI_TG_OP_GONE;
            } else {
                result = VBI_TG_UNSAFE_CLEANUP;
            }
        }
    }
    return result;
}

static int fail_and_detach(struct vbi_thread_group *group, const struct vbi_tg_ops *ops,
                           void *context, int failure) {
    int cleanup = vbi_thread_group_detach_with_ops(group, ops, context);
    return cleanup == VBI_TG_OK ? failure : cleanup;
}

static int verify_task_identity(const struct vbi_thread_group *group,
                                const struct vbi_tg_ops *ops, void *context, pid_t tid) {
    pid_t observed_tgid = 0;
    uint64_t observed_starttime = 0;
    int result = ops->identity(context, tid, &observed_tgid, &observed_starttime);
    if (result != VBI_TG_OP_OK) {
        return result;
    }
    return observed_tgid == group->tgid && observed_starttime == group->starttime
               ? VBI_TG_OP_OK
               : VBI_TG_OP_ERROR;
}

int vbi_thread_group_loader_ready(const struct vbi_thread_group *group) {
    if (!group || !group->stabilized || !group->managed) {
        return 0;
    }
    int execution_owned = 0;
    for (size_t index = 0; index < group->count; ++index) {
        const struct vbi_tg_task *task = &group->tasks[index];
        if (task->tid == group->execution_tid) {
            execution_owned = task->attached && task->stopped && !task->gone;
        } else if (task->attached && !task->gone) {
            return 0;
        }
    }
    return execution_owned;
}

int vbi_thread_group_enter_managed_with_ops(struct vbi_thread_group *group,
                                            const struct vbi_tg_ops *ops, void *context) {
    if (!group || !ops || !ops->identity || !ops->set_options || !ops->detach
        || !group->stabilized || group->managed) {
        return VBI_TG_IDENTITY_MISMATCH;
    }
    struct vbi_tg_task *execution = find_task(group, group->execution_tid);
    if (!execution || !execution->attached || !execution->stopped || execution->gone) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    int identity = verify_task_identity(group, ops, context, execution->tid);
    if (identity != VBI_TG_OP_OK) {
        return identity == VBI_TG_OP_GONE ? VBI_TG_GONE : VBI_TG_IDENTITY_MISMATCH;
    }
    if (ops->set_options(context, execution->tid, 0) != VBI_TG_OP_OK) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    /* New threads can run untraced as soon as the first peer is detached.
     * Final cleanup must never infer attachment from their inventory alone. */
    group->managed = 1;
    int result = VBI_TG_OK;
    for (size_t index = group->count; index > 0; --index) {
        struct vbi_tg_task *task = &group->tasks[index - 1];
        if (task == execution || !task->attached || task->gone) {
            continue;
        }
        if (!task->stopped) {
            result = VBI_TG_UNSAFE_CLEANUP;
            continue;
        }
        int detached = ops->detach(context, task->tid, task->detach_signal);
        if (detached == VBI_TG_OP_OK || detached == VBI_TG_OP_GONE) {
            task->attached = 0;
            task->stopped = 0;
            task->gone = detached == VBI_TG_OP_GONE;
        } else {
            result = VBI_TG_UNSAFE_CLEANUP;
        }
    }
    if (result != VBI_TG_OK) {
        return result;
    }
    identity = verify_task_identity(group, ops, context, execution->tid);
    return identity == VBI_TG_OP_OK ? VBI_TG_OK
           : identity == VBI_TG_OP_GONE ? VBI_TG_GONE : VBI_TG_IDENTITY_MISMATCH;
}

int vbi_thread_group_attach_with_ops(pid_t input_tid, struct vbi_thread_group *group,
                                     const struct vbi_tg_ops *ops, void *context) {
    if (!group || !ops || !ops->identity || !ops->inventory || !ops->attach
        || !ops->wait_stopped || !ops->set_options || !ops->detach || input_tid <= 0) {
        return VBI_TG_DENIED;
    }
    memset(group, 0, sizeof(*group));

    int identity = ops->identity(context, input_tid, &group->tgid, &group->starttime);
    if (identity == VBI_TG_OP_GONE) {
        return VBI_TG_GONE;
    }
    if (identity != VBI_TG_OP_OK || group->tgid <= 0 || group->starttime == 0) {
        return VBI_TG_IDENTITY_MISMATCH;
    }

    pid_t inventory[VBI_TG_MAX_THREADS];
    for (size_t pass = 0; pass < VBI_TG_MAX_STABILIZATION_PASSES; ++pass) {
        size_t inventory_count = 0;
        int listed = ops->inventory(context, group->tgid, inventory,
                                    VBI_TG_MAX_THREADS, &inventory_count);
        if (listed == VBI_TG_OP_GONE) {
            return fail_and_detach(group, ops, context, VBI_TG_GONE);
        }
        if (listed != VBI_TG_OP_OK
            || !valid_inventory(group->tgid, inventory, inventory_count)) {
            return fail_and_detach(group, ops, context, VBI_TG_IDENTITY_MISMATCH);
        }

        for (size_t index = 0; index < inventory_count; ++index) {
            pid_t tid = inventory[index];
            struct vbi_tg_task *task = find_task(group, tid);
            if (task && task->attached && task->stopped && !task->gone) {
                continue;
            }
            int task_identity = verify_task_identity(group, ops, context, tid);
            if (task_identity == VBI_TG_OP_GONE) {
                continue;
            }
            if (task_identity != VBI_TG_OP_OK) {
                return fail_and_detach(group, ops, context,
                                       VBI_TG_IDENTITY_MISMATCH);
            }
            task = add_task(group, tid);
            if (!task) {
                return fail_and_detach(group, ops, context,
                                       VBI_TG_IDENTITY_MISMATCH);
            }
            task->gone = 0;
            int attached = ops->attach(context, tid);
            if (attached == VBI_TG_OP_GONE) {
                task->gone = 1;
                continue;
            }
            if (attached != VBI_TG_OP_OK) {
                int failure = attached == VBI_TG_OP_DENIED ? VBI_TG_DENIED
                                                           : VBI_TG_UNSAFE_CLEANUP;
                return fail_and_detach(group, ops, context, failure);
            }
            task->attached = 1;
            int waited = ops->wait_stopped(context, tid);
            if (waited == VBI_TG_OP_GONE) {
                task->gone = 1;
                task->attached = 0;
                continue;
            }
            if (waited != VBI_TG_OP_OK) {
                return fail_and_detach(group, ops, context,
                                       VBI_TG_UNSAFE_CLEANUP);
            }
            task->stopped = 1;
            if (verify_task_identity(group, ops, context, tid) != VBI_TG_OP_OK) {
                return fail_and_detach(group, ops, context,
                                       VBI_TG_IDENTITY_MISMATCH);
            }
        }

        size_t final_count = 0;
        int relisted = ops->inventory(context, group->tgid, inventory,
                                      VBI_TG_MAX_THREADS, &final_count);
        if (relisted != VBI_TG_OP_OK
            || !valid_inventory(group->tgid, inventory, final_count)) {
            int failure = relisted == VBI_TG_OP_GONE ? VBI_TG_GONE
                                                     : VBI_TG_IDENTITY_MISMATCH;
            return fail_and_detach(group, ops, context, failure);
        }
        int stable = 1;
        for (size_t index = 0; index < final_count; ++index) {
            struct vbi_tg_task *task = find_task(group, inventory[index]);
            if (!task || !task->attached || !task->stopped || task->gone) {
                stable = 0;
                break;
            }
        }
        for (size_t index = 0; index < group->count; ++index) {
            struct vbi_tg_task *task = &group->tasks[index];
            if (task->attached && !inventory_contains(inventory, final_count, task->tid)) {
                pid_t ignored_tgid = 0;
                uint64_t ignored_starttime = 0;
                if (ops->identity(context, task->tid, &ignored_tgid,
                                  &ignored_starttime)
                    == VBI_TG_OP_GONE) {
                    task->gone = 1;
                    task->attached = 0;
                    task->stopped = 0;
                } else {
                    return fail_and_detach(group, ops, context,
                                           VBI_TG_IDENTITY_MISMATCH);
                }
            }
        }
        if (!stable) {
            continue;
        }

        /* No task can clone after the stable inventory because every member
         * is stopped. Enable clone tracing only now; enabling it earlier can
         * auto-attach a child while another peer is still being inventoried. */
        for (size_t index = 0; index < group->count; ++index) {
            struct vbi_tg_task *task = &group->tasks[index];
            if (task->attached && task->stopped && !task->gone
                && ops->set_options(context, task->tid, 1) != VBI_TG_OP_OK) {
                return fail_and_detach(group, ops, context,
                                       VBI_TG_UNSAFE_CLEANUP);
            }
        }

        pid_t final_tgid = 0;
        uint64_t final_starttime = 0;
        if (ops->identity(context, group->tgid, &final_tgid, &final_starttime)
            != VBI_TG_OP_OK
            || final_tgid != group->tgid || final_starttime != group->starttime) {
            return fail_and_detach(group, ops, context,
                                   VBI_TG_IDENTITY_MISMATCH);
        }
        struct vbi_tg_task *requested = find_task(group, input_tid);
        if (requested && requested->attached && requested->stopped && !requested->gone) {
            group->execution_tid = input_tid;
        } else {
            struct vbi_tg_task *leader = find_task(group, group->tgid);
            if (leader && leader->attached && leader->stopped && !leader->gone) {
                group->execution_tid = group->tgid;
            } else {
                for (size_t index = 0; index < group->count; ++index) {
                    struct vbi_tg_task *task = &group->tasks[index];
                    if (task->attached && task->stopped && !task->gone) {
                        group->execution_tid = task->tid;
                        break;
                    }
                }
            }
        }
        if (group->execution_tid <= 0) {
            return fail_and_detach(group, ops, context, VBI_TG_GONE);
        }
        group->stabilized = 1;
        return VBI_TG_OK;
    }
    return fail_and_detach(group, ops, context, VBI_TG_IDENTITY_MISMATCH);
}

#if defined(__linux__) || defined(__ANDROID__)

static int parse_positive_pid(const char *name, pid_t *pid) {
    if (!name || !*name) {
        return 0;
    }
    if (name[0] == '0' && name[1] != '\0') {
        return 0;
    }
    unsigned long value = 0;
    for (const unsigned char *cursor = (const unsigned char *)name; *cursor; ++cursor) {
        if (!isdigit(*cursor)) {
            return 0;
        }
        unsigned int digit = (unsigned int)(*cursor - (unsigned char)'0');
        if (value > ((unsigned long)INT_MAX - digit) / 10UL) {
            return 0;
        }
        value = value * 10UL + digit;
    }
    if (value == 0) {
        return 0;
    }
    *pid = (pid_t)value;
    return 1;
}

static int read_proc_file(const char *path, char *buffer, size_t capacity, size_t *length) {
    int fd;
    do {
        fd = open(path, O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return errno == ENOENT || errno == ESRCH ? VBI_TG_OP_GONE : VBI_TG_OP_ERROR;
    }
    size_t used = 0;
    while (used < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used);
        if (count > 0) {
            used += (size_t)count;
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        return VBI_TG_OP_ERROR;
    }
    char extra;
    ssize_t overflow;
    do {
        overflow = read(fd, &extra, 1);
    } while (overflow < 0 && errno == EINTR);
    close(fd);
    if (overflow != 0 || used == 0) {
        return VBI_TG_OP_ERROR;
    }
    *length = used;
    return VBI_TG_OP_OK;
}

static int parse_status_tgid(const char *buffer, size_t length, pid_t *tgid) {
    const char key[] = "Tgid:";
    const char *cursor = buffer;
    const char *end = buffer + length;
    while (cursor < end) {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!line_end) {
            line_end = end;
        }
        if ((size_t)(line_end - cursor) > sizeof(key) - 1
            && memcmp(cursor, key, sizeof(key) - 1) == 0) {
            const char *value = cursor + sizeof(key) - 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) {
                ++value;
            }
            char digits[32];
            size_t count = (size_t)(line_end - value);
            if (count == 0 || count >= sizeof(digits)) {
                return 0;
            }
            memcpy(digits, value, count);
            digits[count] = '\0';
            return parse_positive_pid(digits, tgid);
        }
        cursor = line_end < end ? line_end + 1 : end;
    }
    return 0;
}

static int parse_stat_starttime(const char *buffer, size_t length, uint64_t *starttime) {
    const char *end = buffer + length;
    const char *close = NULL;
    for (const char *cursor = end; cursor > buffer; --cursor) {
        if (cursor[-1] == ')') {
            close = cursor - 1;
            break;
        }
    }
    if (!close || close + 2 >= end || close[1] != ' ') {
        return 0;
    }
    const char *cursor = close + 2;
    for (int field = 3; field <= 22; ++field) {
        const char *token = cursor;
        while (cursor < end && *cursor != ' ' && *cursor != '\n') {
            ++cursor;
        }
        if (token == cursor) {
            return 0;
        }
        if (field == 22) {
            uint64_t value = 0;
            for (const char *digit = token; digit < cursor; ++digit) {
                if (*digit < '0' || *digit > '9') {
                    return 0;
                }
                unsigned int part = (unsigned int)(*digit - '0');
                if (value > (UINT64_MAX - part) / 10U) {
                    return 0;
                }
                value = value * 10U + part;
            }
            if (value == 0) {
                return 0;
            }
            *starttime = value;
            return 1;
        }
        while (cursor < end && *cursor == ' ') {
            ++cursor;
        }
    }
    return 0;
}

static int system_identity(void *context, pid_t tid, pid_t *tgid, uint64_t *starttime) {
    (void)context;
    char path[64];
    char buffer[4096];
    size_t length = 0;
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    int status_result = read_proc_file(path, buffer, sizeof(buffer), &length);
    if (status_result != VBI_TG_OP_OK) {
        return status_result;
    }
    if (!parse_status_tgid(buffer, length, tgid)) {
        return VBI_TG_OP_ERROR;
    }
    snprintf(path, sizeof(path), "/proc/%d/stat", *tgid);
    int stat_result = read_proc_file(path, buffer, sizeof(buffer), &length);
    if (stat_result != VBI_TG_OP_OK) {
        return stat_result;
    }
    return parse_stat_starttime(buffer, length, starttime) ? VBI_TG_OP_OK
                                                           : VBI_TG_OP_ERROR;
}

int vbi_thread_group_verify_expected_identity(const struct vbi_thread_group *group,
                                              uint32_t expected_uid,
                                              const char *expected_selinux_context) {
    if (!group || !group->stabilized || group->tgid <= 0) {
        return VBI_TG_IDENTITY_MISMATCH;
    }
    pid_t observed_tgid = 0;
    uint64_t observed_starttime = 0;
    int identity = system_identity(NULL, group->tgid, &observed_tgid, &observed_starttime);
    if (identity == VBI_TG_OP_GONE) {
        return VBI_TG_GONE;
    }
    if (identity != VBI_TG_OP_OK || observed_tgid != group->tgid
        || observed_starttime != group->starttime) {
        return VBI_TG_IDENTITY_MISMATCH;
    }

    char path[64];
    char status[4096];
    size_t length = 0;
    snprintf(path, sizeof(path), "/proc/%d/status", group->tgid);
    int status_result = read_proc_file(path, status, sizeof(status), &length);
    if (status_result == VBI_TG_OP_GONE) {
        return VBI_TG_GONE;
    }
    if (status_result != VBI_TG_OP_OK
        || !vbi_tg_uid_fields_match(status, length, expected_uid)) {
        return VBI_TG_IDENTITY_MISMATCH;
    }

    char context[256];
    snprintf(path, sizeof(path), "/proc/%d/attr/current", group->tgid);
    int context_result = read_proc_file(path, context, sizeof(context), &length);
    if (context_result == VBI_TG_OP_GONE) {
        return VBI_TG_GONE;
    }
    if (context_result != VBI_TG_OP_OK
        || !vbi_tg_selinux_context_matches(context, length,
                                           expected_selinux_context)) {
        return VBI_TG_IDENTITY_MISMATCH;
    }
    return VBI_TG_OK;
}

static int system_inventory(void *context, pid_t tgid, pid_t *tids, size_t capacity,
                            size_t *count) {
    (void)context;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", tgid);
    DIR *directory;
    do {
        directory = opendir(path);
    } while (!directory && errno == EINTR);
    if (!directory) {
        return errno == ENOENT || errno == ESRCH ? VBI_TG_OP_GONE : VBI_TG_OP_ERROR;
    }
    *count = 0;
    errno = 0;
    struct dirent *entry;
    for (;;) {
        entry = readdir(directory);
        if (!entry && errno == EINTR) {
            errno = 0;
            continue;
        }
        if (!entry) {
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        pid_t tid = 0;
        if (!parse_positive_pid(entry->d_name, &tid) || *count >= capacity) {
            closedir(directory);
            return VBI_TG_OP_ERROR;
        }
        if (inventory_contains(tids, *count, tid)) {
            closedir(directory);
            return VBI_TG_OP_ERROR;
        }
        tids[(*count)++] = tid;
    }
    int saved_errno = errno;
    closedir(directory);
    if (saved_errno != 0 || *count == 0) {
        return saved_errno == ENOENT || saved_errno == ESRCH ? VBI_TG_OP_GONE
                                                             : VBI_TG_OP_ERROR;
    }
    return VBI_TG_OP_OK;
}

static int system_attach(void *context, pid_t tid) {
    (void)context;
    long result;
    do {
        result = ptrace(PTRACE_ATTACH, tid, NULL, NULL);
    } while (result < 0 && errno == EINTR);
    if (result == 0) {
        return VBI_TG_OP_OK;
    }
    int attach_errno = result < 0 ? errno : EIO;
    if (attach_errno == ESRCH) {
        return VBI_TG_OP_GONE;
    }
    if (attach_errno != EPERM && attach_errno != EACCES) {
        TGDBG("attach tid=%d errno=%d (%s)", tid, attach_errno, strerror(attach_errno));
    } else {
        TGDBG("attach tid=%d denied errno=%d", tid, attach_errno);
    }
    return attach_errno == EPERM || attach_errno == EACCES ? VBI_TG_OP_DENIED : VBI_TG_OP_ERROR;
}

static int wait_stopped_bounded(pid_t tid) {
    for (int elapsed = 0; elapsed < VBI_TG_WAIT_TIMEOUT_MS;
         elapsed += VBI_TG_WAIT_STEP_MS) {
        int status = 0;
        pid_t result = waitpid(tid, &status, WNOHANG | __WALL);
        if (result == tid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                return VBI_TG_OP_GONE;
            }
            return WIFSTOPPED(status) ? VBI_TG_OP_OK : VBI_TG_OP_ERROR;
        }
        if (result < 0 && errno != EINTR) {
            int wait_errno = errno;
            {
                char self_ctx[129] = {0};
                char tracee_ctx[129] = {0};
                int sfd = open("/proc/self/attr/current", O_RDONLY);
                if (sfd >= 0) {
                    ssize_t n = read(sfd, self_ctx, sizeof(self_ctx) - 1);
                    if (n > 0 && self_ctx[n - 1] == '\n') {
                        self_ctx[n - 1] = 0;
                    }
                    close(sfd);
                }
                int tfd;
                char tracee_path[64];
                snprintf(tracee_path, sizeof(tracee_path), "/proc/%d/attr/current", tid);
                tfd = open(tracee_path, O_RDONLY);
                if (tfd >= 0) {
                    ssize_t n = read(tfd, tracee_ctx, sizeof(tracee_ctx) - 1);
                    if (n > 0 && tracee_ctx[n - 1] == '\n') {
                        tracee_ctx[n - 1] = 0;
                    }
                    close(tfd);
                } else {
                    snprintf(tracee_ctx, sizeof(tracee_ctx), "open-failed");
                }
                TGDBG("wait tid=%d errno=%d (%s) self=%s tracee=%s",
                      tid, wait_errno, strerror(wait_errno), self_ctx, tracee_ctx);
            }
            return vbi_tg_classify_wait_error(wait_errno);
        }
        struct timespec delay = {0, (long)VBI_TG_WAIT_STEP_MS * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
    TGDBG("wait tid=%d timeout after %d ms", tid, (int)VBI_TG_WAIT_TIMEOUT_MS);
    return VBI_TG_OP_ERROR;
}

static int system_wait_stopped(void *context, pid_t tid) {
    (void)context;
    return wait_stopped_bounded(tid);
}

static int system_set_options(void *context, pid_t tid, int trace_clones) {
    (void)context;
    long result;
    do {
        result = ptrace(PTRACE_SETOPTIONS, tid, NULL,
                        (void *)(uintptr_t)(trace_clones ? PTRACE_O_TRACECLONE : 0));
    } while (result < 0 && errno == EINTR);
    return result == 0 ? VBI_TG_OP_OK : VBI_TG_OP_ERROR;
}

static int system_detach(void *context, pid_t tid, int signal_number) {
    (void)context;
    int result = vbi_detach_until_safe(tid, signal_number);
    if (result == 0) {
        return VBI_TG_OP_OK;
    }
    /* 1 = ESRCH (gone). -1 = bounded budget exhausted: the detach could not
     * be proven. Report OP_ERROR so the caller records an unsafe cleanup and
     * keeps returning — never an infinite retry. The helper process exiting
     * makes the kernel auto-detach the tracee. */
    return result == 1 ? VBI_TG_OP_GONE : VBI_TG_OP_ERROR;
}

static const struct vbi_tg_ops SYSTEM_OPS = {
    system_identity, system_inventory, system_attach,
    system_wait_stopped, system_set_options, system_detach,
};

int vbi_thread_group_attach(pid_t input_tid, struct vbi_thread_group *group) {
    return vbi_thread_group_attach_with_ops(input_tid, group, &SYSTEM_OPS, NULL);
}

int vbi_thread_group_detach(struct vbi_thread_group *group) {
    return vbi_thread_group_detach_with_ops(group, &SYSTEM_OPS, NULL);
}

int vbi_thread_group_enter_managed(struct vbi_thread_group *group) {
    return vbi_thread_group_enter_managed_with_ops(group, &SYSTEM_OPS, NULL);
}

int vbi_thread_group_capture_clone(struct vbi_thread_group *group, pid_t parent_tid,
                                   int parent_status) {
    if (!group || !WIFSTOPPED(parent_status)
        || (unsigned int)parent_status >> 16 != PTRACE_EVENT_CLONE) {
        return VBI_TG_OK;
    }
    unsigned long event_tid = 0;
    long event_result;
    do {
        event_result = ptrace(PTRACE_GETEVENTMSG, parent_tid, NULL, &event_tid);
    } while (event_result < 0 && errno == EINTR);
    if (event_result < 0 || event_tid == 0 || event_tid > (unsigned long)INT_MAX) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    struct vbi_tg_task *task = add_task(group, (pid_t)event_tid);
    if (!task) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    task->attached = 1;
    int waited = wait_stopped_bounded(task->tid);
    if (waited == VBI_TG_OP_GONE) {
        task->attached = 0;
        task->gone = 1;
        return VBI_TG_OK;
    }
    if (waited != VBI_TG_OP_OK) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    task->stopped = 1;
    if (system_set_options(NULL, task->tid, 1) != VBI_TG_OP_OK
        || verify_task_identity(group, &SYSTEM_OPS, NULL, task->tid) != VBI_TG_OP_OK) {
        return VBI_TG_UNSAFE_CLEANUP;
    }
    return VBI_TG_OK;
}

void vbi_thread_group_retain_stop_signal(struct vbi_thread_group *group, pid_t tid,
                                         int signal_number) {
    struct vbi_tg_task *task = group ? find_task(group, tid) : NULL;
    if (task && signal_number > 0 && signal_number < NSIG) {
        task->detach_signal = signal_number;
    }
}

#else

int vbi_thread_group_attach(pid_t input_tid, struct vbi_thread_group *group) {
    (void)input_tid;
    (void)group;
    return VBI_TG_DENIED;
}

int vbi_thread_group_detach(struct vbi_thread_group *group) {
    (void)group;
    return VBI_TG_UNSAFE_CLEANUP;
}

int vbi_thread_group_verify_expected_identity(const struct vbi_thread_group *group,
                                              uint32_t expected_uid,
                                              const char *expected_selinux_context) {
    (void)group;
    (void)expected_uid;
    (void)expected_selinux_context;
    return VBI_TG_IDENTITY_MISMATCH;
}

int vbi_thread_group_enter_managed(struct vbi_thread_group *group) {
    (void)group;
    return VBI_TG_UNSAFE_CLEANUP;
}

int vbi_thread_group_capture_clone(struct vbi_thread_group *group, pid_t parent_tid,
                                   int parent_status) {
    (void)group;
    (void)parent_tid;
    (void)parent_status;
    return VBI_TG_UNSAFE_CLEANUP;
}

void vbi_thread_group_retain_stop_signal(struct vbi_thread_group *group, pid_t tid,
                                         int signal_number) {
    struct vbi_tg_task *task = group ? find_task(group, tid) : NULL;
    if (task && signal_number > 0 && signal_number < NSIG) {
        task->detach_signal = signal_number;
    }
}

#endif
