#define _POSIX_C_SOURCE 200809L
#include "thread_group.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(value) do { if (!(value)) { \
                              fprintf(stderr, "managed check failed line %d: %s\n", __LINE__, #value); return 1; \
                          } } while (0)

struct fixture {
    struct vbi_thread_group *group;
    int owned[3];
    int trace_clones;
    int options_fail;
    int options_calls;
    int identity_changes_after_release;
    int identity_changed;
    pid_t fail_detach;
    pid_t gone_detach;
    pid_t detach_tids[8];
    int detach_signals[8];
    size_t detach_count;
    size_t inventory_calls;
    int new_worker;
    int new_worker_stopped;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int release_peer;
    int suspension_requested;
    int acknowledged;
    int stop_peer;
};

static int identity(void *opaque, pid_t tid, pid_t *tgid, uint64_t *starttime) {
    struct fixture *fixture = opaque;
    (void)tid;
    *tgid = 100;
    *starttime = fixture->identity_changed
                 || (fixture->identity_changes_after_release && fixture->detach_count) ? 778 : 777;
    return VBI_TG_OP_OK;
}
static int inventory(void *opaque, pid_t tgid, pid_t *tids, size_t capacity, size_t *count) {
    struct fixture *fixture = opaque;
    (void)tgid;
    ++fixture->inventory_calls;
    if (capacity < 4) {
        return VBI_TG_OP_ERROR;
    }
    tids[0] = 100; tids[1] = 101; tids[2] = 102;
    *count = 3;
    if (fixture->new_worker) {
        tids[3] = 103;
        *count = 4;
    }
    return VBI_TG_OP_OK;
}
static int attach(void *opaque, pid_t tid) {
    struct fixture *fixture = opaque;
    if (tid < 100 || tid > 102) {
        return VBI_TG_OP_ERROR;
    }
    fixture->owned[tid - 100] = 1;
    return VBI_TG_OP_OK;
}
static int wait_stopped(void *opaque, pid_t tid) {
    (void)opaque;
    return tid <= 102 ? VBI_TG_OP_OK : VBI_TG_OP_ERROR;
}
static int options(void *opaque, pid_t tid, int trace_clones) {
    struct fixture *fixture = opaque;
    ++fixture->options_calls;
    if (!trace_clones && fixture->options_fail) {
        return VBI_TG_OP_ERROR;
    }
    if (tid == 100) {
        fixture->trace_clones = trace_clones;
    }
    return VBI_TG_OP_OK;
}
static int detach(void *opaque, pid_t tid, int signal_number) {
    struct fixture *fixture = opaque;
    if (tid < 100 || tid > 102 || !fixture->owned[tid - 100]) {
        return VBI_TG_OP_ERROR;
    }
    fixture->detach_tids[fixture->detach_count] = tid;
    fixture->detach_signals[fixture->detach_count++] = signal_number;
    if (tid == fixture->fail_detach) {
        return VBI_TG_OP_ERROR;
    }
    fixture->owned[tid - 100] = 0;
    if (tid == 101) {
        pthread_mutex_lock(&fixture->mutex);
        fixture->release_peer = 1;
        pthread_cond_broadcast(&fixture->changed);
        pthread_mutex_unlock(&fixture->mutex);
    }
    return tid == fixture->gone_detach ? VBI_TG_OP_GONE : VBI_TG_OP_OK;
}
static const struct vbi_tg_ops ops = {identity, inventory, attach, wait_stopped, options, detach};

static void initialize(struct fixture *fixture, struct vbi_thread_group *group) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->group = group;
    pthread_mutex_init(&fixture->mutex, NULL);
    pthread_cond_init(&fixture->changed, NULL);
}
static void destroy(struct fixture *fixture) {
    pthread_cond_destroy(&fixture->changed);
    pthread_mutex_destroy(&fixture->mutex);
}

/* Controlled ART-like safepoint: an attached/stopped peer cannot acknowledge
 * until the actual production detach callback permits it to execute. */
static void *peer_safepoint(void *opaque) {
    struct fixture *fixture = opaque;
    pthread_mutex_lock(&fixture->mutex);
    while (!fixture->stop_peer) {
        if (fixture->release_peer && fixture->suspension_requested) {
            fixture->acknowledged = 1;
            pthread_cond_broadcast(&fixture->changed);
            break;
        }
        pthread_cond_wait(&fixture->changed, &fixture->mutex);
    }
    pthread_mutex_unlock(&fixture->mutex);
    return NULL;
}
static int await_acknowledgement(struct fixture *fixture, long milliseconds) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += milliseconds * 1000000L;
    deadline.tv_sec += deadline.tv_nsec / 1000000000L;
    deadline.tv_nsec %= 1000000000L;
    pthread_mutex_lock(&fixture->mutex);
    while (!fixture->acknowledged) {
        int result = pthread_cond_timedwait(&fixture->changed, &fixture->mutex, &deadline);
        if (result == ETIMEDOUT) {
            break;
        }
        if (result != 0) {
            pthread_mutex_unlock(&fixture->mutex);
            return 0;
        }
    }
    int acknowledged = fixture->acknowledged;
    pthread_mutex_unlock(&fixture->mutex);
    return acknowledged;
}

static int safepoint_progress_and_untraced_worker(void) {
    struct fixture fixture;
    struct vbi_thread_group group;
    initialize(&fixture, &group);
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &ops, &fixture) == VBI_TG_OK);
    CHECK(fixture.trace_clones && fixture.owned[0] && fixture.owned[1]);
    CHECK(!vbi_thread_group_loader_ready(&group));
    pthread_t peer;
    CHECK(pthread_create(&peer, NULL, peer_safepoint, &fixture) == 0);
    pthread_mutex_lock(&fixture.mutex);
    fixture.suspension_requested = 1;
    pthread_cond_broadcast(&fixture.changed);
    pthread_mutex_unlock(&fixture.mutex);
    CHECK(!await_acknowledgement(&fixture, 20)); /* reproduce before transition */
    CHECK(vbi_thread_group_enter_managed_with_ops(&group, &ops, &fixture) == VBI_TG_OK);
    CHECK(vbi_thread_group_loader_ready(&group));
    CHECK(await_acknowledgement(&fixture, 500)); /* production boundary releases peer */
    CHECK(pthread_join(peer, NULL) == 0);
    CHECK(group.managed && group.tasks[0].attached && group.tasks[0].stopped);
    CHECK(!fixture.owned[1] && !fixture.owned[2] && fixture.owned[0]);
    fixture.new_worker = 1;
    fixture.new_worker_stopped = fixture.trace_clones; /* kernel clone option contract */
    CHECK(!fixture.new_worker_stopped);
    size_t inventories = fixture.inventory_calls;
    CHECK(vbi_thread_group_detach_with_ops(&group, &ops, &fixture) == VBI_TG_OK);
    CHECK(fixture.inventory_calls == inventories); /* no false ownership of worker103 */
    CHECK(fixture.detach_count == 3 && fixture.detach_tids[2] == 100);
    CHECK(group.count == 3 && !fixture.owned[0]);
    destroy(&fixture);
    return 0;
}

static int loader_requires_owned_execution_and_no_frozen_peer(void) {
    struct fixture fixture;
    struct vbi_thread_group group;
    initialize(&fixture, &group);
    CHECK(!vbi_thread_group_loader_ready(NULL));
    CHECK(vbi_thread_group_attach_with_ops(100, &group, &ops, &fixture) == VBI_TG_OK);
    CHECK(!vbi_thread_group_loader_ready(&group));
    CHECK(vbi_thread_group_enter_managed_with_ops(&group, &ops, &fixture) == VBI_TG_OK);
    CHECK(vbi_thread_group_loader_ready(&group));
    group.tasks[1].attached = 1;
    CHECK(!vbi_thread_group_loader_ready(&group));
    group.tasks[1].attached = 0;
    group.tasks[0].stopped = 0;
    CHECK(!vbi_thread_group_loader_ready(&group));
    group.tasks[0].stopped = 1;
    group.tasks[0].gone = 1;
    CHECK(!vbi_thread_group_loader_ready(&group));
    group.tasks[0].gone = 0;
    CHECK(vbi_thread_group_detach_with_ops(&group, &ops, &fixture) == VBI_TG_OK);
    CHECK(!vbi_thread_group_loader_ready(&group));
    destroy(&fixture);
    return 0;
}

static int negative_boundaries_and_retained_signals(void) {
    for (int failure = 0; failure < 6; ++failure) {
        struct fixture fixture;
        struct vbi_thread_group group;
        initialize(&fixture, &group);
        CHECK(vbi_thread_group_attach_with_ops(100, &group, &ops, &fixture) == VBI_TG_OK);
        group.tasks[1].detach_signal = SIGTERM;
        group.tasks[2].detach_signal = SIGSTOP;
        int option_calls = fixture.options_calls;
        if (failure == 0) {
            fixture.options_fail = 1;
        }
        if (failure == 1) {
            fixture.fail_detach = 102;
        }
        if (failure == 2) {
            fixture.identity_changes_after_release = 1;
        }
        if (failure == 3) {
            fixture.gone_detach = 102;
        }
        if (failure == 4) {
            group.tasks[0].stopped = 0;
        }
        if (failure == 5) {
            fixture.identity_changed = 1;
        }
        int result = vbi_thread_group_enter_managed_with_ops(&group, &ops, &fixture);
        CHECK(vbi_thread_group_loader_ready(&group) == (failure == 3 || failure == 2));
        if (failure == 0 || failure == 4) {
            CHECK(result == VBI_TG_UNSAFE_CLEANUP && !group.managed);
            CHECK(fixture.detach_count == 0 && fixture.owned[1] && fixture.owned[2]);
        } else if (failure == 1) {
            CHECK(result == VBI_TG_UNSAFE_CLEANUP && group.managed);
            CHECK(fixture.owned[2] && !fixture.owned[1] && fixture.owned[0]);
        } else if (failure == 2 || failure == 5) {
            CHECK(result == VBI_TG_IDENTITY_MISMATCH);
            if (failure == 5) {
                CHECK(fixture.options_calls == option_calls && !group.managed);
            }
        } else {
            CHECK(result == VBI_TG_OK && group.tasks[2].gone && !group.tasks[2].attached);
        }
        if (failure == 1 || failure == 2 || failure == 3) {
            CHECK(fixture.detach_signals[0] == SIGSTOP && fixture.detach_signals[1] == SIGTERM);
            CHECK(fixture.detach_tids[0] == 102 && fixture.detach_tids[1] == 101);
            CHECK(fixture.owned[0]); /* no managed call/cleanup detached execution prematurely */
        }
        fixture.options_fail = 0;
        fixture.fail_detach = 0;
        fixture.identity_changes_after_release = 0;
        fixture.identity_changed = 0;
        group.tasks[0].stopped = 1;
        CHECK(vbi_thread_group_detach_with_ops(&group, &ops, &fixture) == VBI_TG_OK);
        CHECK(!fixture.owned[0] && !fixture.owned[1] && !fixture.owned[2]);
        destroy(&fixture);
    }
    return 0;
}

int main(void) {
    CHECK(safepoint_progress_and_untraced_worker() == 0);
    CHECK(loader_requires_owned_execution_and_no_frozen_peer() == 0);
    CHECK(negative_boundaries_and_retained_signals() == 0);
    return 0;
}
