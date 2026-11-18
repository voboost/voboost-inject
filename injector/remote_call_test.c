#include "remote_call.h"
#include "ptrace_recovery.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>

struct fake {
    enum vbi_remote_stage failure;
    uint64_t value;
    uint64_t pc;
    uint64_t lr;
    int status;
    int wait_error;
    int stop_failure;
    int stop_status;
    int restore_failure;
    int calls;
    int sets;
    int resumes;
    int stops;
    int reads;
    int restores;
    int retained;
    int gone;
    int require_zero_lr;
    int captures;
    int signals_remaining;
    int verifies;
    int forwards;
    int verify_error;
    int forward_error;
    int waits;
    int budget;
    int deadline;
};

static int fail(enum vbi_remote_stage stage, struct fake *fake) {
    if (fake->failure == stage) {
        errno = EIO;
        return -1;
    }
    return 0;
}
static int set(void *context) {
    struct fake *fake = context;
    ++fake->sets;
    return fail(VBI_CALL_SET, fake);
}
static int resume(void *context) {
    struct fake *fake = context;
    ++fake->resumes;
    fake->deadline = fake->budget;
    return fail(VBI_CALL_CONTINUE, fake);
}
static int wait_status(void *context, int *status) {
    struct fake *fake = context;
    ++fake->waits;
    if (fake->deadline && fake->waits >= fake->deadline) {
        return 1;
    }
    if (fake->signals_remaining > 0) {
        --fake->signals_remaining;
        *status = (SIGCHLD << 8) | 0x7f;
        return 0;
    }
    if (fake->failure == VBI_CALL_TIMEOUT) {
        return 1;
    }
    if (fake->failure == VBI_CALL_WAIT) {
        errno = fake->wait_error;
        return -1;
    }
    *status = fake->status;
    return 0;
}
static int stop(void *context, int *status) {
    struct fake *fake = context;
    ++fake->stops;
    *status = fake->stop_status;
    if (fake->stop_failure) {
        errno = EIO;
        return -1;
    }
    return 0;
}
static int read_result(void *context, uint64_t *value, uint64_t *pc, uint64_t *lr) {
    struct fake *fake = context;
    ++fake->reads;
    if (fail(VBI_CALL_READ, fake) != 0) {
        return -1;
    }
    *value = fake->value;
    *pc = fake->pc;
    *lr = fake->lr;
    return 0;
}
static int restore(void *context) {
    struct fake *fake = context;
    ++fake->restores;
    if (fake->restore_failure) {
        errno = EIO;
        return -1;
    }
    return 0;
}
static void retain(void *context, int signal_number) {
    struct fake *fake = context;
    fake->retained = signal_number;
}
static void gone(void *context) {
    struct fake *fake = context;
    ++fake->gone;
}
static void capture_signal(void *context, const struct vbi_remote_result *result) {
    struct fake *fake = context;
    assert(fake->restores == 0); /* callee state precedes original restore */
    assert(WIFSTOPPED(result->wait_status));
    ++fake->captures;
    errno = EACCES; /* diagnostic callback cannot alter transport metadata */
}
static int verify_sigchld(void *context) {
    struct fake *fake = context;
    ++fake->verifies;
    errno = fake->verify_error;
    return fake->verify_error ? -1 : 0;
}
static int forward_sigchld(void *context) {
    struct fake *fake = context;
    ++fake->forwards;
    errno = fake->forward_error;
    return fake->forward_error ? -1 : 0;
}
static const struct vbi_remote_ops ops = {
    set, resume, wait_status, stop, read_result, restore, retain, gone, capture_signal,
    verify_sigchld, forward_sigchld
};
static struct vbi_remote_result call(void *context) {
    struct fake *fake = context;
    ++fake->calls;
    return vbi_remote_execute(&ops, context, fake->require_zero_lr);
}
static struct fake initial(int abi) {
    struct fake fake = {
        .failure = VBI_CALL_RETURNED,
        .status = (SIGSEGV << 8) | 0x7f,
        .wait_error = ECHILD,
        .stop_status = (SIGSTOP << 8) | 0x7f,
        .require_zero_lr = abi == 64
    };
    return fake;
}

/* The real checked dispatcher is the production caller boundary. An old
 * failure->0 mapping lets the next getter/handoff execute; this boundary
 * must neither publish that zero nor invoke any secondary callback. */
static void failure_fences_secondary_handoff(int abi, enum vbi_remote_stage stage) {
    struct fake fake = initial(abi);
    fake.failure = stage;
    int failed = 0;
    uint64_t value = UINT64_C(0xdead);
    assert(!vbi_remote_checked(&failed, call, &fake, &value));
    assert(value == UINT64_C(0xdead));
    assert(failed);
    fake.failure = VBI_CALL_RETURNED;
    assert(!vbi_remote_checked(&failed, call, &fake, &value));
    assert(fake.calls == 1); /* secondary getter/handoff never runs */
    assert(fake.restores == 1);
    assert(fake.stops == (stage == VBI_CALL_TIMEOUT || stage == VBI_CALL_WAIT));
}

static void zero_is_success(int abi) {
    struct fake fake = initial(abi);
    int failed = 0;
    uint64_t value = UINT64_C(0xdead);
    assert(vbi_remote_checked(&failed, call, &fake, &value));
    assert(value == 0 && !failed && fake.retained == 0 && fake.captures == 0);
    fake.value = 33;
    assert(vbi_remote_checked(&failed, call, &fake, &value));
    assert(value == 33 && fake.calls == 2 && fake.restores == 2);
}

static void stop_and_restore_boundaries(int abi) {
    struct fake fake = initial(abi);
    fake.pc = 0x1234;
    fake.lr = 0x5678;
    struct vbi_remote_result result = call(&fake);
    assert(!result.ok && result.restored && result.executed);
    assert(result.pc == 0x1234 && result.lr == 0x5678);
    assert(fake.retained == SIGSEGV && fake.captures == 1); /* capture precedes restore */

    fake = initial(abi);
    fake.status = (SIGABRT << 8) | 0x7f;
    fake.pc = 0x7000;
    result = call(&fake);
    assert(!result.ok && result.pc == 0x7000 && fake.captures == 1);
    assert(fake.retained == SIGABRT && result.restored && result.error == 0);

    fake = initial(abi);
    fake.status = (SIGTERM << 8) | 0x7f;
    result = call(&fake);
    assert(!result.ok && fake.retained == SIGTERM && fake.restores == 1);

    fake = initial(abi);
    fake.status = (SIGTRAP << 8) | 0x7f | (3 << 16);
    result = call(&fake);
    assert(!result.ok && fake.retained == 0 && fake.captures == 0); /* ptrace event */

    fake = initial(abi);
    fake.failure = VBI_CALL_READ;
    result = call(&fake);
    assert(!result.ok && fake.retained == SIGSEGV);

    fake = initial(abi);
    fake.failure = VBI_CALL_TIMEOUT;
    fake.stop_failure = 1;
    result = call(&fake);
    assert(!result.ok && !result.restored && fake.restores == 0);
    assert(result.stage == VBI_CALL_STOP);

    fake = initial(abi);
    fake.failure = VBI_CALL_TIMEOUT;
    fake.stop_status = (SIGSEGV << 8) | 0x7f;
    fake.pc = 0x1234;
    fake.lr = 0x5678;
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_TIMEOUT && result.restored);
    assert(result.pc == 0x1234 && result.lr == 0x5678 && fake.retained == SIGSEGV);

    fake = initial(abi);
    fake.failure = VBI_CALL_WAIT;
    fake.stop_status = (SIGTERM << 8) | 0x7f;
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_WAIT && fake.retained == SIGTERM);

    fake = initial(abi);
    fake.failure = VBI_CALL_TIMEOUT;
    fake.stop_status = (SIGSEGV << 8) | 0x7f;
    result = call(&fake);
    assert(!result.ok && fake.retained == 0 && result.restored); /* internal return trap */

    fake = initial(abi);
    fake.restore_failure = 1;
    result = call(&fake);
    assert(!result.ok && !result.restored && result.stage == VBI_CALL_RESTORE);

    fake = initial(abi);
    fake.failure = VBI_CALL_WAIT;
    fake.wait_error = ESRCH;
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_GONE
           && fake.gone == 1 && fake.stops == 0 && fake.restores == 0);

    fake = initial(abi);
    fake.status = 0;
    result = call(&fake);
    assert(!result.ok && fake.gone == 1 && fake.reads == 0 && fake.restores == 0);
}

static void origin_is_saved_context_not_callee_context(void) {
    struct vbi_arm64_regs arm64 = {.pc = UINT64_C(0x1234567890)};
    arm64.regs[30] = UINT64_C(0x2345678901);
    struct vbi_remote_origin origin = {0};
    assert(vbi_remote_capture_origin(&origin, 64, &arm64, sizeof(arm64)));
    assert(origin.valid && origin.pc == arm64.pc && origin.lr == arm64.regs[30]);
    struct fake fake = initial(64);
    fake.pc = 0x5000;
    fake.lr = 0x6000;
    struct vbi_remote_result result = call(&fake);
    result.origin = origin; /* same transfer as the production ABI adapter */
    assert(!result.ok && result.pc == 0x5000 && result.lr == 0x6000);
    assert(result.origin.pc == UINT64_C(0x1234567890));
    assert(result.origin.lr == UINT64_C(0x2345678901));
    struct vbi_arm32_regs arm32 = {0};
    arm32.uregs[15] = 0x12345678;
    arm32.uregs[14] = 0x23456789;
    assert(vbi_remote_capture_origin(&origin, 32, &arm32, sizeof(arm32)));
    assert(origin.valid && origin.pc == arm32.uregs[15] && origin.lr == arm32.uregs[14]);
    assert(!vbi_remote_capture_origin(&origin, 32, &arm32, sizeof(arm32) - 1));
    assert(!origin.valid && origin.pc == 0 && origin.lr == 0);
    assert(!vbi_remote_capture_origin(&origin, 64, NULL, sizeof(arm64)));
    assert(!origin.valid && origin.pc == 0 && origin.lr == 0);
    assert(!vbi_remote_capture_origin(&origin, 16, &arm32, sizeof(arm32)));
    assert(!origin.valid);
    assert(!vbi_remote_capture_origin(&origin, 64, &arm64, sizeof(arm64) + 1));
    assert(!origin.valid && origin.pc == 0 && origin.lr == 0);
    arm64.pc = 0;
    arm64.regs[30] = 0;
    assert(vbi_remote_capture_origin(&origin, 64, &arm64, sizeof(arm64)));
    assert(origin.valid && origin.pc == 0 && origin.lr == 0); /* zero is not unavailable */
}

static void sigchld_same_call(int abi) {
    struct fake fake = initial(abi);
    fake.signals_remaining = 1;
    struct vbi_remote_result result = call(&fake);
    assert(result.ok && fake.sets == 1 && fake.resumes == 1 && fake.waits == 2);
    assert(fake.verifies == 1 && fake.forwards == 1 && fake.retained == 0);
    assert(fake.restores == 1 && fake.reads == 1);

    fake = initial(abi);
    fake.signals_remaining = 20;
    fake.budget = 3;
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_TIMEOUT && fake.waits == 3);
    assert(fake.forwards == 2 && fake.resumes == 1 && fake.sets == 1);
    assert(fake.stops == 1 && fake.restores == 1);

    fake = initial(abi);
    fake.signals_remaining = 1;
    fake.forward_error = EIO;
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_CONTINUE && result.error == EIO);
    assert(fake.forwards == 1 && fake.waits == 1 && fake.retained == SIGCHLD);
    assert(fake.restores == 1);

    fake = initial(abi);
    fake.signals_remaining = 1;
    fake.verify_error = EINVAL; /* GETSIGINFO/group-stop or ownership failure */
    result = call(&fake);
    assert(!result.ok && fake.forwards == 0 && fake.retained == SIGCHLD);

    fake = initial(abi);
    fake.status = (SIGCHLD << 8) | 0x7f | (3 << 16);
    result = call(&fake);
    assert(!result.ok && fake.verifies == 0 && fake.forwards == 0);

    fake = initial(abi);
    fake.signals_remaining = 1;
    fake.status = 0; /* exited after signal delivery, never restore a recycled PID */
    result = call(&fake);
    assert(!result.ok && result.stage == VBI_CALL_GONE && fake.restores == 0);

    fake = initial(abi);
    fake.signals_remaining = 1;
    fake.pc = 0x1234; /* genuine SIGSEGV after handler remains fatal */
    result = call(&fake);
    assert(!result.ok && fake.retained == SIGSEGV && fake.forwards == 1);
}

int main(void) {
    origin_is_saved_context_not_callee_context();
    for (int abi = 32; abi <= 64; abi += 32) {
        sigchld_same_call(abi);
        zero_is_success(abi);
        for (enum vbi_remote_stage stage = VBI_CALL_SET; stage <= VBI_CALL_READ; ++stage) {
            if (stage != VBI_CALL_STOP) {
                failure_fences_secondary_handoff(abi, stage);
            }
        }
        stop_and_restore_boundaries(abi);
    }
    return 0;
}
