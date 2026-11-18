#include "remote_call.h"
#include "ptrace_state.h"
#include "ptrace_recovery.h"

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

int vbi_remote_capture_origin(struct vbi_remote_origin *origin, int bitness,
                              const void *registers, size_t length) {
    if (!origin) {
        return 0;
    }
    *origin = (struct vbi_remote_origin){0};
    if (!registers) {
        return 0;
    }
    if (bitness == 64 && length == sizeof(struct vbi_arm64_regs)) {
        const struct vbi_arm64_regs *saved = registers;
        origin->pc = saved->pc;
        origin->lr = saved->regs[30];
    } else if (bitness == 32 && length == sizeof(struct vbi_arm32_regs)) {
        const struct vbi_arm32_regs *saved = registers;
        origin->pc = saved->uregs[15];
        origin->lr = saved->uregs[14];
    } else {
        return 0;
    }
    origin->valid = 1;
    return 1;
}

const char *vbi_remote_stage_name(enum vbi_remote_stage stage) {
    static const char *const names[] = {
        "prepare", "set", "continue", "wait", "timeout", "stop", "read", "restore", "gone", "returned"
    };
    return stage >= VBI_CALL_PREPARE && stage <= VBI_CALL_RETURNED
           ? names[stage] : "invalid";
}

static void capture_nonreturn_signal(const struct vbi_remote_ops *ops, void *context,
                                     const struct vbi_remote_result *result, int exact_trap) {
    int signal_number = vbi_remote_stop_signal_for_detach(result->wait_status, exact_trap);
    if (ops->capture_signal && signal_number > 0 && signal_number != SIGSTOP) {
        int saved_errno = errno;
        ops->capture_signal(context, result);
        errno = saved_errno;
    }
}

struct vbi_remote_result vbi_remote_execute(
    const struct vbi_remote_ops *ops, void *context, int require_zero_lr) {
    struct vbi_remote_result result = {.stage = VBI_CALL_SET};
    if (ops->set(context) != 0) {
        result.error = errno;
        goto restore;
    }
    result.stage = VBI_CALL_CONTINUE;
    if (ops->resume(context) != 0) {
        result.error = errno;
        goto restore;
    }
    result.executed = 1;
    result.stage = VBI_CALL_WAIT;
    wait_same_call:;
    int wait_result = ops->wait(context, &result.wait_status);
    if (wait_result != 0) {
        result.error = wait_result == 1 ? ETIMEDOUT : errno;
        result.stage = wait_result == 1 ? VBI_CALL_TIMEOUT : VBI_CALL_WAIT;
        if (wait_result == -1 && result.error == ESRCH) {
            result.stage = VBI_CALL_GONE;
            ops->gone(context);
            return result;
        }
        int stop_result = ops->stop(context, &result.wait_status);
        if (stop_result != 0) {
            result.stage = VBI_CALL_STOP;
            result.error = errno;
            if (stop_result == 1) {
                result.stage = VBI_CALL_GONE;
                ops->gone(context);
            }
            return result;
        }
        /* The timeout remains a failed call even if cleanup finds the return
         * trap. Read only for diagnostics and preserve genuine signals; the
         * proven return trap is internal. Preserve the existing cleanup policy
         * for SIGSTOP: stop() requests it, but its origin remains unverified. */
        int read_ok = ops->read(context, &result.value, &result.pc, &result.lr) == 0;
        result.registers_read = read_ok;
        int exact_trap = read_ok && WIFSTOPPED(result.wait_status)
                         && WSTOPSIG(result.wait_status) == SIGSEGV
                         && (require_zero_lr ? (result.pc & ~UINT64_C(1)) == 0
                                             : result.pc == 0)
                         && (!require_zero_lr || result.lr == 0);
        if (WIFSTOPPED(result.wait_status) && WSTOPSIG(result.wait_status) != SIGSTOP) {
            ops->retain_signal(context,
                               vbi_remote_stop_signal_for_detach(result.wait_status, exact_trap));
        }
        capture_nonreturn_signal(ops, context, &result, exact_trap);
        goto restore;
    }
    if (WIFEXITED(result.wait_status) || WIFSIGNALED(result.wait_status)) {
        result.stage = VBI_CALL_GONE;
        ops->gone(context);
        return result;
    }
    if (WIFSTOPPED(result.wait_status) && WSTOPSIG(result.wait_status) == SIGCHLD
        && ((unsigned int)result.wait_status >> 16) == 0
        && ops->verify_sigchld && ops->forward_sigchld
        && ops->verify_sigchld(context) == 0) {
        if (ops->forward_sigchld(context) == 0) {
            result.stage = VBI_CALL_WAIT;
            goto wait_same_call;
        }
        /* A failed CONT has not delivered the pending signal. Preserve it for cleanup. */
        result.error = errno;
        result.stage = VBI_CALL_CONTINUE;
        ops->retain_signal(context, SIGCHLD);
        capture_nonreturn_signal(ops, context, &result, 0);
        goto restore;
    }
    result.stage = VBI_CALL_READ;
    if (ops->read(context, &result.value, &result.pc, &result.lr) != 0) {
        result.error = errno;
        capture_nonreturn_signal(ops, context, &result, 0);
        if (WIFSTOPPED(result.wait_status)) {
            ops->retain_signal(context,
                               vbi_remote_stop_signal_for_detach(result.wait_status, 0));
        }
        goto restore;
    }
    result.registers_read = 1;
    if (!WIFSTOPPED(result.wait_status)
        || WSTOPSIG(result.wait_status) != SIGSEGV
        || (require_zero_lr ? (result.pc & ~UINT64_C(1)) != 0 : result.pc != 0)
        || (require_zero_lr && result.lr != 0)) {
        result.stage = VBI_CALL_STOP;
        capture_nonreturn_signal(ops, context, &result, 0);
        if (WIFSTOPPED(result.wait_status)) {
            ops->retain_signal(context,
                               vbi_remote_stop_signal_for_detach(result.wait_status, 0));
        }
        goto restore;
    }
    result.ok = 1;
    result.stage = VBI_CALL_RETURNED;
restore:
    result.restore_attempted = 1;
    result.restored = ops->restore(context) == 0;
    if (!result.restored) {
        result.ok = 0;
        result.stage = VBI_CALL_RESTORE;
        result.error = errno;
    }
    return result;
}

int vbi_remote_checked(int *failed,
                       struct vbi_remote_result (*call)(void *context), void *context, uint64_t *value) {
    if (*failed) {
        return 0;
    }
    struct vbi_remote_result result = call(context);
    if (!result.ok) {
        *failed = 1;
        return 0;
    }
    *value = result.value;
    return 1;
}
