/*
 * injector.c — hybrid ptrace injector (C), the daemon's native injection rail.
 *
 * Injects a .so into a target process via ptrace + remote dlopen, then makes
 * an explicit remote-call to an entry symbol (e.g. implant_init).
 *
 * Proven mechanism (PoC, vendor-Android 9, kernel 4.14.156-perf+):
 *   - bitness detection from /proc/<pid>/exe (app_process32/app_process64)
 *     with /proc/<pid>/maps /lib64/ scan fallback
 *   - remote call via PTRACE_CONT + LR=0 trap (SINGLESTEP/hw-bp do NOT work
 *     on this kernel — AndKittyInjector rejected for that reason)
 *   - cross-bitness regsets: arm64_regs (64) / user_regs_32 (32, Thumb via CPSR.T)
 *   - private target-linker exports (NOT libdl wrappers, which lose arguments)
 *   - caller_addr inside app_process for namespace resolution
 *   - .so path written ~8KB below SP (closer is clobbered by call frame)
 *   - explicit remote-call to init_sym after linker constructors complete
 *
 * See injector-remote-execution and injector-linker-reconstruction for the contract.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

#include "injector.h"
#include "injector_internal.h"
#include "init_result.h"
#include "remote_call.h"
#include "callee_frames.h"
#include "fault_record.h"
#include "handoff_result.h"
#include "maps_parse.h"
#include "ptrace_recovery.h"
#include "ptrace_state.h"
#include "regset_contract.h"
#include "pstate_admission.h"
#include "target_process_profile.h"
#include "thread_group.h"
#include "namespace_abi.h"
#include "diagnostic_time.h"

/* Native diagnostics are represented by vbi_inject return codes and logged by
* the Rust daemon into its root-owned file. The injector never uses logcat. */
#include "native_diagnostic.h"
#define DBG(...) vbi_native_diagnostic("debug", "injector", __VA_ARGS__)

/* Elapsed time is local to this injection; monoMs is CLOCK_MONOTONIC boot time.
 * Keep the existing [helper PID] prefix and diagnostic payloads searchable. */
#define TIMING(phase) DBG("timing phase=%s elapsedMs=%llu", phase, \
    (unsigned long long)vbi_diagnostic_elapsed(started_ms, vbi_diagnostic_millis()))
#define TIMED_RETURN(value) do { \
    int result = (value); \
    DBG("timing phase=return elapsedMs=%llu result=%d", \
        (unsigned long long)vbi_diagnostic_elapsed(started_ms, vbi_diagnostic_millis()), result); \
    return result; \
} while (0)

/* ---- internal types from regs.c ---- */

static int get_regset_exact(int pid, void *registers, size_t expected,
                            struct iovec *iov) {
    iov->iov_base = registers;
    iov->iov_len = expected;
    return vbi_get_regset_exact(pid, registers, expected);
}

/* ---- internal decls from elf_resolve.c ---- */

typedef unsigned long long u64;

struct vbi_extended_state {
    unsigned char floating_point[VBI_ARM64_FP_BYTES];
    unsigned char tls[8];
    size_t floating_point_length;
    size_t tls_length;
    unsigned int floating_point_note;
    int valid;
};

static _Thread_local struct vbi_extended_state g_extended_state;
static _Thread_local struct vbi_restore_diag g_remote_restore_diag;

static int get_extended_exact(pid_t pid, unsigned int note, void *bytes, size_t length) {
    struct iovec iov = {bytes, length};
    memset(bytes, 0, length);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)note, &iov) < 0
        || iov.iov_len != length) {
        memset(bytes, 0, length);
        return -1;
    }
    return 0;
}

static int save_extended_state(pid_t pid, int bitness) {
    memset(&g_extended_state, 0, sizeof(g_extended_state));
    g_extended_state.floating_point_note =
        bitness == 64 ? VBI_NT_FPREGSET : VBI_NT_ARM_VFP;
    g_extended_state.floating_point_length =
        vbi_regset_expected_length(bitness, g_extended_state.floating_point_note);
    g_extended_state.tls_length =
        vbi_regset_expected_length(bitness, VBI_NT_ARM_TLS);
    if (get_extended_exact(pid, g_extended_state.floating_point_note,
                           g_extended_state.floating_point,
                           g_extended_state.floating_point_length) < 0
        || get_extended_exact(pid, VBI_NT_ARM_TLS, g_extended_state.tls,
                              g_extended_state.tls_length) < 0) {
        memset(&g_extended_state, 0, sizeof(g_extended_state));
        return -1;
    }
    g_extended_state.valid = 1;
    return 0;
}

static long extended_restore_set(void *context, pid_t pid, unsigned int note,
                                 const void *bytes, size_t length) {
    (void)context;
    struct iovec iov = {(void *)bytes, length};
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)note, &iov);
}
static long extended_restore_get(void *context, pid_t pid, unsigned int note,
                                 void *bytes, size_t *length) {
    (void)context;
    struct iovec iov = {bytes, *length};
    long result = ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)note, &iov);
    *length = iov.iov_len;
    return result;
}
static const struct vbi_restore_ops EXTENDED_RESTORE_OPS = {
    extended_restore_set, extended_restore_get
};

static int restore_extended_state(pid_t pid) {
    if (!g_extended_state.valid) {
        g_remote_restore_diag = (struct vbi_restore_diag){.part = VBI_RESTORE_FP,
                                                          .operation = VBI_RESTORE_UNAVAILABLE, .reason = VBI_RESTORE_NO_SNAPSHOT};
        return -1;
    }
    const struct vbi_restore_regset parts[] = {
        {VBI_RESTORE_FP, g_extended_state.floating_point_note,
         g_extended_state.floating_point, g_extended_state.floating_point_length},
        {VBI_RESTORE_TLS, VBI_NT_ARM_TLS, g_extended_state.tls, g_extended_state.tls_length}
    };
    /* Retain the existing attempt count/backoff and set-FP/set-TLS then
     * get-FP/compare/get-TLS/compare ordering; only metadata is added. */
    for (int attempts = 0; attempts < 200; ++attempts) {
        if (vbi_restore_regsets_once(pid, parts, 2, &EXTENDED_RESTORE_OPS,
                                     NULL, &g_remote_restore_diag) == 0) {
            g_extended_state.valid = 0;
            return 0;
        }
        if (errno == ESRCH) {
            return -1;
        }
        struct timespec retry = {0, 10L * 1000 * 1000};
        while (nanosleep(&retry, &retry) < 0 && errno == EINTR) {
        }
    }
    return -1;
}

int  target_read_mem(int pid, u64 addr, void *buf, size_t len);
int  target_write_mem(int pid, u64 addr, const void *buf, size_t len);
int  target_verify_mem(int pid, u64 addr, const void *expected, size_t len);
u64  find_target_caller_addr(int pid);
u64  resolve_loader_symbol(int pid, int bitness, const char *sym_name);
int vbi_target_libc_entry_busy(int pid, int bitness, u64 pc, u64 lr);

/* Read only stopped-target mappings; no target code or memory is changed. */
static int loader_entry_busy(int pid, int bitness, u64 pc, u64 lr) {
    char path[96];
    int length = snprintf(path, sizeof(path), "/proc/%d/task/%d/maps", pid, pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }
    FILE *maps = fopen(path, "re");
    if (!maps) {
        return -1;
    }
    char *line = NULL;
    size_t capacity = 0, total_bytes = 0, total_lines = 0;
    int linker_found = 0, busy = 0, valid = 1;
    ssize_t count;
    while ((count = getline(&line, &capacity, maps)) >= 0) {
        if (!vbi_maps_budget_add((size_t)count, line[count - 1] == '\n',
                                 &total_bytes, &total_lines)) {
            valid = 0;
            break;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(line, &entry)) {
            continue;
        }
        if (entry.perms[2] == 'x' && vbi_map_is_linker(&entry, bitness == 64)) {
            linker_found = 1;
        }
        busy |= vbi_map_blocks_loader_entry(&entry, bitness, pc, lr);
    }
    valid = valid && !ferror(maps) && linker_found;
    free(line);
    fclose(maps);
    return valid ? busy : -1;
}

static int scratch_is_in_exact_thread_stack(int pid, u64 stack_pointer,
                                            u64 scratch_start,
                                            size_t scratch_size) {
    char path[96];
    int length = snprintf(path, sizeof(path), "/proc/%d/task/%d/maps", pid, pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return 0;
    }
    FILE *maps = fopen(path, "re");
    if (!maps) {
        return 0;
    }
    char *line = NULL;
    size_t capacity = 0;
    size_t total_bytes = 0;
    size_t total_lines = 0;
    int matched = 0;
    ssize_t count;
    while ((count = getline(&line, &capacity, maps)) >= 0) {
        int complete = count > 0 && line[count - 1] == '\n';
        if (!vbi_maps_budget_add((size_t)count, complete,
                                 &total_bytes, &total_lines)) {
            matched = 0;
            break;
        }
        struct vbi_map_entry entry;
        if (vbi_parse_map_line(line, &entry)
            && vbi_scratch_range_in_stack(&entry, pid, stack_pointer,
                                          scratch_start, scratch_size)) {
            matched++;
        }
    }
    free(line);
    if (ferror(maps)) {
        matched = 0;
    }
    fclose(maps);
    return matched == 1;
}

/* ---- bitness detection ---- */

/*
 * Detect the target process bitness at runtime.
 *
 * Checks /proc/<pid>/exe for app_process32 vs app_process64, then falls
 * back to scanning /proc/<pid>/maps for /lib64/.
 *
 * Returns: 64, 32, or 0 on failure (injector-linker-reconstruction: bitness MUST be
 * detected per-injection, never from a static agent→bitness table).
 */
static int detect_bitness(int pid) {
    char exe_path[64];
    char buf[512];
    ssize_t n;

    /* Method 1: readlink /proc/<pid>/exe */
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    n = readlink(exe_path, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        if (strcmp(buf, "/system/bin/app_process32") == 0
            || strcmp(buf, "/system/bin/app_process32_real") == 0) {
            return 32;
        }
        if (strcmp(buf, "/system/bin/app_process64") == 0
            || strcmp(buf, "/system/bin/app_process64_real") == 0) {
            return 64;
        }
    }

    /* Method 2: scan maps for /lib64/ (64-bit) vs absence (32-bit) */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return 0;
    }
    size_t total_bytes = 0;
    size_t total_lines = 0;
    while (fgets(buf, sizeof(buf), f)) {
        size_t length = strlen(buf);
        int complete = length && (buf[length - 1] == '\n' || feof(f));
        if (!vbi_maps_budget_add(length, complete, &total_bytes, &total_lines)) {
            fclose(f);
            return 0;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(buf, &entry)) {
            continue;
        }
        const char *system64 = "/system/lib64/";
        const char *vendor64 = "/vendor/lib64/";
        if ((entry.path_len > strlen(system64)
             && memcmp(entry.path, system64, strlen(system64)) == 0)
            || (entry.path_len > strlen(vendor64)
                && memcmp(entry.path, vendor64, strlen(vendor64)) == 0)) {
            fclose(f);
            return 64;
        }
    }
    fclose(f);
    /* No /lib64/ found — likely 32-bit */
    return 32;
}

static int verify_target_executable(int pid, int bitness) {
    char exe_path[64];
    char resolved[512];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t count = readlink(exe_path, resolved, sizeof(resolved) - 1);
    if (count <= 0 || (size_t)count >= sizeof(resolved) - 1) {
        return 0;
    }
    resolved[count] = '\0';
    return vbi_target_app_process_path_matches(resolved, bitness);
}

/* ---- 64-bit remote call ---- */

/*
 * Call a function in a 64-bit target via ptrace.
 * Sets x0..x7 for up to 8 args, LR=0 (trap on return), PC=func_addr.
 * Resumes with PTRACE_CONT; catches SIGSEGV-at-0 as the return signal.
 * Returns the x0 (return value) of the called function.
 */
/* Per-attempt cleanup state. A failed stop or register restore makes detach
 * unsafe: detaching a running tracee with the temporary LR/PC/SP frame would
 * hand corrupted execution back to the OEM process. */
static _Thread_local int g_tracee_detach_safe = 1;
static _Thread_local int g_tracee_gone = 0;
static _Thread_local int g_thread_group_cleanup_safe = 1;
static _Thread_local struct vbi_thread_group *g_active_thread_group = NULL;

static void set_execution_stopped(int stopped) {
    if (!g_active_thread_group) {
        return;
    }
    for (size_t index = 0; index < g_active_thread_group->count; ++index) {
        if (g_active_thread_group->tasks[index].tid == g_active_thread_group->execution_tid) {
            g_active_thread_group->tasks[index].stopped = stopped;
            return;
        }
    }
}

static void retain_execution_stop_signal(int signal_number) {
    if (g_active_thread_group) {
        vbi_thread_group_retain_stop_signal(
            g_active_thread_group, g_active_thread_group->execution_tid, signal_number);
    }
}

/* Bounded wait for a ptrace event. */
#define VBI_CALL_TIMEOUT_MS 15000
#define VBI_WAIT_EVENT 0
#define VBI_WAIT_TIMEOUT 1
#define VBI_WAIT_ERROR (-1)
static int call_deadline(struct timespec *deadline) {
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) {
        return -1;
    }
    deadline->tv_sec += VBI_CALL_TIMEOUT_MS / 1000;
    deadline->tv_nsec += (VBI_CALL_TIMEOUT_MS % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        ++deadline->tv_sec;
        deadline->tv_nsec -= 1000000000L;
    }
    return 0;
}

static int waitpid_until(pid_t pid, int *out_status, const struct timespec *deadline) {
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            return VBI_WAIT_ERROR;
        }
        if (now.tv_sec > deadline->tv_sec
            || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
            return VBI_WAIT_TIMEOUT;
        }
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG | __WALL);
        if (r == pid) {
            unsigned int event = vbi_ptrace_event_from_status(status);
            if (event == PTRACE_EVENT_CLONE) {
                if (!g_active_thread_group
                    || vbi_thread_group_capture_clone(g_active_thread_group, pid, status)
                    != VBI_TG_OK) {
                    g_thread_group_cleanup_safe = 0;
                    *out_status = status;
                    return VBI_WAIT_ERROR;
                }
                /* A ptrace event is encoded as a SIGTRAP stop but is not a
                 * signal-delivery stop. Consume it with signal 0 and keep
                 * waiting for the deliberate LR=0 return trap. */
                if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
                    *out_status = status;
                    return VBI_WAIT_ERROR;
                }
                set_execution_stopped(0);
                continue;
            }
            *out_status = status;
            return VBI_WAIT_EVENT;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return VBI_WAIT_ERROR;
        }
        struct timespec ts = {0, 5L * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

static int waitpid_bounded_status(pid_t pid, int *out_status) {
    struct timespec deadline;
    if (call_deadline(&deadline) != 0) {
        return VBI_WAIT_ERROR;
    }
    return waitpid_until(pid, out_status, &deadline);
}

/* PTRACE_ATTACH flow cannot use PTRACE_INTERRUPT (that request is for
 * PTRACE_SEIZE). SIGSTOP is unmaskable: deliver it, wait for an actual ptrace
 * stop, and only then permit register restore or detach. Bounded overall: a
 * tracee that never reaches a stop must give up so the injection returns and
 * the helper can exit (tracer death auto-detaches the tracee). */
static int stop_tracee_for_cleanup(pid_t pid, int *out_status) {
    const int max_attempts = 3;
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        if (kill(pid, SIGSTOP) == 0) {
            int wait_result = waitpid_bounded_status(pid, out_status);
            if (wait_result == VBI_WAIT_EVENT && WIFSTOPPED(*out_status)) {
                set_execution_stopped(1);
                return 0;
            }
            if (wait_result == VBI_WAIT_EVENT
                && (WIFEXITED(*out_status) || WIFSIGNALED(*out_status))) {
                g_tracee_gone = 1;
                return -1;
            }
        } else if (errno == ESRCH) {
            g_tracee_gone = 1;
            return -1;
        }
        struct timespec retry = {0, 10L * 1000 * 1000};
        while (nanosleep(&retry, &retry) < 0 && errno == EINTR) {
        }
    }
    return -1;
}

/* Block catchable termination signals around the LR=0 remote-call window.
 * This code runs only in the exec-owned injection helper. A graceful helper
 * shutdown is blocked here, while daemon SIGKILL cannot kill or auto-detach
 * the helper that owns the saved registers and ptrace relationship. */
static int block_term_signals(sigset_t *old) {
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGHUP);
    return sigprocmask(SIG_BLOCK, &block, old);
}
static void restore_term_signals(const sigset_t *old) {
    sigprocmask(SIG_SETMASK, old, NULL);
}

struct remote_context {
    int pid;
    int bitness;
    union {
        struct vbi_arm64_regs arm64;
        struct vbi_arm32_regs arm32;
    } original, frame;
    unsigned char saved_stack[64];
    uint64_t stack_address;
    size_t stack_bytes;
    int stack_saved;
    struct timespec deadline;
};

static int remote_set(void *opaque) {
    struct remote_context *context = opaque;
    g_tracee_detach_safe = 0;
    return vbi_set_regset(context->pid, &context->frame,
                          context->bitness == 64 ? sizeof(context->frame.arm64)
                              : sizeof(context->frame.arm32));
}

static int remote_resume(void *opaque) {
    struct remote_context *context = opaque;
    if (call_deadline(&context->deadline) != 0) {
        return -1;
    }
    if (ptrace(PTRACE_CONT, context->pid, NULL, NULL) < 0) {
        return -1;
    }
    set_execution_stopped(0);
    return 0;
}

static int remote_verify_sigchld(void *opaque) {
    struct remote_context *context = opaque;
    if (!g_active_thread_group || g_active_thread_group->execution_tid != context->pid) {
        errno = EPERM;
        return -1;
    }
    int owned = 0;
    for (size_t index = 0; index < g_active_thread_group->count; ++index) {
        const struct vbi_tg_task *task = &g_active_thread_group->tasks[index];
        if (task->tid == context->pid && task->attached && task->stopped && !task->gone) {
            owned = 1;
        }
    }
    siginfo_t info = {0};
    if (!owned || ptrace(PTRACE_GETSIGINFO, context->pid, NULL, &info) != 0) {
        if (!owned) {
            errno = EPERM;
        }
        return -1;
    }
    if (info.si_signo != SIGCHLD) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int remote_forward_sigchld(void *opaque) {
    struct remote_context *context = opaque;
    if (ptrace(PTRACE_CONT, context->pid, NULL, (void *)(uintptr_t)SIGCHLD) < 0) {
        return -1;
    }
    set_execution_stopped(0);
    return 0;
}

static int remote_wait(void *opaque, int *status) {
    struct remote_context *context = opaque;
    int result = waitpid_until(context->pid, status, &context->deadline);
    if (result == VBI_WAIT_TIMEOUT) {
        return 1;
    }
    if (result == VBI_WAIT_ERROR) {
        return -1;
    }
    set_execution_stopped(1);
    return 0;
}

static int remote_stop(void *opaque, int *status) {
    struct remote_context *context = opaque;
    int result = stop_tracee_for_cleanup(context->pid, status);
    return result == 0 ? 0 : (g_tracee_gone ? 1 : -1);
}

static int remote_read(void *opaque, uint64_t *value, uint64_t *pc, uint64_t *lr) {
    struct remote_context *context = opaque;
    size_t length = context->bitness == 64 ? sizeof(context->frame.arm64)
                                         : sizeof(context->frame.arm32);
    struct iovec iov = {&context->frame, length};
    if (get_regset_exact(context->pid, &context->frame, length, &iov) < 0) {
        return -1;
    }
    if (context->bitness == 64) {
        *value = context->frame.arm64.regs[0];
        *pc = context->frame.arm64.pc;
        *lr = context->frame.arm64.regs[30];
    } else {
        *value = context->frame.arm32.uregs[0];
        *pc = context->frame.arm32.uregs[15];
        *lr = context->frame.arm32.uregs[14];
    }
    return 0;
}

static int remote_restore(void *opaque) {
    struct remote_context *context = opaque;
    int stack_result = 0;
    int stack_error = 0;
    if (context->stack_saved) {
        stack_result = target_write_mem(context->pid, context->stack_address,
                                        context->saved_stack, context->stack_bytes);
        stack_error = errno;
    }
    int result = context->bitness == 64
        ? vbi_restore_arm64_until_safe(context->pid, &context->original.arm64)
        : vbi_restore_arm32_until_safe(context->pid, &context->original.arm32);
    g_remote_restore_diag = vbi_ptrace_read_restore_diag();
    if (result == 0 && restore_extended_state(context->pid) != 0) {
        result = -1;
    }
    if (stack_result != 0) {
        g_remote_restore_diag = (struct vbi_restore_diag){.part = VBI_RESTORE_STACK,
                                                          .operation = VBI_RESTORE_SET, .reason = VBI_RESTORE_SYSCALL,
                                                          .error = stack_error, .errno_valid = stack_error != 0,
                                                          .expected_length = context->stack_bytes};
    }
    if (result != 0 || stack_result != 0) {
        g_tracee_gone = result == 1;
        g_tracee_detach_safe = 0;
        return -1;
    }
    g_tracee_detach_safe = 1;
    return 0;
}

static void remote_retain_signal(void *opaque, int signal_number) {
    (void)opaque;
    retain_execution_stop_signal(signal_number);
}

static void remote_gone(void *opaque) {
    (void)opaque;
    g_tracee_gone = 1;
}

struct callee_capture_context { int pid; };

static void callee_record(struct callee_capture_context *capture, const char *record, size_t length) {
    (void)capture;
    vbi_native_diagnostic("error", "injector.callee", "%.*s", (int)length, record);
}

static int callee_read_pair(void *opaque, uint64_t fp, uint64_t pair[2]) {
    struct callee_capture_context *capture = opaque;
    return target_read_mem(capture->pid, fp, pair, sizeof(uint64_t) * 2);
}

static void callee_emit(void *opaque, size_t index, uint64_t fp, uint64_t return_address) {
    struct callee_capture_context *capture = opaque;
    char line[224];
    int length = snprintf(line, sizeof(line),
                          "[%d] callee-frame pid=%d index=%zu fp=0x%llx return=0x%llx\n",
                          (int)getpid(), capture->pid, index, (unsigned long long)fp,
                          (unsigned long long)return_address);
    if (length > 0 && (size_t)length < sizeof(line)) {
        callee_record(capture, line, (size_t)length);
    }
}

/* Fixed buffers: maps bounds never require getline, heap allocation or JNI. */
static int callee_stack_bounds(int tgid, int tid, uint64_t sp, uint64_t *start, uint64_t *end,
                               const struct vbi_remote_result *result,
                               struct callee_capture_context *capture) {
    char path[96];
    int length = snprintf(path, sizeof(path), "/proc/%d/task/%d/maps", tgid, tid);
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return 0;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return 0;
    }
    char chunk[4096];
    char line[1024];
    size_t used = 0, total_bytes = 0, total_lines = 0;
    int matched = 0, valid = 1;
    unsigned int mapped = 0;
    ssize_t count;
    while ((count = read(fd, chunk, sizeof(chunk))) > 0) {
        for (ssize_t byte = 0; byte < count; ++byte) {
            if (used >= sizeof(line) - 1) {
                valid = 0; goto finish_maps;
            }
            line[used++] = chunk[byte];
            if (chunk[byte] != '\n') {
                continue;
            }
            line[used] = '\0';
            if (!vbi_maps_budget_add(used, 1, &total_bytes, &total_lines)) {
                valid = 0; goto finish_maps;
            }
            struct vbi_map_entry entry;
            if (!vbi_parse_map_line(line, &entry)) {
                valid = 0; /* Preserve the conservative unwind contract. */
                used = 0;
                continue; /* Still collect independent mapped PC/LR evidence. */
            }
            const uint64_t addresses[] = {result->pc, result->lr};
            const char *const labels[] = {"pc", "lr"};
            for (size_t index = 0; index < 2; ++index) {
                if ((mapped & (1U << index)) || addresses[index] < entry.start
                    || addresses[index] >= entry.end) {
                    continue;
                }
                mapped |= 1U << index;
                const char *identity = vbi_fault_image(entry.path, entry.path_len);
                char record[256];
                int length = snprintf(record, sizeof(record),
                                      "[%d] callee-map pid=%d register=%s start=0x%llx end=0x%llx offset=0x%llx perms=%.4s image=%s\n",
                                      (int)getpid(), tid, labels[index],
                                      (unsigned long long)entry.start,
                                      (unsigned long long)entry.end,
                                      (unsigned long long)entry.file_offset, entry.perms, identity);
                if (length > 0 && (size_t)length < sizeof(record)) {
                    callee_record(capture, record, (size_t)length);
                }
            }
            if (vbi_map_is_exact_thread_stack(&entry, tid) && sp >= entry.start && sp < entry.end
                && (tid == tgid || !vbi_map_path_equals(&entry, "[stack]"))) {
                ++matched;
                *start = entry.start;
                *end = entry.end;
            }
            used = 0;
        }
    }
    if (count < 0 || used != 0) {
        valid = 0;
    }
finish_maps:
    for (size_t index = 0; index < 2; ++index) {
        if (!(mapped & (1U << index))) {
            char record[128];
            int length = snprintf(record, sizeof(record),
                                  "[%d] callee-map pid=%d register=%s image=unknown outcome=unavailable\n",
                                  (int)getpid(), tid, index == 0 ? "pc" : "lr");
            if (length > 0 && (size_t)length < sizeof(record)) {
                callee_record(capture, record, (size_t)length);
            }
        }
    }
    close(fd);
    return valid && matched == 1;
}

static void remote_capture_signal(void *opaque, const struct vbi_remote_result *result) {
    struct remote_context *context = opaque;
    struct callee_capture_context capture = {context->pid};
    const char *reason = "registers-unavailable";
    size_t frames = 0;
    uint64_t sp = 0, fp = 0, start = 0, end = 0;
    if (!g_active_thread_group || g_active_thread_group->execution_tid != context->pid) {
        reason = "ownership-unavailable"; goto finish_capture;
    }
    int owned_stop = 0;
    for (size_t index = 0; index < g_active_thread_group->count; ++index) {
        const struct vbi_tg_task *task = &g_active_thread_group->tasks[index];
        if (task->tid == context->pid && task->attached && task->stopped && !task->gone) {
            owned_stop = 1;
        }
    }
    if (!owned_stop) {
        reason = "ownership-unavailable"; goto finish_capture;
    }
    siginfo_t info = {0};
    int info_ok = ptrace(PTRACE_GETSIGINFO, context->pid, NULL, &info) == 0;
    int info_error = info_ok ? 0 : errno;
    char fault[256];
    int fault_length = vbi_fault_record(fault, sizeof(fault), (int)getpid(), context->pid,
                                        info_ok, info_error, &info);
    if (fault_length > 0) {
        callee_record(&capture, fault, (size_t)fault_length);
    }
    if (!result->registers_read) {
        goto finish_capture;
    }
    if (context->bitness == 64) {
        sp = context->frame.arm64.sp;
        fp = context->frame.arm64.regs[29];
    }
    if (!callee_stack_bounds(g_active_thread_group->tgid, context->pid, sp, &start, &end,
                             result, &capture)) {
        reason = "maps-unavailable"; goto finish_capture;
    }
    if (context->bitness != 64) {
        reason = "unsupported-abi"; goto finish_capture;
    }
    const struct vbi_callee_frame_ops frame_ops = {callee_read_pair, callee_emit};
    struct vbi_callee_frame_result chain = vbi_callee_frames(sp, fp, start, end, &frame_ops, &capture);
    reason = vbi_callee_frame_reason(chain.reason);
    frames = chain.count;
finish_capture:;
    char line[320];
    int length = snprintf(line, sizeof(line),
                          "[%d] callee-chain pid=%d abi=%d signal=%d pc=0x%llx lr=0x%llx sp=0x%llx fp=0x%llx frames=%zu outcome=%s complete-unwind=unverified unmapped-image=unknown\n",
                          (int)getpid(), context->pid, context->bitness,
                          WIFSTOPPED(result->wait_status) ? WSTOPSIG(result->wait_status) : 0,
                          (unsigned long long)result->pc, (unsigned long long)result->lr,
                          (unsigned long long)sp, (unsigned long long)fp, frames, reason);
    if (length > 0 && (size_t)length < sizeof(line)) {
        callee_record(&capture, line, (size_t)length);
    }
}

static const struct vbi_remote_ops remote_ops = {
    remote_set, remote_resume, remote_wait, remote_stop, remote_read,
    remote_restore, remote_retain_signal, remote_gone, remote_capture_signal,
    remote_verify_sigchld, remote_forward_sigchld
};

/* Failure stops the complete injection sequence, including optional loader
 * probes and handoff. The sticky fence is reset only at the next vbi_inject. */
static _Thread_local int g_remote_failed;
static _Thread_local const char *g_remote_phase = "native";
static _Thread_local struct vbi_remote_result g_remote_result;

static struct vbi_remote_result remote_call_layout(
    int pid, int bitness, u64 function, u64 args[], int nargs,
    const uint32_t *stack_words, size_t stack_word_count) {
    struct vbi_remote_result result = {.stage = VBI_CALL_PREPARE};
    struct vbi_remote_origin origin = {0};
    struct remote_context context = {.pid = pid, .bitness = bitness};
    if (g_remote_failed) {
        return result;
    }
    g_remote_restore_diag = (struct vbi_restore_diag){.operation = VBI_RESTORE_UNAVAILABLE,
                                                      .reason = VBI_RESTORE_NO_SNAPSHOT};
    size_t length = bitness == 64 ? sizeof(context.original.arm64)
                                 : sizeof(context.original.arm32);
    struct iovec iov = {&context.original, length};
    if (get_regset_exact(pid, &context.original, length, &iov) < 0) {
        result.error = errno;
        goto finish;
    }
    vbi_remote_capture_origin(&origin, bitness, &context.original, length);
    if (bitness == 64 && !vbi_pstate_admissible(context.original.arm64.pstate)) {
        result.error = EAGAIN;
        goto finish;
    }
    if (save_extended_state(pid, bitness) < 0) {
        result.error = errno;
        goto finish;
    }
    memcpy(&context.frame, &context.original, sizeof(context.frame));
    if (bitness == 64) {
        for (int i = 0; i < nargs && i < 8; ++i) {
            context.frame.arm64.regs[i] = args[i];
        }
        context.frame.arm64.regs[30] = 0;
        context.frame.arm64.sp = (context.frame.arm64.sp & ~UINT64_C(15)) - 256;
        context.frame.arm64.pc = function;
    } else {
        for (int i = 0; i < nargs && i < 4; ++i) {
            context.frame.arm32.uregs[i] = (uint32_t)args[i];
        }
        context.frame.arm32.uregs[14] = 0;
        context.frame.arm32.uregs[13] = (context.frame.arm32.uregs[13] & ~7U) - 256;
        context.frame.arm32.uregs[15] = (uint32_t)function & ~1U;
        if (function & 1) {
            context.frame.arm32.uregs[16] |= 0x20U;
        } else {
            context.frame.arm32.uregs[16] &= ~0x20U;
        }
        if (stack_word_count > sizeof(context.saved_stack) / sizeof(uint32_t)
            || (stack_word_count && !stack_words)) {
            result.error = EINVAL;
            goto finish;
        }
        context.stack_address = context.frame.arm32.uregs[13];
        context.stack_bytes = stack_word_count * sizeof(uint32_t);
        if (context.stack_bytes) {
            if (target_read_mem(pid, context.stack_address, context.saved_stack,
                                context.stack_bytes) < 0) {
                result.error = errno;
                goto finish;
            }
            context.stack_saved = 1;
        }
    }
    sigset_t signal_mask;
    if (block_term_signals(&signal_mask) < 0) {
        result.error = errno;
        goto finish;
    }
    if (context.stack_saved
        && target_write_mem(pid, context.stack_address, stack_words,
                            context.stack_bytes) < 0) {
        result.error = errno;
        result.restore_attempted = 1;
        result.restored = remote_restore(&context) == 0;
    } else {
        result = vbi_remote_execute(&remote_ops, &context, bitness == 64);
    }
    restore_term_signals(&signal_mask);
finish:
    result.origin = origin;
    g_remote_result = result;
    if (result.restore_attempted) {
        DBG("restore-check pid=%d abi=%d part=%s operation=%s reason=%s errno-valid=%d errno=%d expected=%zu returned=%zu mismatch-count=%zu first-mismatch=%zu pstate-valid=%d expected=0x%llx observed=0x%llx changed=0x%llx",
            pid, bitness, vbi_restore_part_name(g_remote_restore_diag.part),
            vbi_restore_operation_name(g_remote_restore_diag.operation),
            vbi_restore_reason_name(g_remote_restore_diag.reason),
            g_remote_restore_diag.errno_valid, g_remote_restore_diag.error,
            g_remote_restore_diag.expected_length, g_remote_restore_diag.returned_length,
            g_remote_restore_diag.mismatch_count, g_remote_restore_diag.first_mismatch,
            g_remote_restore_diag.pstate_valid,
            (unsigned long long)g_remote_restore_diag.pstate_expected,
            (unsigned long long)g_remote_restore_diag.pstate_observed,
            (unsigned long long)g_remote_restore_diag.pstate_changed);
    }
    DBG("remote-origin phase=%s pid=%d abi=%d function=0x%llx valid=%d original-pc=0x%llx original-lr=0x%llx",
        g_remote_phase, pid, bitness, (unsigned long long)function, origin.valid,
        (unsigned long long)origin.pc, (unsigned long long)origin.lr);
    DBG("remote-call %s pid=%d abi=%d function=0x%llx stage=%s status=0x%x signal=%d callee-pc=0x%llx callee-lr=0x%llx errno=%d executed=%d registers-read=%d restore-attempted=%d restored=%d managed-unwind=%s",
        result.ok ? "debug" : "failure", pid, bitness, (unsigned long long)function,
        vbi_remote_stage_name(result.stage), result.wait_status,
        WIFSTOPPED(result.wait_status) ? WSTOPSIG(result.wait_status) : 0,
        (unsigned long long)result.pc, (unsigned long long)result.lr,
        result.error, result.executed, result.registers_read,
        result.restore_attempted, result.restored,
        result.executed && !result.ok ? "unverified" : "returned-or-not-executed");
    if (!result.ok) {
        vbi_native_diagnostic("error", "injector", "stage=remote-call-%s target_pid=%d abi=%d errno=%d restored=%d",
                vbi_remote_stage_name(result.stage), pid, bitness, result.error,
                result.restored);
    }
    return result;
}

static int loader_call_unresolved(int ret) {
    return ret == -3 && g_remote_failed && g_remote_result.executed
           && g_remote_result.stage == VBI_CALL_TIMEOUT
           && strcmp(g_remote_phase, "native") == 0;
}

struct remote_request {
    int pid;
    int bitness;
    u64 function;
    u64 *args;
    int nargs;
    const uint32_t *stack_words;
    size_t stack_word_count;
};

static struct vbi_remote_result remote_dispatch(void *opaque) {
    struct remote_request *request = opaque;
    return remote_call_layout(request->pid, request->bitness, request->function,
                              request->args, request->nargs, request->stack_words,
                              request->stack_word_count);
}

static int remote_call(int pid, int bitness, u64 function, u64 args[], int nargs,
                       u64 *value) {
    struct remote_request request = {pid, bitness, function, args, nargs, NULL, 0};
    uint64_t result = 0;
    if (!vbi_remote_checked(&g_remote_failed, remote_dispatch, &request, &result)) {
        return 0;
    }
    *value = result;
    return 1;
}

static void copy_phase_error(char *output, size_t output_size,
                             const char *phase) {
    if (!output || output_size == 0 || !phase) {
        return;
    }
    size_t limit = output_size - 1;
    size_t length = strlen(phase);
    if (length > limit) {
        length = limit;
    }
    memcpy(output, phase, length);
    output[length] = '\0';
}

static int resolve_loader_api(int pid, int bitness,
                              struct vbi_loader_api *api) {
    if (!api) {
        return 0;
    }
    api->create_namespace = resolve_loader_symbol(
        pid, bitness, "__loader_android_create_namespace");
    api->link_namespaces = resolve_loader_symbol(
        pid, bitness, "__loader_android_link_namespaces");
    api->get_exported_namespace = resolve_loader_symbol(
        pid, bitness, "__loader_android_get_exported_namespace");
    api->dlopen_ext = resolve_loader_symbol(
        pid, bitness, "__loader_android_dlopen_ext");
    api->dlopen = resolve_loader_symbol(
        pid, bitness, "__loader_dlopen");
    api->dlsym = resolve_loader_symbol(pid, bitness, "__loader_dlsym");
    api->dlerror = resolve_loader_symbol(pid, bitness, "__loader_dlerror");
    DBG("loader api create=0x%llx link=0x%llx exported=0x%llx ext=0x%llx dlopen=0x%llx dlsym=0x%llx error=0x%llx",
        (unsigned long long)api->create_namespace,
        (unsigned long long)api->link_namespaces,
        (unsigned long long)api->get_exported_namespace,
        (unsigned long long)api->dlopen_ext,
        (unsigned long long)api->dlopen,
        (unsigned long long)api->dlsym,
        (unsigned long long)api->dlerror);
    return api->create_namespace != 0 && api->link_namespaces != 0
           && api->dlopen_ext != 0 && api->dlsym != 0 && api->dlerror != 0;
}

static void copy_remote_dlerror(int pid, int bitness, u64 dlerror_addr,
                                char *output, size_t output_size) {
    if (!dlerror_addr) {
        return;
    }
    u64 error_ptr = 0;
    if (!remote_call(pid, bitness, dlerror_addr, NULL, 0, &error_ptr)) {
        return;
    }
    if (!error_ptr) {
        return;
    }
    char error_buffer[256] = {0};
    if (target_read_mem(pid, error_ptr, error_buffer,
                        sizeof(error_buffer) - 1) == 0) {
        if (output && output_size > 0) {
            size_t copy = strnlen(error_buffer, output_size - 1);
            memcpy(output, error_buffer, copy);
            output[copy] = '\0';
        }
        DBG("remote linker error: %s", error_buffer);
    }
}

static void copy_loader_failure(int pid, int bitness, u64 dlerror_addr,
                                const char *phase, char *output,
                                size_t output_size) {
    char linker_error[256] = {0};
    copy_remote_dlerror(pid, bitness, dlerror_addr, linker_error,
                        sizeof(linker_error));
    if (!output || output_size == 0 || !phase) {
        return;
    }
    if (linker_error[0] != '\0') {
        int written = snprintf(output, output_size, "%s: %s", phase,
                               linker_error);
        if (written < 0 || (size_t)written >= output_size) {
            output[output_size - 1] = '\0';
        }
    } else {
        copy_phase_error(output, output_size, phase);
    }
}

static u64 remote_loader_namespace_create(
    int pid, int bitness, const struct vbi_loader_api *api,
    u64 name, u64 default_path, u64 permitted_path, u64 caller) {
    if (bitness == 64) {
        u64 args[7] = {name, 0, default_path,
                       VBI_ANDROID_NAMESPACE_TYPE_ISOLATED,
                       permitted_path, 0, caller};
        u64 value = 0;
        return remote_call(pid, 64, api->create_namespace, args, 7, &value) ? value : 0;
    }

    uint32_t words[8] = {
        (uint32_t)name, 0, (uint32_t)default_path,
        (uint32_t)VBI_ANDROID_NAMESPACE_TYPE_ISOLATED, 0,
        (uint32_t)permitted_path, 0, (uint32_t)caller
    };
    struct vbi_namespace32_call_layout layout;
    if (name > UINT32_MAX || default_path > UINT32_MAX
        || permitted_path > UINT32_MAX || caller > UINT32_MAX
        || !vbi_build_namespace32_create_layout(words, &layout)) {
        return 0;
    }
    u64 register_args[4] = {layout.register_words[0],
                            layout.register_words[1],
                            layout.register_words[2],
                            layout.register_words[3]};
    struct remote_request request = {pid, 32, api->create_namespace, register_args, 4,
                                     layout.stack_words, layout.stack_word_count};
    uint64_t value = 0;
    return vbi_remote_checked(&g_remote_failed, remote_dispatch, &request, &value)
           ? value : 0;
}

u64 remote_namespace_load(int pid, int bitness,
                          const struct vbi_loader_api *api,
                          const struct vbi_scratch_layout *scratch,
                          u64 caller, const char *so_path,
                          char *dlerr_out, size_t dlerr_out_sz) {
    static const char namespace_name[] = "voboost";
    static const char library_path[] = "/data/voboost";
    static const char shared_sonames[] =
        "libc.so:libdl.so:libm.so:liblog.so:libz.so";
    static const char default_name[] = "default";
    if (!api || !scratch || !so_path || !caller) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-api-unavailable");
        return 0;
    }
    /* Fail-closed with the same convention as every other error branch:
     * the caller rejects !handle, so -1 (which would coerce to UINT64_MAX
     * in this u64 return type and read as a valid handle) must never reach
     * the __loader_dlsym call. */
    if (!api->get_exported_namespace) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-export-unavailable");
        return 0;
    }

    u64 name_addr = scratch->auxiliary;
    u64 default_path_addr = name_addr + 128;
    u64 permitted_path_addr = name_addr + 256;
    u64 sonames_addr = name_addr + 384;
    u64 extinfo_addr = name_addr + 1024;
    size_t extinfo_size = bitness == 64 ? 48 : 36;
    uint64_t end = 0;
    if (name_addr > UINT64_MAX - 2048
        || scratch->size > UINT64_MAX - scratch->start
        || __builtin_add_overflow(extinfo_addr, extinfo_size, &end)
        || end > scratch->start + scratch->size) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-scratch-invalid");
        return 0;
    }
    if (target_write_mem(pid, name_addr, namespace_name,
                         sizeof(namespace_name)) < 0
        || target_write_mem(pid, default_path_addr, library_path,
                            sizeof(library_path)) < 0
        || target_write_mem(pid, permitted_path_addr, library_path,
                            sizeof(library_path)) < 0
        || target_write_mem(pid, sonames_addr, shared_sonames,
                            sizeof(shared_sonames)) < 0) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-path-write-failed");
        return 0;
    }

    /* Every linker API may acquire a process-wide lock. Never enter while
     * a peer that could own that lock is still frozen by this helper. */
    if (!vbi_thread_group_loader_ready(g_active_thread_group)) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "loader-peers-not-released");
        return 0;
    }

    /* Obtain the exported default namespace for diagnostic dlopen. */
    u64 default_namespace = 0;
    if (api->get_exported_namespace) {
        if (target_write_mem(pid, extinfo_addr - 64, default_name,
                             sizeof(default_name)) == 0) {
            u64 default_args[1] = {extinfo_addr - 64};
            if (!remote_call(pid, bitness, api->get_exported_namespace, default_args, 1, &default_namespace)) {
                return 0;
            }
            DBG("explicit default namespace probe -> 0x%llx",
                (unsigned long long)default_namespace);
        }
    }

    /* Diagnostic: try __loader_dlopen (uses caller's namespace, no extinfo).
     * The caller is in APEX libc which belongs to the DEFAULT namespace that
     * permits /data. This bypasses explicit namespace selection entirely. */
    if (api->dlopen) {
        /* First, test with RTLD_NOLOAD on a known system library to verify
         * the remote call mechanism works and the caller's namespace resolves. */
        static const char test_lib[] = "/system/lib64/libc.so";
        u64 test_name_addr = scratch->auxiliary + 2048;
        if (target_write_mem(pid, test_name_addr, test_lib,
                             sizeof(test_lib)) == 0) {
            u64 test_args[3] = {test_name_addr, 4, caller};
            u64 test_handle = 0;
            if (!remote_call(pid, bitness, api->dlopen, test_args, 3, &test_handle)) {
                return 0;
            }
            DBG("diagnostic __loader_dlopen(RTLD_NOLOAD, libc.so) handle=0x%llx",
                (unsigned long long)test_handle);
            if (!test_handle) {
                copy_loader_failure(pid, bitness, api->dlerror,
                                    "dlopen-noload-failed", dlerr_out,
                                    dlerr_out_sz);
            }
        }

        u64 dlopen_args[3] = {scratch->path, 2, caller};
        DBG("diagnostic __loader_dlopen path=0x%llx caller=0x%llx",
            (unsigned long long)dlopen_args[0], (unsigned long long)dlopen_args[2]);
        u64 dlopen_handle = 0;
        if (!remote_call(pid, bitness, api->dlopen, dlopen_args, 3, &dlopen_handle)) {
            return 0;
        }
        if (dlopen_handle) {
            DBG("__loader_dlopen succeeded handle=0x%llx",
                (unsigned long long)dlopen_handle);
            return dlopen_handle;
        }
        DBG("__loader_dlopen failed, trying namespace path");
        copy_loader_failure(pid, bitness, api->dlerror,
                            "dlopen-failed", dlerr_out, dlerr_out_sz);
    }

    /* Diagnostic: try loading in the default namespace first. */
    if (default_namespace) {
        uint8_t default_extinfo[48];
        size_t default_extinfo_size = bitness == 64 ? 48 : 36;
        if (vbi_build_dlextinfo(bitness, default_namespace, default_extinfo,
                                sizeof(default_extinfo))
            && target_write_mem(pid, extinfo_addr, default_extinfo,
                                default_extinfo_size) == 0) {
            u64 default_load_args[4] = {scratch->path, 2, extinfo_addr, caller};
            DBG("diagnostic default-namespace dlopen_ext path=0x%llx",
                (unsigned long long)default_load_args[0]);
            u64 default_handle = 0;
            if (!remote_call(pid, bitness, api->dlopen_ext, default_load_args, 4, &default_handle)) {
                return 0;
            }
            if (default_handle) {
                DBG("default-namespace dlopen_ext succeeded handle=0x%llx",
                    (unsigned long long)default_handle);
                return default_handle;
            }
            DBG("default-namespace dlopen_ext failed, trying isolated namespace");
            copy_loader_failure(pid, bitness, api->dlerror,
                                "default-load-failed", dlerr_out, dlerr_out_sz);
        }
    }

    u64 namespace_handle = remote_loader_namespace_create(
        pid, bitness, api, name_addr, default_path_addr, permitted_path_addr,
        caller);
    if (!namespace_handle) {
        copy_loader_failure(pid, bitness, api->dlerror,
                            "namespace-create-failed", dlerr_out,
                            dlerr_out_sz);
        return 0;
    }
    DBG("created namespace handle=0x%llx", (unsigned long long)namespace_handle);

    u64 link_args[3] = {namespace_handle, 0, sonames_addr};
    u64 linked = 0;
    if (!remote_call(pid, bitness, api->link_namespaces, link_args, 3, &linked)) {
        return 0;
    }
    if (!linked) {
        copy_loader_failure(pid, bitness, api->dlerror,
                            "namespace-link-failed", dlerr_out,
                            dlerr_out_sz);
        return 0;
    }

    char path_probe[256] = {0};
    if (target_read_mem(pid, scratch->path, path_probe,
                        sizeof(path_probe) - 1) < 0
        || strnlen(path_probe, sizeof(path_probe) - 1) != strlen(so_path)
        || memcmp(path_probe, so_path, strlen(so_path)) != 0) {
        copy_phase_error(dlerr_out, dlerr_out_sz,
                         "payload-path-corrupted-before-load");
        DBG("payload path changed before dlopen_ext: addr=0x%llx value=%s",
            (unsigned long long)scratch->path, path_probe);
        return 0;
    }
    DBG("payload path before dlopen_ext: addr=0x%llx value=%s",
        (unsigned long long)scratch->path, path_probe);

    uint8_t extinfo[48];
    if (!vbi_build_dlextinfo(bitness, namespace_handle, extinfo,
                             sizeof(extinfo))
        || target_write_mem(pid, extinfo_addr, extinfo, extinfo_size) < 0) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-extinfo-failed");
        return 0;
    }
    u64 load_args[4] = {scratch->path, 2, extinfo_addr, caller};
    DBG("calling android_dlopen_ext path=0x%llx flags=0x%llx extinfo=0x%llx caller=0x%llx",
        (unsigned long long)load_args[0], (unsigned long long)load_args[1],
        (unsigned long long)load_args[2], (unsigned long long)load_args[3]);
    u64 handle = 0;
    if (!remote_call(pid, bitness, api->dlopen_ext, load_args, 4, &handle)) {
        return 0;
    }
    if (!handle) {
        copy_loader_failure(pid, bitness, api->dlerror,
                            "payload-load-failed", dlerr_out, dlerr_out_sz);
        return 0;
    }
    DBG("namespace dlopen_ext returned handle=0x%llx",
        (unsigned long long)handle);
    return handle;
}

/* ---- failed-init log pipe adoption ---- */

static int remote_exported_fd(int pid, int bitness, u64 handle, u64 dlsym_addr,
                              u64 caller_addr, u64 str_addr, const char *symbol) {
    size_t length = strlen(symbol) + 1;
    if (target_write_mem(pid, str_addr, symbol, length) < 0) {
        return -1;
    }
    u64 args[3] = { handle, str_addr, caller_addr };
    u64 function = 0;
    if (!remote_call(pid, bitness, dlsym_addr, args, 3, &function)) {
        return -1;
    }
    if (function == 0) {
        return -1;
    }
    u64 raw = 0;
    if (!remote_call(pid, bitness, function, NULL, 0, &raw)) {
        return -1;
    }
    int fd = (int)(uint32_t)raw;
    return (raw != 0 && fd > 0) ? fd : -1;
}

/*
 * adopt_failed_log_pipe — duplicate the failed implant's log-pipe read-end
 * into this process so the daemon can drain the init diagnostics.
 *
 * After IMPLANT_INIT_FAILED the sentinel return value carries no fd number,
 * yet the implant keeps its pipe open with the diagnostics already written.
 * This fetches the target-local read-end via the exported getter, duplicates
 * it through /proc, and adopts it via implant_finish_log_handoff(1) (the
 * implant closes its read copy; the write end stays open so the daemon sees
 * EOF when the target dies).
 *
 * Returns the daemon-owned O_NONBLOCK fd, or -1 when any step fails (the
 * pipe then simply stays unadopted until the target process dies).
 */
static int adopt_failed_log_pipe(int pid, int bitness, u64 handle, u64 dlsym_addr,
                                 u64 caller_addr, u64 str_addr) {
    const char *fd_sym = "implant_log_read_fd";
    size_t fd_len = strlen(fd_sym) + 1;
    /* str_addr is the caller-passed safe-zone base (cfg_addr from the inject
     * path); place the fd symbol below it in the same safe zone. */
    u64 fd_str_addr = str_addr - fd_len - 4096;
    if (target_write_mem(pid, fd_str_addr, fd_sym, fd_len) < 0) {
        return -1;
    }

    u64 sym_args[3] = { handle, fd_str_addr, caller_addr };
    u64 fd_fn = 0;
    if (!remote_call(pid, bitness, dlsym_addr, sym_args, 3, &fd_fn)) {
        return -1;
    }
    if (fd_fn == 0) {
        return -1;
    }

    u64 fd_raw = 0;
    if (!remote_call(pid, bitness, fd_fn, NULL, 0, &fd_raw)) {
        return -1;
    }
    int target_fd = (int)(uint32_t)fd_raw;
    /* The transport succeeded; descriptor zero is still not a log pipe. */
    if (fd_raw == 0 || target_fd <= 0) {
        return -1;
    }

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, target_fd);
    int daemon_fd = open(fd_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (daemon_fd < 0) {
        return -1;
    }

    /* accepted=1: implant closes its read copy only. */
    const char *finish_sym = "implant_finish_log_handoff";
    size_t finish_len = strlen(finish_sym) + 1;
    u64 finish_str_addr = fd_str_addr - finish_len - 16;
    if (target_write_mem(pid, finish_str_addr, finish_sym, finish_len) < 0) {
        close(daemon_fd);
        return -1;
    }
    u64 fsym_args[3] = { handle, finish_str_addr, caller_addr };
    u64 finish_fn = 0;
    if (!remote_call(pid, bitness, dlsym_addr, fsym_args, 3, &finish_fn)) {
        close(daemon_fd);
        return -1;
    }
    if (finish_fn == 0) {
        close(daemon_fd);
        return -1;
    }
    u64 acc_args[1] = { 1U }; /* bit 0: record read end adopted */
    u64 handoff_ack = 0;
    if (!remote_call(pid, bitness, finish_fn, acc_args, 1, &handoff_ack)) {
        close(daemon_fd);
        return -1;
    }
    if (handoff_ack != VBI_HANDOFF_ACK) {
        close(daemon_fd);
        return -1;
    }

    return daemon_fd;
}


/* Re-read /proc/<pid>/cmdline argv[0] after the complete target thread group
 * is stopped and compare it with the daemon's exact selection. This is a
 * PID-reuse consistency check, not standalone target authority. Returns 1 on
 * match, 0 on mismatch, -1 on read failure (treated as target-gone). */
static int verify_target_identity(int pid, const char *expect_argv0) {
    if (!expect_argv0 || !*expect_argv0) {
        return 0;
    }
    enum { MAX_EXPECTED_ARGV0_BYTES = 255 };
    size_t expected_len = strnlen(expect_argv0, MAX_EXPECTED_ARGV0_BYTES + 1);
    if (expected_len == 0 || expected_len > MAX_EXPECTED_ARGV0_BYTES) {
        return 0;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    char buf[MAX_EXPECTED_ARGV0_BYTES + 1];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) {
        return -1;
    }
    const char *terminator = (const char *)memchr(buf, '\0', (size_t)n);
    if (!terminator) {
        return 0;
    }
    size_t actual_len = (size_t)(terminator - buf);
    if (actual_len == expected_len
        && memcmp(buf, expect_argv0, expected_len) == 0) {
        return 1;
    }
    DBG("identity mismatch: argv0 bytes differ from expected process");
    return 0;
}


/* ---- main injection entry ---- */

static int begin_injection(void *context) {
    g_remote_failed = 0;
    g_remote_phase = "native";
    return block_term_signals((sigset_t *)context) == 0 ? 1 : -1;
}


/*
 * vbi_inject — inject a .so into a target process via ptrace.
 *
 * NOTE on the EGL/driver-init race (live ANR 2026-09-18, vehiclesetting):
 * hijacking a thread of an app whose RenderThread is mid-EGL-init while a
 * second thread holds the dynamic-linker lock can serialize the remote
 * dlopen behind the linker lock and contribute to an EGL/linker deadlock
 * (main thread waiting on RenderThread, RenderThread in egl_init_drivers,
 * third thread in dlopen of the vendor EGL driver). Detecting "target is
 * inside GPU driver init" from the tracer would require walking every
 * stopped thread's stack/PC for vendor-driver address ranges before the
 * first remote call and re-deciding the hijack thread — a larger redesign of
 * the thread-group attach (per-thread PC gating, retry-with-backoff at the
 * thread-selection layer). Deferred deliberately; the bounded-cleanup fixes
 * above ensure the failure mode is a failed inject (daemon retries with its
 * existing backoff) instead of a frozen target. The daemon's retry loop and
 * circuit breaker already bound repeated attempts.
 *
 * Returns 0 on success, negative on error (see injector.h).
 */
int vbi_inject(int pid, const char *so_path, const char *init_sym,
               const char *config_path, const char *expect_argv0, uint64_t expect_starttime,
               uint32_t expect_uid, const char *expect_selinux_context,
               struct vbi_agent_pipe_fds *pipe_fds,
               char *dlerr_out, size_t dlerr_out_sz) {
    uint64_t started_ms = vbi_diagnostic_millis();
    TIMING("begin");
    g_tracee_detach_safe = 1;
    g_tracee_gone = 0;
    g_thread_group_cleanup_safe = 1;
    g_active_thread_group = NULL;
    DBG("vbi_inject pid=%d so_path=%s init_sym=%s config_path=%s",
        pid, so_path, init_sym, config_path ? config_path : "(null)");
    if (pipe_fds) {
        pipe_fds->record_read_fd = -1;
        pipe_fds->state_reply_fd = -1;
    }
    if (dlerr_out && dlerr_out_sz > 0) {
        dlerr_out[0] = '\0';
    }
    if (!so_path || pid <= 0) {
        DBG("invalid args");
        TIMED_RETURN(-1);
    }

    unsigned loader_retries = 0;
acquire_group:;
    if (dlerr_out && dlerr_out_sz > 0) {
        dlerr_out[0] = '\0';
    }
    sigset_t injection_sigold;
    if (begin_injection(&injection_sigold) < 0) {
        TIMED_RETURN(-8);
    }

    /* Stop a stable inventory of the complete thread group. The caller may
     * pass a non-leader TID; the group helper resolves TGID and binds the
     * leader starttime before and after every task reaches a ptrace-stop. */
    struct vbi_thread_group thread_group;
    TIMING("attach.begin");
    int group_result = vbi_thread_group_attach(pid, &thread_group);
    TIMING("attach.end");
    if (group_result != VBI_TG_OK) {
        restore_term_signals(&injection_sigold);
        TIMED_RETURN(group_result);
    }
    pid = thread_group.execution_tid;
    g_active_thread_group = &thread_group;

    int ret = -1;
    int retry_loader = 0;
    DBG("attached thread group tgid=%d execution_tid=%d count=%zu",
        thread_group.tgid, pid, thread_group.count);

    if (expect_starttime == 0 || thread_group.starttime != expect_starttime) {
        ret = -7;
        goto detach;
    }
    int expected_identity = vbi_thread_group_verify_expected_identity(
        &thread_group, expect_uid, expect_selinux_context);
    if (expected_identity != VBI_TG_OK) {
        ret = expected_identity == VBI_TG_GONE ? -2 : -7;
        goto detach;
    }

    /* 1b. PID-reuse consistency check. The catalog declares the exact process
     * name; the fixed UID/domain profile and unchanged starttime complete the
     * process-security boundary. argv[0] alone is not authority. */
    {
        int ident = verify_target_identity(thread_group.tgid, expect_argv0);
        if (ident < 0) {
            ret = -2; /* target gone */
            goto detach;
        }
        if (ident == 0) {
            ret = -7; /* identity mismatch: wrong or spoofed process */
            goto detach;
        }
    }

    /* 2. Detect target bitness at runtime. */
    int bitness = detect_bitness(pid);
    DBG("detected bitness=%d", bitness);
    if (bitness != 32 && bitness != 64) {
        DBG("bitness detection failed");
        ret = -5; /* bitness detection failed */
        goto detach;
    }
    if (!verify_target_executable(pid, bitness)) {
        ret = -7;
        goto detach;
    }

    u64 stack_pointer = 0, original_pc = 0, original_lr = 0;
    if (bitness == 64) {
        struct vbi_arm64_regs regs = {0};
        struct iovec iov = { &regs, sizeof(regs) };
        if (get_regset_exact(pid, &regs, sizeof(regs), &iov) < 0) {
            DBG("GETREGSET for scratch failed: %s", strerror(errno));
            ret = -5; /* cannot read target regs */
            goto detach;
        }
        /* Check before any target memory/register write. A fresh full-group
         * acquisition lets the target reach a natural BTYPE-free stop. */
        if (!vbi_pstate_admissible(regs.pstate)) {
            retry_loader = 1;
            copy_phase_error(dlerr_out, dlerr_out_sz, "register-baseline-deferred");
            DBG("register baseline deferred pid=%d pstate=0x%llx retry=%u",
                pid, (unsigned long long)regs.pstate, loader_retries);
            ret = -11;
            goto detach;
        }
        stack_pointer = regs.sp & ~0xFULL;
        original_pc = regs.pc;
        original_lr = regs.regs[30];
    } else {
        struct vbi_arm32_regs regs;
        memset(&regs, 0, sizeof(regs));
        struct iovec iov = { &regs, sizeof(regs) };
        int gr = get_regset_exact(pid, &regs, sizeof(regs), &iov);
        if (gr < 0) {
            DBG("32-bit GETREGSET for scratch failed: %s", strerror(errno));
            ret = -5; /* cannot read target regs */
            goto detach;
        }
        DBG("32-bit GETREGSET rc=%d iov_len=%zu (sizeof user_regs_32=%zu)",
            gr, iov.iov_len, sizeof(regs));
        DBG("32-bit raw uregs[13](sp)=0x%x uregs[14](lr)=0x%x uregs[15](pc)=0x%x",
            regs.uregs[13], regs.uregs[14], regs.uregs[15]);
        /* uregs is now uint32_t[18] (matches the kernel's 72-byte regset), so
         * SP is a clean 32-bit value. Align to 8 (ARM EABI). */
        stack_pointer = regs.uregs[13] & ~(u64)0x7;
        original_pc = regs.uregs[15];
        original_lr = regs.uregs[14];
    }
    TIMING("maps.begin");
    int busy = loader_entry_busy(pid, bitness, original_pc, original_lr);
    TIMING("maps.end");
    if (busy != 0) {
        retry_loader = busy > 0;
        copy_phase_error(dlerr_out, dlerr_out_sz,
                         busy > 0 ? "loader-entry-busy" : "loader-context-unavailable");
        DBG("loader entry blocked pid=%d abi=%d pc=0x%llx lr=0x%llx busy=%d retry=%u",
            pid, bitness, (unsigned long long)original_pc,
            (unsigned long long)original_lr, busy, loader_retries);
        ret = -3;
        goto detach;
    }

    /* Loader/JNI allocation must not reenter an interrupted allocator or
     * mutex operation on this borrowed thread. Reacquire before any target
     * scratch/register write; an unavailable exact ELF is also deferred. */
    int libc_busy = vbi_target_libc_entry_busy(pid, bitness, original_pc, original_lr);
    if (libc_busy != 0) {
        retry_loader = 1;
        copy_phase_error(dlerr_out, dlerr_out_sz,
                         libc_busy > 0 ? "libc-entry-busy" : "libc-context-unavailable");
        DBG("libc entry deferred pid=%d abi=%d pc=0x%llx lr=0x%llx busy=%d retry=%u",
            pid, bitness, (unsigned long long)original_pc,
            (unsigned long long)original_lr, libc_busy, loader_retries);
        ret = -11;
        goto detach;
    }

    /* 3. Resolve every private linker entry point before the first namespace
     * mutation. A missing capability is distinct from payload/path failure. */
    TIMING("resolve.begin");
    struct vbi_loader_api loader_api;
    if (!resolve_loader_api(pid, bitness, &loader_api)) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "namespace-api-unavailable");
        DBG("required namespace linker API is unavailable");
        ret = -3;
        goto detach;
    }

    /* 4. Find caller_addr inside app_process (for namespace resolution). */
    u64 caller_addr = find_target_caller_addr(pid);
    TIMING("resolve.end");
    TIMING("stage.begin");
    DBG("caller_addr @ 0x%llx", (unsigned long long)caller_addr);
    if (!caller_addr) {
        copy_phase_error(dlerr_out, dlerr_out_sz, "target-caller-unresolved");
        ret = -3;
        goto detach;
    }

    /* 5. Write the .so path string ~8KB below SP (safe from call frame). */
    u64 str_addr = 0;
    size_t path_len = strlen(so_path) + 1;

    const char *cfg_src = config_path ? config_path : "";
    size_t cfg_len = strlen(cfg_src) + 1;
    size_t sym_len = init_sym ? strlen(init_sym) + 1 : 1;
    struct vbi_scratch_layout scratch;
    if (!vbi_build_scratch_layout(stack_pointer, path_len, cfg_len,
                                  sym_len, &scratch)
        || !scratch_is_in_exact_thread_stack(pid, stack_pointer,
                                             scratch.start, scratch.size)) {
        DBG("scratch layout is not inside exact writable thread stack");
        ret = -5;
        goto detach;
    }
    str_addr = scratch.path;
    DBG("path string @ 0x%llx (sp-based), len=%zu", (unsigned long long)str_addr, path_len);

    if (target_write_mem(pid, str_addr, so_path, path_len) < 0) {
        DBG("target_write_mem for path FAILED: %s", strerror(errno));
        ret = -3;
        goto detach;
    }
    if (target_verify_mem(pid, str_addr, so_path, path_len) < 0) {
        DBG("payload path bytes failed target read-back verification");
        copy_phase_error(dlerr_out, dlerr_out_sz,
                         "payload-path-marshal-failed");
        ret = -3;
        goto detach;
    }
    DBG("path string written ok");

    /* 5b. Write the config-path string well BELOW str_addr (toward lower
     * addresses, further from SP along the down-growing stack). The deep
     * ART/JNI call frames that run between dlopen and init_sym (dlopen libart,
     * JNI_GetCreatedJavaVMs, AttachCurrentThread, init_lsplant) grow the stack
     * down past str_addr-4096 — observed on-device as cfg at str_addr-4096
     * trampled to "" while the .so path at str_addr survives. A 16 KiB margin
     * keeps cfg clear of that growth. Passed as the sole argument to init_sym
     * (e.g. implant_init(const char *cfg, int log_fd)) — daemon↔agent config
     * delivery
     * (injector-remote-execution spec). NULL config_path writes an empty string so the
     * target sees cfg="" rather than a stale/garbage pointer. */
    u64 cfg_addr = scratch.config;
    if (target_write_mem(pid, cfg_addr, cfg_src, cfg_len) < 0) {
        DBG("target_write_mem for config_path FAILED: %s", strerror(errno));
        ret = -3;
        goto detach;
    }
    DBG("config path string @ 0x%llx, len=%zu", (unsigned long long)cfg_addr, cfg_len);

    /* Linker operations and constructors can wait on locks held by peers.
     * Release them before the first loader API, retaining the borrowed TID.
     * Scratch is on that stopped TID own stack; final cleanup retains its
     * register/stack/TLS ownership after peers start running. */
    {
        if (!g_tracee_detach_safe || !g_thread_group_cleanup_safe) {
            ret = -8;
            goto detach;
        }
        int managed = vbi_thread_group_enter_managed(&thread_group);
        DBG("loader-call boundary pid=%d result=%d execution-only=%d",
            pid, managed, thread_group.managed);
        if (managed != VBI_TG_OK) {
            if (managed == VBI_TG_UNSAFE_CLEANUP) {
                g_thread_group_cleanup_safe = 0;
            }
            ret = managed;
            copy_phase_error(dlerr_out, dlerr_out_sz, "loader-peer-release-failed");
            goto detach;
        }
        int authority = vbi_thread_group_verify_expected_identity(
            &thread_group, expect_uid, expect_selinux_context);
        int argv_identity = verify_target_identity(thread_group.tgid, expect_argv0);
        if (authority != VBI_TG_OK || argv_identity != 1
            || !verify_target_executable(pid, bitness)) {
            ret = authority == VBI_TG_GONE || argv_identity < 0 ? -2 : -7;
            copy_phase_error(dlerr_out, dlerr_out_sz, "loader-target-identity-changed");
            goto detach;
        }
    }

    /* 6. Create one bounded namespace and load the verified payload through
     * the target linker. The returned handle is target-local and is never
     * persisted across PID/starttime changes. */
    TIMING("stage.end");
    TIMING("loader.begin");
    u64 handle = remote_namespace_load(pid, bitness, &loader_api, &scratch,
                                       caller_addr, so_path,
                                       dlerr_out, dlerr_out_sz);
    if (!handle) {
        DBG("namespace payload load failed: %s",
            dlerr_out && dlerr_out_sz > 0 ? dlerr_out : "(phase unavailable)");
        ret = -3;
        goto detach;
    }
    TIMING("loader.end");
    DBG("namespace payload loaded, handle=0x%llx", (unsigned long long)handle);

    /* 7. Explicit remote-call to init_sym. The linker already ran native
    * constructors; this is the daemon-controlled Java/bootstrap seam. */
    if (init_sym) {
        u64 dlsym_addr = loader_api.dlsym;
        DBG("__loader_dlsym @ 0x%llx", (unsigned long long)dlsym_addr);
        if (dlsym_addr) {
            /* Write the symbol name string into target memory. Place it BELOW
             * cfg_addr in the same safe zone (str_addr - 16384 and lower) so
             * deep ART/JNI call frames growing down from SP cannot trample it
             */
            u64 sym_str_addr = scratch.symbol;
            DBG("sym '%s' @ 0x%llx, len=%zu", init_sym, (unsigned long long)sym_str_addr, sym_len);
            if (target_write_mem(pid, sym_str_addr, init_sym, sym_len) < 0) {
                DBG("target_write_mem for sym FAILED");
                ret = -4;
                goto detach;
            }

            /* dlsym(handle, init_sym, caller_addr) */
            u64 sym_args[3] = { handle, sym_str_addr, caller_addr };
            u64 init_addr;
            if (!remote_call(pid, bitness, dlsym_addr, sym_args, 3, &init_addr)) {
                ret = -4;
                goto detach;
            }
            DBG("dlsym(handle, %s) -> init_addr=0x%llx", init_sym, (unsigned long long)init_addr);

            if (init_addr == 0) {
                DBG("init symbol not found");
                ret = -4; /* init symbol not found */
                goto detach;
            }


            /* implant_init creates the pipe in the target's fd table and
             * returns its target-local read-end. Root duplicates that end via
             * /proc before asking the implant to close its copy.
             *
             * The return value is also the observable agent-init result
             * (agent_entry_seam.h): a non-negative value is a valid log pipe
             * read-end and means the agent was reached; the distinct negative
             * sentinels IMPLANT_INIT_DEFERRED / IMPLANT_INIT_FAILED mean the
             * native payload loaded but the agent did not initialize. Those
             * are mapped to the vbi_inject return codes so the daemon can
             * avoid marking the agent active on native-load success alone and
             * apply a bounded same-live-PID retry on Deferred. */
            u64 init_args[1] = { cfg_addr };
            u64 target_read_fd;
            if (thread_group.managed) {
                g_remote_phase = "managed-init";
            }
            TIMING("init.begin");
            DBG("calling init_addr(0x%llx)...", (unsigned long long)cfg_addr);
            if (!remote_call(pid, bitness, init_addr, init_args, 1, &target_read_fd)) {
                ret = -4;
                goto detach;
            }

            TIMING("init.end");
            TIMING("handoff.begin");
            if (thread_group.managed) {
                g_remote_phase = "handoff";
            }
            int init_rc = (int)(int32_t)target_read_fd;
            /* Distinguish staged initialization from adopted live endpoints. */
            DBG("implant_init remote returns init_rc=%d", init_rc);
            /* Must match agent_entry_seam.h IMPLANT_INIT_* (kept as local
             * constants because injector.c is pure C and does not include the
             * C++ seam header). */
            int was_rebound = 0;

            enum vbi_implant_init_kind init_kind = vbi_classify_implant_init(init_rc);
            if (init_kind == VBI_INIT_STAGED) {
                ret = -10; /* returned only after successful final safe detach */
                goto detach;
            }
            if (init_kind == VBI_INIT_PIPE_OK) {
                DBG("implant_init completed through adopted pipe");
                ret = 0;
                goto detach;
            }

            if (init_kind == VBI_INIT_DEFERRED) {
                DBG("implant_init deferred (currentApplication null)");
                ret = -6; /* agent pending — retryable on same live PID */
                goto detach;
            }
            if (init_kind == VBI_INIT_FAILED) {
                DBG("implant_init hard-failed (agent load failed)");
                /* The sentinel carries no fd number, yet the implant kept its
                 * log pipe open with the init diagnostics already written
                 * into it. Fetch the target-local read-end via the exported
                 * getter, duplicate it through /proc, and adopt it via
                 * implant_finish_log_handoff(1) so the daemon can drain the
                 * diagnostics through its normal log router (agent-logging
                 * contract: all diagnostics ride the pipe, never logcat). */
                int fail_fd = adopt_failed_log_pipe(pid, bitness, handle,
                                                    dlsym_addr, caller_addr,
                                                    cfg_addr);
                if (fail_fd >= 0 && pipe_fds) {
                    pipe_fds->record_read_fd = fail_fd;
                } else if (fail_fd >= 0) {
                    close(fail_fd);
                }
                ret = -4; /* init failed — not retryable */
                goto detach;
            }

            if (init_kind == VBI_INIT_REBOUND) {
                target_read_fd = (u64)(uint32_t)remote_exported_fd(
                    pid, bitness, handle, dlsym_addr, caller_addr,
                    sym_str_addr - 8192, "implant_log_read_fd");
                if (g_remote_failed) {
                    ret = -4;
                    goto detach;
                }
                was_rebound = 1;
            } else if (init_kind == VBI_INIT_UNKNOWN_NEGATIVE
                       || init_kind == VBI_INIT_INVALID_FD) {
                DBG("implant_init returned unknown negative code %d", init_rc);
                ret = -4;
                goto detach;
            }

            int target_fd = (int)(uint32_t)target_read_fd;
            int daemon_fd = -1;
            int daemon_reply_fd = -1;
            /* A successful remote result still requires a positive pipe fd. */
            if (target_fd > 0) {
                char fd_path[64];
                snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, target_fd);
                daemon_fd = open(fd_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
                /* Preserve the native open result separately from the remote fd. */
                DBG("record /proc open -> daemon_fd=%d (errno=%d)",
                    daemon_fd, daemon_fd < 0 ? errno : 0);
                if (daemon_fd < 0) {
                    vbi_native_diagnostic("error", "injector", "stage=record-pipe-open target_pid=%d target_fd=%d errno=%d", pid, target_fd, errno);
                }
            }

            const char *reply_sym = "implant_state_reply_write_fd";
            size_t reply_len = strlen(reply_sym) + 1;
            u64 reply_str_addr = sym_str_addr - reply_len - 512;
            if (target_write_mem(pid, reply_str_addr, reply_sym, reply_len) == 0) {
                u64 reply_sym_args[3] = { handle, reply_str_addr, caller_addr };
                u64 reply_fn = 0;
                if (!remote_call(pid, bitness, dlsym_addr, reply_sym_args, 3, &reply_fn)) {
                    goto handoff_failed;
                }
                if (reply_fn) {
                    u64 reply_raw = 0;
                    if (!remote_call(pid, bitness, reply_fn, NULL, 0, &reply_raw)) {
                        goto handoff_failed;
                    }
                    int target_reply_fd = (int)(uint32_t)reply_raw;
                    /* Distinguish an absent remote write-end from a failed local open. */
                    DBG("state_reply remote returns target_reply_fd=%d (raw=0x%llx)",
                        target_reply_fd, (unsigned long long)reply_raw);
                    /* Descriptor zero is not a state-reply pipe. */
                    if (target_reply_fd > 0) {
                        char reply_path[64];
                        snprintf(reply_path, sizeof(reply_path), "/proc/%d/fd/%d",
                                 pid, target_reply_fd);
                        daemon_reply_fd =
                            open(reply_path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
                        /* Retain the write-end open outcome before handoff. */
                        DBG("state_reply /proc open -> daemon_reply_fd=%d (errno=%d)",
                            daemon_reply_fd, daemon_reply_fd < 0 ? errno : 0);
                        if (daemon_reply_fd < 0) {
                            vbi_native_diagnostic("error", "injector", "stage=state-reply-pipe-open target_pid=%d target_fd=%d errno=%d", pid, target_reply_fd, errno);
                        }
                    }
                }
            }

            const char *finish_sym = "implant_finish_log_handoff";
            size_t finish_len = strlen(finish_sym) + 1;
            u64 finish_str_addr = reply_str_addr - finish_len - 16;
            if (target_write_mem(pid, finish_str_addr, finish_sym, finish_len) == 0) {
                u64 finish_args[3] = { handle, finish_str_addr, caller_addr };
                u64 finish_addr = 0;
                if (!remote_call(pid, bitness, dlsym_addr, finish_args, 3, &finish_addr)) {
                    goto handoff_failed;
                }
                if (finish_addr) {
                    unsigned int accepted = 0U;
                    if (daemon_fd >= 0) {
                        accepted |= 1U;
                    }
                    if (daemon_reply_fd >= 0) {
                        accepted |= 2U;
                    }
                    u64 accepted_args[1] = { accepted };
                    /* Only adopted endpoints contribute accepted handoff bits. */
                    DBG("finish_log_handoff accepted=0x%x (record=%d reply=%d)",
                        accepted, daemon_fd, daemon_reply_fd);
                    u64 handoff_ack = 0;
                    if (!remote_call(pid, bitness, finish_addr, accepted_args, 1, &handoff_ack)) {
                        goto handoff_failed;
                    }
                    DBG("finish_log_handoff ack=0x%llx", (unsigned long long)handoff_ack);
                    if (handoff_ack != VBI_HANDOFF_ACK) {
                        if (daemon_fd >= 0) {
                            close(daemon_fd);
                            daemon_fd = -1;
                        }
                        if (daemon_reply_fd >= 0) {
                            close(daemon_reply_fd);
                            daemon_reply_fd = -1;
                        }
                    }
                } else {
                    if (daemon_fd >= 0) {
                        close(daemon_fd);
                        daemon_fd = -1;
                    }
                    if (daemon_reply_fd >= 0) {
                        close(daemon_reply_fd);
                        daemon_reply_fd = -1;
                    }
                }
            } else {
                if (daemon_fd >= 0) {
                    close(daemon_fd);
                    daemon_fd = -1;
                }
                if (daemon_reply_fd >= 0) {
                    close(daemon_reply_fd);
                    daemon_reply_fd = -1;
                }
            }
handoff_failed:
            if (g_remote_failed) {
                if (daemon_fd >= 0) {
                    close(daemon_fd);
                }
                if (daemon_reply_fd >= 0) {
                    close(daemon_reply_fd);
                }
                ret = -4;
                goto detach;
            }
            if (pipe_fds) {
                pipe_fds->record_read_fd = daemon_fd;
            } else if (daemon_fd >= 0) {
                close(daemon_fd);
            }
            if (pipe_fds) {
                pipe_fds->state_reply_fd = daemon_reply_fd;
            } else if (daemon_reply_fd >= 0) {
                close(daemon_reply_fd);
            }
            if (was_rebound) {
                if (daemon_fd < 0 || daemon_reply_fd < 0) {
                    ret = -4;
                } else {
                    ret = -9;
                }
                goto detach;
            }
            if (daemon_fd < 0 || daemon_reply_fd < 0) {
                DBG("implant_init returned without both adopted endpoints");
                ret = -4;
                goto detach;
            }
            DBG("init_addr call returned");
            ret = 0;
            goto detach;
        } else {
            DBG("resolve __loader_dlsym FAILED");
            ret = -4;
            goto detach;
        }
    }

    TIMING("handoff.end");
    DBG("inject SUCCESS");
    ret = 0; /* success */

detach:;
    if (g_remote_failed && dlerr_out && dlerr_out_sz > 0) {
        snprintf(dlerr_out, dlerr_out_sz,
                 "remote-call-%s restore=%s/%s reason=%s pstate-valid=%d expected=0x%llx observed=0x%llx changed=0x%llx errno-valid=%d restore-errno=%d length=%zu/%zu mismatch=%zu first=%zu helper=%d pid=%d phase=%s origin-valid=%d original-pc=0x%llx original-lr=0x%llx status=0x%x signal=%d callee-pc=0x%llx callee-lr=0x%llx errno=%d executed=%d registers-read=%d restore-attempted=%d restored=%d managed-unwind=%s",
                 vbi_remote_stage_name(g_remote_result.stage),
                 vbi_restore_part_name(g_remote_restore_diag.part),
                 vbi_restore_operation_name(g_remote_restore_diag.operation),
                 vbi_restore_reason_name(g_remote_restore_diag.reason),
                 g_remote_restore_diag.pstate_valid,
                 (unsigned long long)g_remote_restore_diag.pstate_expected,
                 (unsigned long long)g_remote_restore_diag.pstate_observed,
                 (unsigned long long)g_remote_restore_diag.pstate_changed,
                 g_remote_restore_diag.errno_valid, g_remote_restore_diag.error,
                 g_remote_restore_diag.expected_length, g_remote_restore_diag.returned_length,
                 g_remote_restore_diag.mismatch_count, g_remote_restore_diag.first_mismatch,
                 (int)getpid(), pid, g_remote_phase,
                 g_remote_result.origin.valid, (unsigned long long)g_remote_result.origin.pc,
                 (unsigned long long)g_remote_result.origin.lr, g_remote_result.wait_status,
                 WIFSTOPPED(g_remote_result.wait_status)
                     ? WSTOPSIG(g_remote_result.wait_status) : 0,
                 (unsigned long long)g_remote_result.pc,
                 (unsigned long long)g_remote_result.lr, g_remote_result.error,
                 g_remote_result.executed, g_remote_result.registers_read,
                 g_remote_result.restore_attempted, g_remote_result.restored,
                 g_remote_result.executed ? "unverified" : "not-executed");
    }
    /* Restore helpers do not return while a live tracee may still contain a
     * temporary frame, so every attached task remains cleanup-owned here.
     *
     * Unsafe-cleanup invariant (live ANR 2026-09-18): even when registers
     * could not be proven restored, the group detach below is still attempted
     * for every attached task (bounded), and this function must RETURN -8
     * (never retry forever). If a task could not be detached at all, the
     * helper process exits right after this return; tracer death makes the
     * kernel auto-detach the tracee, so no helper may remain ptrace-ATTACHED
     * to the target once the daemon gives up. The daemon additionally
     * SIGKILLs and reaps the helper on every IPC error path. */
    int detach_result = VBI_TG_OK;
    /* Always attempt the group detach: the result codes below already carry
     * the unsafe/not-safe distinction, and attempting costs nothing while an
     * unconditional skip risks an attached orphan. */
    TIMING("detach.begin");
    detach_result = vbi_thread_group_detach(&thread_group);
    TIMING("detach.end");
    g_active_thread_group = NULL;
    restore_term_signals(&injection_sigold);
    if (detach_result != VBI_TG_OK || !g_tracee_detach_safe
        || !g_thread_group_cleanup_safe) {
        TIMED_RETURN(-8);
    }
    /* Restored registers/stack/TLS do not unwind loader constructors or locks.
     * Preserve a typed result, independent of the truncated diagnostic buffer.
     * An executed timed-out native loader must never be called again in this
     * lifetime, even for bootstrap abort. Unsafe detach above retains -8. */
    if (loader_call_unresolved(ret)) {
        TIMED_RETURN(-12);
    }
    if (retry_loader && loader_retries < 8) {
        loader_retries++;
        struct timespec pause = {0, 10L * 1000 * 1000};
        while (nanosleep(&pause, &pause) < 0 && errno == EINTR) {
        }
        goto acquire_group;
    }
    TIMED_RETURN(ret);
}
