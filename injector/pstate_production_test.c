#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_CONT 7
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static FILE *mock_fopen(const char *path, const char *mode);
static int mock_open(const char *path, int flags, ...);
static ssize_t mock_read(int fd, void *bytes, size_t length);
static int mock_close(int fd);
static ssize_t mock_readlink(const char *path, char *bytes, size_t length);
static int mock_nanosleep(const struct timespec *request, struct timespec *remaining);
static long mock_ptrace(int request, pid_t pid, void *address, void *data);

/* Compile the actual entry point and static per-call gate, replacing only
 * external kernel/proc transport. No admission/detach/retry code is copied. */
#define fopen mock_fopen
#define open mock_open
#define read mock_read
#define close mock_close
#define readlink mock_readlink
#define nanosleep mock_nanosleep
#define ptrace mock_ptrace
#include "injector.c"
#undef fopen
#undef open
#undef read
#undef close
#undef readlink
#undef nanosleep
#undef ptrace

static unsigned attaches, detaches, sleeps, memory_writes, register_writes, ptrace_calls;
static int natural_after, detach_failure;
static struct vbi_arm64_regs kernel;

static FILE *mock_fopen(const char *path, const char *mode) {
    (void)path; (void)mode;
    /* No debug-log writes. After a safe initial baseline, loader maps are
     * deliberately unavailable so the test exits before payload injection. */
    return NULL;
}
static int mock_open(const char *path, int flags, ...) {
    (void)flags;
    assert(strcmp(path, "/proc/42/cmdline") == 0);
    return 999;
}
static ssize_t mock_read(int fd, void *bytes, size_t length) {
    assert(fd == 999 && length >= sizeof("target"));
    memcpy(bytes, "target", sizeof("target"));
    return sizeof("target");
}
static int mock_close(int fd) {
    assert(fd == 999);
    return 0;
}
static ssize_t mock_readlink(const char *path, char *bytes, size_t length) {
    const char executable[] = "/system/bin/app_process64";
    assert(strcmp(path, "/proc/42/exe") == 0 && length >= sizeof(executable));
    memcpy(bytes, executable, sizeof(executable) - 1);
    return sizeof(executable) - 1;
}
static int mock_nanosleep(const struct timespec *request, struct timespec *remaining) {
    (void)remaining;
    assert(request->tv_sec == 0 && request->tv_nsec == 10000000);
    /* Every retry must release the group before allowing natural progress. */
    assert(attaches == detaches);
    sleeps++;
    return 0;
}
static long mock_ptrace(int request, pid_t pid, void *address, void *data) {
    (void)request; (void)pid; (void)address; (void)data;
    ptrace_calls++;
    assert(!"unexpected ptrace: admission must precede extended state/frame writes");
    return -1;
}
static long fake_get(pid_t pid, void *registers, size_t *length) {
    assert(pid == 42 && *length == sizeof(kernel));
    memcpy(registers, &kernel, *length);
    return 0;
}
static long fake_set(pid_t pid, const void *registers, size_t length) {
    (void)pid; (void)registers; (void)length;
    register_writes++;
    assert(!"unexpected register mutation");
    return -1;
}
static long fake_detach(pid_t pid, int signal_number) {
    (void)pid; (void)signal_number;
    assert(!"group mock owns detach");
    return -1;
}

int vbi_thread_group_attach(pid_t pid, struct vbi_thread_group *group) {
    assert(pid == 42 && attaches == detaches);
    attaches++;
    *group = (struct vbi_thread_group){
        .tgid = 42, .execution_tid = 42, .starttime = 1, .count = 1,
        .tasks = {{.tid = 42, .attached = 1, .stopped = 1}}
    };
    if (natural_after && attaches > (unsigned)natural_after) {
        /* Only a released/reacquired group can observe natural execution
         * progress. The injector never SETs this new baseline. */
        kernel.pstate = UINT64_C(0x20000000);
    }
    return VBI_TG_OK;
}
int vbi_thread_group_detach(struct vbi_thread_group *group) {
    assert(group->execution_tid == 42 && attaches == detaches + 1);
    detaches++;
    if (detach_failure == 2) {
        g_tracee_detach_safe = 0;
    } else if (detach_failure == 3) {
        g_thread_group_cleanup_safe = 0;
    }
    return detach_failure == 1 ? VBI_TG_UNSAFE_CLEANUP : VBI_TG_OK;
}
int vbi_thread_group_verify_expected_identity(const struct vbi_thread_group *group,
                                              uint32_t uid, const char *context) {
    (void)uid; (void)context;
    assert(group->starttime == 1);
    return VBI_TG_OK;
}
int vbi_thread_group_loader_ready(const struct vbi_thread_group *group) {
    (void)group;
    assert(!"namespace load is unreachable with unavailable loader maps");
    return 0;
}
int vbi_target_libc_entry_busy(int pid, int bitness, u64 pc, u64 lr) {
    (void)pid; (void)bitness; (void)pc; (void)lr;
    assert(!"libc probe is unreachable with unavailable loader maps");
    return -1;
}
int vbi_thread_group_enter_managed(struct vbi_thread_group *group) {
    (void)group; assert(!"unexpected managed transition"); return -1;
}
int vbi_thread_group_capture_clone(struct vbi_thread_group *group, pid_t pid, int status) {
    (void)group; (void)pid; (void)status; assert(!"unexpected clone"); return -1;
}
void vbi_thread_group_retain_stop_signal(struct vbi_thread_group *group,
                                         pid_t tid, int signal_number) {
    (void)group; (void)tid; (void)signal_number;
    assert(!"unexpected retained signal");
}
int target_read_mem(int pid, u64 address, void *bytes, size_t length) {
    (void)pid; (void)address; (void)bytes; (void)length;
    assert(!"unexpected target memory read"); return -1;
}
int target_write_mem(int pid, u64 address, const void *bytes, size_t length) {
    (void)pid; (void)address; (void)bytes; (void)length;
    memory_writes++;
    assert(!"unexpected target memory write"); return -1;
}
int target_verify_mem(int pid, u64 address, const void *bytes, size_t length) {
    (void)pid; (void)address; (void)bytes; (void)length;
    assert(!"unexpected target memory verify"); return -1;
}
u64 find_target_caller_addr(int pid) {
    (void)pid; return 0;
}
u64 resolve_loader_symbol(int pid, int bitness, const char *name) {
    (void)pid; (void)bitness; (void)name;
    assert(!"unexpected linker resolution"); return 0;
}
static void reset(void) {
    attaches = detaches = sleeps = memory_writes = register_writes = ptrace_calls = 0;
    natural_after = detach_failure = 0;
    kernel = (struct vbi_arm64_regs){.sp = 0x10000, .pc = 0x20000,
                                     .pstate = UINT64_C(0x20000400)};
    g_remote_failed = 0;
}
static int inject(char *diagnostic, size_t length) {
    struct vbi_agent_pipe_fds pipes = {9, 10};
    int result = vbi_inject(42, "/payload.so", NULL, NULL, "target", 1, 1000,
                            "u:r:system_app:s0", &pipes, diagnostic, length);
    assert(pipes.record_read_fd == -1 && pipes.state_reply_fd == -1);
    assert(memory_writes == 0 && register_writes == 0 && ptrace_calls == 0);
    return result;
}
int main(void) {
    const struct vbi_ptrace_syscalls syscalls = {fake_get, fake_set, fake_detach};
    vbi_ptrace_install_test_syscalls(&syscalls);
    char diagnostic[128];

    reset();
    struct vbi_arm64_regs original = kernel;
    assert(inject(diagnostic, sizeof(diagnostic)) == -11);
    assert(strcmp(diagnostic, "register-baseline-deferred") == 0);
    assert(attaches == 9 && detaches == 9 && sleeps == 8);
    assert(memcmp(&kernel, &original, sizeof(kernel)) == 0);

    reset();
    natural_after = 1;
    assert(inject(diagnostic, sizeof(diagnostic)) == -3);
    assert(strcmp(diagnostic, "loader-context-unavailable") == 0);
    assert(attaches == 2 && detaches == 2 && sleeps == 1);
    assert(kernel.pstate == UINT64_C(0x20000000));

    for (int unsafe = 1; unsafe <= 3; unsafe++) {
        reset();
        detach_failure = unsafe;
        assert(inject(diagnostic, sizeof(diagnostic)) == -8);
        assert(attaches == 1 && detaches == 1 && sleeps == 0);
    }

    reset();
    original = kernel;
    struct vbi_remote_result result = remote_call_layout(42, 64, 0x30000, NULL, 0, NULL, 0);
    assert(result.stage == VBI_CALL_PREPARE && result.error == EAGAIN);
    assert(!result.executed && !result.restore_attempted && !result.restored);
    assert(memory_writes == 0 && register_writes == 0 && ptrace_calls == 0);
    assert(memcmp(&kernel, &original, sizeof(kernel)) == 0);
    // Production classifier: restored CPU state does not prove loader unwind.
    g_remote_failed = 1;
    g_remote_phase = "native";
    g_remote_result = (struct vbi_remote_result){
        .stage = VBI_CALL_TIMEOUT, .executed = 1, .restored = 1,
    };
    assert(loader_call_unresolved(-3));
    assert(!loader_call_unresolved(-4));
    g_remote_result.executed = 0;
    assert(!loader_call_unresolved(-3));
    g_remote_result.executed = 1;
    g_remote_result.stage = VBI_CALL_RETURNED;
    assert(!loader_call_unresolved(-3));
    g_remote_result.stage = VBI_CALL_TIMEOUT;
    g_remote_phase = "managed-init";
    assert(!loader_call_unresolved(-3));
    g_remote_phase = "native";
    g_remote_failed = 0;
    assert(!loader_call_unresolved(-3));

    vbi_ptrace_install_test_syscalls(NULL);
    return 0;
}
