#include "../injector/thread_group.h"

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int syscall_errno, diagnostic_errno;
static long fixture_ptrace(int, pid_t, void *, void *) {
    errno = syscall_errno;
    return -1;
}
static pid_t fixture_waitpid(pid_t, int *, int) {
    errno = syscall_errno;
    return -1;
}
static void fixture_log() {
    errno = diagnostic_errno;
}
static int fixture_open(const char *, int) {
    errno = diagnostic_errno;
    return -1;
}
#define ptrace fixture_ptrace
#define waitpid fixture_waitpid
#define open fixture_open
#define TGDBG(...) fixture_log()
#define PTRACE_ATTACH 1
#ifndef __WALL
#define __WALL 0x40000000
#endif
#define VBI_TG_WAIT_TIMEOUT_MS 15000
#define VBI_TG_WAIT_STEP_MS 10
#include "thread_group_errno_test.inc"
#undef ptrace
#undef waitpid
#undef open
#undef TGDBG

struct Bootstrap {
    std::string manifest;
};
struct PipeBootstrapReadDiag {
    const char *stage;
    int error;
};
static Bootstrap g_pipe_bootstrap;
static bool g_pipe_bootstrap_ready;
static int g_state_reply_fd, fail_flags_call, flags_calls, worker_calls, cleanup_calls;
static constexpr int IMPLANT_INIT_FAILED = -1;
static int fixture_fcntl(int fd, int command, int flags) {
    if (++flags_calls == fail_flags_call) {
        errno = EBADF;
        return -1;
    }
    return fcntl(fd, command, flags);
}
static bool read_pipe_bootstrap_diag(int fd, Bootstrap *value, PipeBootstrapReadDiag *) {
    assert((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
    value->manifest = "verified fixture";
    return true;
}
static int fail_bootstrap_attempt(int result) {
    ++cleanup_calls;
    g_pipe_bootstrap_ready = false;
    g_pipe_bootstrap.manifest.clear();
    return result;
}
#define fcntl fixture_fcntl
#define IMPLANT_LOGE(...) ((void)0)
static int run_bootstrap() {
#include "bootstrap_flags_test.inc"
    ++worker_calls;
    return 0;
}
#undef fcntl
#undef IMPLANT_LOGE

int main() noexcept try {
    diagnostic_errno = ESRCH;
    syscall_errno = EPERM;
    assert(system_attach(nullptr, 42) == VBI_TG_OP_DENIED);
    syscall_errno = EACCES;
    assert(system_attach(nullptr, 42) == VBI_TG_OP_DENIED);
    syscall_errno = ECHILD;
    assert(wait_stopped_bounded(42) == VBI_TG_OP_ERROR);
    syscall_errno = ESRCH;
    diagnostic_errno = EACCES;
    assert(wait_stopped_bounded(42) == VBI_TG_OP_GONE);
    int pipes[2];
    assert(pipe(pipes) == 0);
    g_state_reply_fd = pipes[0];
    for (int failure = 1; failure <= 3; ++failure) {
        assert(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0);
        g_pipe_bootstrap.manifest.clear();
        g_pipe_bootstrap_ready = false;
        flags_calls = 0; fail_flags_call = failure;
        assert(run_bootstrap() == IMPLANT_INIT_FAILED);
        assert(!g_pipe_bootstrap_ready && worker_calls == 0);
        assert(cleanup_calls == failure);
    }
    assert(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0);
    flags_calls = 0; fail_flags_call = 0;
    g_pipe_bootstrap.manifest.clear();
    assert(run_bootstrap() == 0 && worker_calls == 1 && g_pipe_bootstrap_ready);
    assert((fcntl(pipes[0], F_GETFL) & O_NONBLOCK) != 0);
    close(pipes[0]); close(pipes[1]);
}
catch (...) {
    return 1;
}
