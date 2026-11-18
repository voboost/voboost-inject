#include "bootstrap_fd_ownership.h"
#include "jni_attachment.h"
#include "scoped_jni_attachment.h"
#include "sigpipe_safe_write.h"
#include "pipe_bootstrap_phase.h"

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <unistd.h>

#include <fcntl.h>

static volatile sig_atomic_t sigpipe_calls = 0;

static void custom_sigpipe_handler(int) {
    sigpipe_calls = sigpipe_calls + 1;
}

struct FakeEnv {};

struct FakeVm {
    int get_env_result = 0;
    int attach_result = 0;
    int detach_result = 0;
    int attach_calls = 0;
    int detach_calls = 0;
    FakeEnv env;

    int GetEnv(void **result, int) {
        if (get_env_result == 0) {
            *result = &env;
        }
        return get_env_result;
    }

    int AttachCurrentThread(FakeEnv **result, void *) {
        attach_calls++;
        if (attach_result == 0) {
            *result = &env;
        }
        return attach_result;
    }

    int DetachCurrentThread() {
        detach_calls++;
        return detach_result;
    }
};

static int detach_failures = 0;

static void record_detach_failure() {
    detach_failures++;
}

static void test_production_attachment_scope() {
    constexpr int ok = 0;
    constexpr int detached = -2;
    constexpr int failed = -1001;
    FakeVm pre_attached;
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &pre_attached, ok, detached, 6, failed, record_detach_failure);
        assert(attachment.env() == &pre_attached.env);
        assert(attachment.finish(7) == 7);
    }
    assert(pre_attached.attach_calls == 0 && pre_attached.detach_calls == 0);

    FakeVm get_env_failed{.get_env_result = -3};
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &get_env_failed, ok, detached, 6, failed, record_detach_failure);
        assert(attachment.env() == nullptr);
        assert(attachment.decision() == JniAttachmentDecision::FAIL);
    }
    assert(get_env_failed.attach_calls == 0 && get_env_failed.detach_calls == 0);

    FakeVm attach_failed{.get_env_result = detached, .attach_result = -1};
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &attach_failed, ok, detached, 6, failed, record_detach_failure);
        assert(attachment.env() == nullptr);
    }
    assert(attach_failed.attach_calls == 1 && attach_failed.detach_calls == 0);

    for (int result : {0, -1000, failed}) {
        FakeVm owned{.get_env_result = detached};
        {
            ScopedJniAttachment<FakeVm, FakeEnv> attachment(
                &owned, ok, detached, 6, failed, record_detach_failure);
            assert(attachment.env() == &owned.env);
            assert(attachment.finish(result) == result);
            assert(attachment.finish(result) == failed);
        }
        assert(owned.attach_calls == 1 && owned.detach_calls == 1);
    }

    FakeVm detach_failed{.get_env_result = detached, .detach_result = -1};
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &detach_failed, ok, detached, 6, failed, record_detach_failure);
        assert(attachment.finish(7) == failed);
    }
    assert(detach_failed.detach_calls == 1 && detach_failures == 1);

    FakeVm exceptional{.get_env_result = detached};
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &exceptional, ok, detached, 6, failed, record_detach_failure);
        assert(attachment.env() == &exceptional.env);
    }
    assert(exceptional.detach_calls == 1);

    FakeVm exceptional_detach_failed{
        .get_env_result = detached, .detach_result = -1};
    {
        ScopedJniAttachment<FakeVm, FakeEnv> attachment(
            &exceptional_detach_failed, ok, detached, 6, failed,
            record_detach_failure);
        assert(attachment.env() == &exceptional_detach_failed.env);
    }
    assert(exceptional_detach_failed.detach_calls == 1 && detach_failures == 2);
}

int main() {
    /* Parsed identity and an initialization guard are not a completed Java runtime. */
    assert(!pipe_resident_ready(true, false, 64, 64));
    assert(!pipe_resident_ready(false, false, 64, 64));
    assert(!pipe_resident_ready(true, true, 0, 64));
    assert(!pipe_resident_ready(true, true, 64, 0));
    assert(pipe_resident_ready(true, true, 64, 64));
    try {
        test_production_attachment_scope();
        /* A published ancillary artifact stays readable after consumed DEX fds are
         * closed, and its number cannot alias a subsequently opened unrelated fd. */
        int dex_pipe[2];
        int artifact_pipe[2];
        assert(pipe(dex_pipe) == 0);
        assert(pipe(artifact_pipe) == 0);
        static const char artifact_bytes[] = "artifact";
        assert(write(artifact_pipe[1], artifact_bytes, sizeof(artifact_bytes)) ==
               static_cast<ssize_t>(sizeof(artifact_bytes)));
        close(dex_pipe[1]);
        close(artifact_pipe[1]);
        int dex_fd = dex_pipe[0];
        int artifact_fd = artifact_pipe[0];
        BootstrapFdOwnership ownership;
        ownership.stage(dex_fd, false);
        ownership.stage(artifact_fd, true);
        ownership.publish();
        assert(ownership.staged_count() == 0);
        assert(ownership.resident_count() == 1);
        assert(fcntl(dex_fd, F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(artifact_fd, F_GETFD) >= 0);
        char delayed_read[sizeof(artifact_bytes)]{};
        assert(read(artifact_fd, delayed_read, sizeof(delayed_read)) ==
               static_cast<ssize_t>(sizeof(delayed_read)));
        assert(memcmp(delayed_read, artifact_bytes, sizeof(artifact_bytes)) == 0);
        int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
        assert(reused >= 0);
        assert(reused != artifact_fd);
        close(reused);

        /* A failed replacement leaves the current generation live; a successful
         * replacement rotates it and permits the old number to be reused only
         * after no registered path can refer to it. */
        int failed_pipe[2];
        assert(pipe(failed_pipe) == 0);
        close(failed_pipe[1]);
        ownership.stage(failed_pipe[0], true);
        ownership.discard_staged();
        assert(fcntl(artifact_fd, F_GETFD) >= 0);
        int replacement_pipe[2];
        assert(pipe(replacement_pipe) == 0);
        close(replacement_pipe[1]);
        int replacement_fd = replacement_pipe[0];
        ownership.stage(replacement_fd, true);
        ownership.publish();
        assert(fcntl(artifact_fd, F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(replacement_fd, F_GETFD) >= 0);

        assert(jni_attachment_decision(0, 0, -2) ==
               JniAttachmentDecision::PRE_ATTACHED);
        assert(jni_attachment_decision(-2, 0, -2) ==
               JniAttachmentDecision::ATTACH);
        assert(jni_attachment_decision(-3, 0, -2) ==
               JniAttachmentDecision::FAIL);
        assert(!jni_attachment_is_owned(JniAttachmentDecision::PRE_ATTACHED, true));
        assert(!jni_attachment_is_owned(JniAttachmentDecision::ATTACH, false));
        assert(jni_attachment_is_owned(JniAttachmentDecision::ATTACH, true));
        assert(jni_detach_result(false, -1, 0, 7, -1001) == 7);
        assert(jni_detach_result(true, 0, 0, -1000, -1001) == -1000);
        assert(jni_detach_result(true, 0, 0, -1001, -1001) == -1001);
        assert(jni_detach_result(true, -1, 0, 7, -1001) == -1001);

        struct sigaction custom {};
        custom.sa_handler = custom_sigpipe_handler;
        sigemptyset(&custom.sa_mask);
        struct sigaction previous {};
        assert(sigaction(SIGPIPE, &custom, &previous) == 0);

        int fds[2];
        assert(pipe(fds) == 0);
        close(fds[0]);
        errno = 0;
        assert(sigpipe_safe_write(fds[1], "x", 1) == -1);
        assert(errno == EPIPE);
        close(fds[1]);
        assert(sigpipe_calls == 0);

        struct sigaction current {};
        assert(sigaction(SIGPIPE, nullptr, &current) == 0);
        assert(current.sa_handler == custom_sigpipe_handler);

        assert(pipe(fds) == 0);
        close(fds[0]);
        assert(write(fds[1], "x", 1) == -1);
        assert(errno == EPIPE);
        close(fds[1]);
        assert(sigpipe_calls == 1);

        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        sigset_t old_mask;
        assert(pthread_sigmask(SIG_BLOCK, &set, &old_mask) == 0);
        assert(raise(SIGPIPE) == 0);
        assert(pipe(fds) == 0);
        close(fds[0]);
        assert(sigpipe_safe_write(fds[1], "x", 1) == -1);
        assert(errno == EPIPE);
        close(fds[1]);
        sigset_t pending;
        assert(sigpending(&pending) == 0);
        assert(sigismember(&pending, SIGPIPE) == 1);
        int consumed_signal = 0;
        assert(sigwait(&set, &consumed_signal) == 0);
        assert(consumed_signal == SIGPIPE);
        assert(pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) == 0);

        assert(sigaction(SIGPIPE, &previous, nullptr) == 0);
    }
    catch (...) {
        return 1;
    }
}
