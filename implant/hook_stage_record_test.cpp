#include "hook_stage_record.h"
#include "lsplant_stage_callback_test.inc"

#include <cassert>
#include <chrono>
#include <cstring>
#include <atomic>
#include <thread>
#include <poll.h>

static const char *observed[16];
static uint64_t elapsed_values[16];
static size_t count;
static void observe(const char *stage, uint64_t elapsed) noexcept {
    assert(count < 16);
    observed[count] = stage;
    elapsed_values[count++] = elapsed;
}

static void callback_optional_and_scoped() {
    using voboost_hook_diagnostics::Scope;
    using voboost_hook_diagnostics::Stage;
    Scope absent;
    absent.Emit("build-dex-begin");
    assert(count == 0);
    voboost_lsplant_set_stage_callback(observe);
    Scope scope;
    scope.Emit("build-dex-begin");
    {
        Stage jni(scope, "jni-begin", "jni-end");
    }
    scope.Emit("build-dex-end");
    assert(count == 4);
    assert(std::strcmp(observed[0], "build-dex-begin") == 0);
    assert(std::strcmp(observed[1], "jni-begin") == 0);
    assert(std::strcmp(observed[2], "jni-end") == 0);
    assert(std::strcmp(observed[3], "build-dex-end") == 0);
    for (size_t index = 1; index < count; ++index) {
        assert(elapsed_values[index] >= elapsed_values[index - 1]);
    }
    voboost_lsplant_set_stage_callback(nullptr);
    Scope disabled;
    disabled.Emit("mutation-end");
    assert(count == 4);
    scope.Emit("mutation-end"); /* current hook keeps its captured callback */
    assert(count == 5);
}

static void records_never_wait_for_peer_or_pipe() {
    int fds[2];
    assert(pipe(fds) == 0);
    assert(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    assert(!write_hook_stage_record(fds[1], &mutex, 123, "mutation-end", 5, 6, 7));
    assert(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
    assert(pthread_mutex_lock(&mutex) == 0);
    std::atomic<int> result{-1};
    std::thread blocked([&] {
                        result.store(write_hook_stage_record(fds[1], &mutex, 123, "gc-critical-begin", 5, 6, 7),
                                     std::memory_order_release);
        });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (result.load(std::memory_order_acquire) < 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    assert(result.load(std::memory_order_acquire) == 0);
    blocked.join();
    assert(pthread_mutex_unlock(&mutex) == 0);
    assert(write_hook_stage_record(fds[1], &mutex, 123, "suspend-all-begin", 5, 6, 7));
    char actual[512] = {};
    struct pollfd available {fds[0], POLLIN, 0};
    assert(poll(&available, 1, 250) == 1 && (available.revents & POLLIN));
    ssize_t length = read(fds[0], actual, sizeof(actual));
    const char *expected =
        "L|123|implant|2|lsplant-stage: stage=suspend-all-begin pid=5 tid=6 elapsed_ms=7\n";
    assert(length == static_cast<ssize_t>(strlen(expected)));
    assert(memcmp(actual, expected, static_cast<size_t>(length)) == 0);
    char fill[4096] = {};
    while (write(fds[1], fill, sizeof(fill)) > 0) {
    }
    assert(errno == EAGAIN);
    assert(!write_hook_stage_record(fds[1], &mutex, 123, "mutation-end", 5, 6, 7));
    assert(pthread_mutex_trylock(&mutex) == 0);
    assert(pthread_mutex_unlock(&mutex) == 0);
    close(fds[0]);
    assert(!write_hook_stage_record(fds[1], &mutex, 123, "mutation-end", 5, 6, 7));
    close(fds[1]);
    assert(pthread_mutex_destroy(&mutex) == 0);
}

int main() {
    callback_optional_and_scoped();
    records_never_wait_for_peer_or_pipe();
}
