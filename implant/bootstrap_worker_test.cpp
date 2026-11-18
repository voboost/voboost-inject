#include "bootstrap_worker.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>
#include <vector>
#include <fcntl.h>

static BootstrapWorkerBinding binding() {
    BootstrapWorkerBinding value;
    value.pid = 42; value.starttime = 123; value.nonce.fill(1);
    value.generation.fill('a'); value.catalog.fill('b');
    return value;
}
int main(int argc, char **argv) noexcept try {
    auto expected = binding();
    std::atomic<int> calls{0};
    BootstrapWorkerGate gate(expected);
    assert(gate.phase() == BootstrapWorkerPhase::Staged && calls == 0);
    bool dispatched = gate.run(expected, [&] {
        ++calls;
    });
    assert(dispatched);
    dispatched = gate.run(expected, [&] {
        ++calls;
    });
    assert(!dispatched && calls == 1);
    gate.cancel();
    assert(!gate.finish(true) && gate.phase() == BootstrapWorkerPhase::Cancelled);
    for (int field = 0; field < 5; ++field) {
        auto wrong = expected;
        if (field == 0) {
            wrong.pid++;
        }
        if (field == 1) {
            wrong.starttime++;
        }
        if (field == 2) {
            wrong.nonce[0]++;
        }
        if (field == 3) {
            wrong.generation[0] = 'c';
        }
        if (field == 4) {
            wrong.catalog[0] = 'c';
        }
        BootstrapWorkerGate rejected(expected);
        bool admitted = rejected.run(wrong, [&] {
            ++calls;
        });
        assert(!admitted && calls == 1);
        assert(rejected.phase() == BootstrapWorkerPhase::Cancelled);
    }
    BootstrapWorkerGate completed(expected);
    assert(completed.commit(expected) && completed.finish(true) && completed.claim());
    completed.cancel();
    assert(!completed.publish(expected));
    BootstrapWorkerGate published(expected);
    assert(published.commit(expected) && published.finish(true) && published.claim());
    assert(published.publish(expected));
    assert(published.phase() == BootstrapWorkerPhase::Ready);
    BootstrapWorkerGate deferred(expected);
    assert(deferred.commit(expected) && deferred.defer());
    assert(!deferred.publish(expected));

    // This is the same dispatch seam used by the owned production worker.
    std::mutex original_lock;
    original_lock.lock();
    std::promise<void> detach_completed;
    auto commit = detach_completed.get_future();
    BootstrapWorkerGate owned(expected);
    std::atomic<int> attached{0}, detached{0};
    std::promise<void> attachment_entered;
    auto entered = attachment_entered.get_future();
    auto creator = std::this_thread::get_id();
    std::thread worker([&] {
                       commit.wait();
                       bool admitted = owned.run(expected, [&] {
                                                 assert(std::this_thread::get_id() != creator);
                                                 ++attached;
                                                 attachment_entered.set_value();
                                                 std::lock_guard<std::mutex> lock(original_lock);
                                                 ++detached;
            });
                       assert(admitted);
        });
    assert(attached == 0);
    detach_completed.set_value();
    assert(entered.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
    entered.get();
    assert(attached == 1 && detached == 0);
    original_lock.unlock();
    worker.join();
    assert(attached == 1 && detached == 1);
    BootstrapWorkerGate once(expected);
    std::atomic<int> executions{0};
    auto start = [&] {
                     once.run(expected, [&] {
            ++executions;
        });
                 };
    std::thread first(start), second(start);
    first.join(); second.join();
    assert(executions == 1);

    int fds[2]; assert(pipe(fds) == 0);
    int owned_read = dup(fds[0]), owned_write = dup(fds[1]);
    assert(owned_read >= 0 && owned_write >= 0);
    BootstrapWorkerChannels channels(owned_write, owned_read);
    channels.close_all();
    assert(fcntl(owned_read, F_GETFD) == -1 && fcntl(owned_write, F_GETFD) == -1);
    int reused = dup(fds[0]); assert(reused >= 0);
    channels.close_all();
    assert(fcntl(reused, F_GETFD) >= 0 && fcntl(fds[1], F_GETFD) >= 0);
    close(reused); close(fds[0]); close(fds[1]);

    if (argc == 2) {
        std::ifstream input(argv[1], std::ios::binary);
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
        BootstrapWorkerBinding decoded;
        assert(bootstrap_worker_decode(bytes.data(), bytes.size(), "WKSC", &decoded));
        assert(decoded == expected);
        assert(!bootstrap_worker_decode(bytes.data(), bytes.size()-1, "WKSC", &decoded));
        assert(!bootstrap_worker_decode(bytes.data(), bytes.size()+1, "WKSC", &decoded));
        assert(!bootstrap_worker_decode(bytes.data(), bytes.size(), "WKSS", &decoded));
        bytes[4] = bytes[5] = bytes[6] = bytes[7] = 0;
        assert(!bootstrap_worker_decode(bytes.data(), bytes.size(), "WKSC", &decoded));
    }
    puts("worker dispatch, cancellation, original-lock progress, once and owned FD reuse: passed");
}
catch (...) {
    return 1;
}
