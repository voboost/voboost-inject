#include "event_uplink.h"
#include "pipe_record_format.h"
#include "hook_stage_record.h"
#include "sigpipe_safe_write.h"
#include <cassert>
#include <fcntl.h>
#include <string>

struct Pipe {
    int fd[2];
    Pipe() {
        assert(pipe(fd) == 0);
        for (int end : fd) {
            assert(fcntl(end, F_SETFL, O_NONBLOCK) == 0);
        }
    }
    ~Pipe() {
        close(fd[0]);
        close(fd[1]);
    }
    std::string read_all() {
        std::string result;
        char bytes[4096];
        ssize_t size;
        while ((size = read(fd[0], bytes, sizeof(bytes))) > 0) {
            result.append(bytes, size);
        }
        assert(size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        return result;
    }
};

static void final_ready_snapshot_survives_a_pending_event_without_future_publications() {
    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const void *bytes, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], bytes, size);
                  };
    const std::string first = "S|1|com.qinggan.canbus.service|snapshot|"
                              "{\"FEV\":\"initial-sync\",\"PW\":\"ready\"}\n";
    const std::string ready = "S|2|com.qinggan.canbus.service|snapshot|"
                              "{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(queue.write_status(first.data(), first.size(), writer) == static_cast<ssize_t>(first.size()));
    assert(pipe.read_all() == first);
    assert(queue.enqueue(1, "FEV", "CAN", "mode:2"));
    // This is the production status path. A pending E rejects the one-shot S
    // even when the actual pipe is empty; there are no later status callbacks.
    (void)queue.write_status(ready.data(), ready.size(), writer);
    std::string observed = pipe.read_all();
    for (size_t tick = 0; queue.pending() && tick < 100; ++tick) {
        assert(queue.flush(writer));
        observed += pipe.read_all();
    }
    assert(!queue.pending());
    assert(observed == "E|1|FEV|CAN|mode:2\n" + ready
           || observed == ready + "E|1|FEV|CAN|mode:2\n");
}

static void status_retries_after_full_pipe_without_another_publication() {
    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const void *bytes, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], bytes, size);
                  };
    std::string filler(4096, 'f');
    size_t filled = 0;
    ssize_t written;
    while ((written = writer(filler.data(), filler.size())) > 0) {
        filled += written;
    }
    assert(filled && errno == EAGAIN);
    const std::string ready = "S|3|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(queue.write_status(ready.data(), ready.size(), writer) == static_cast<ssize_t>(ready.size()));
    assert(queue.pending());
    assert(pipe.read_all() == std::string(filled, 'f'));
    // The existing watcher tick is sufficient; no future event/status is needed.
    assert(queue.flush(writer));
    assert(!queue.pending() && pipe.read_all() == ready);
}

static void partial_status_retains_its_suffix_and_only_the_latest_successor() {
    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const void *bytes, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], bytes, size);
                  };
    bool first = true;
    auto blocked = [&](const void *bytes, size_t size) -> ssize_t {
                       if (!first) {
                           errno = EAGAIN; return -1;
                       }
                       first = false;
                       return writer(bytes, size > 7 ? 7 : size);
                   };
    const std::string initial = "S|1|canbus|snapshot|{\"FEV\":\"initial-sync\",\"PW\":\"ready\"}\n";
    const std::string intermediate = "S|2|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"initial-sync\"}\n";
    const std::string ready = "S|3|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(queue.write_status(initial.data(), initial.size(), blocked) == static_cast<ssize_t>(initial.size()));
    std::string observed = pipe.read_all();
    assert(observed == initial.substr(0, 7));
    assert(queue.write_status(intermediate.data(), intermediate.size(), blocked) == static_cast<ssize_t>(intermediate.size()));
    assert(queue.write_status(ready.data(), ready.size(), blocked) == static_cast<ssize_t>(ready.size()));
    assert(queue.enqueue(4, "FEV", "CAN", "next"));
    assert(queue.write_other("L|other\n", 8, writer) == -1 && errno == EAGAIN);
    assert(queue.flush(writer));
    observed += pipe.read_all();
    assert(!queue.pending());
    assert(observed == initial + ready + "E|4|FEV|CAN|next\n");
}

static void pending_status_follows_current_partial_event_before_the_next_event() {
    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const void *bytes, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], bytes, size);
                  };
    bool first = true;
    auto blocked = [&](const void *bytes, size_t size) -> ssize_t {
                       if (!first) {
                           errno = EAGAIN; return -1;
                       }
                       first = false;
                       return writer(bytes, size > 3 ? 3 : size);
                   };
    assert(queue.enqueue(1, "FEV", "CAN", "current"));
    assert(queue.flush(blocked));
    std::string observed = pipe.read_all();
    assert(observed == "E|1");
    assert(queue.enqueue(2, "PW", "CAN", "next"));
    const std::string ready = "S|3|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(queue.write_status(ready.data(), ready.size(), blocked) == static_cast<ssize_t>(ready.size()));
    assert(queue.flush(writer));
    observed += pipe.read_all();
    assert(!queue.pending());
    assert(observed == "E|1|FEV|CAN|current\n" + ready + "E|2|PW|CAN|next\n");
}

static void status_epoch_bounds_and_closed_endpoint_never_leak_or_claim_delivery() {
    Pipe old, replacement;
    EventUplink queue;
    queue.bind(old.fd[1], 1);
    auto blocked = [](const void *, size_t) -> ssize_t {
                       errno = EAGAIN; return -1;
                   };
    const std::string stale = "S|1|old|snapshot|old\n", current = "S|2|new|snapshot|ready\n";
    assert(queue.write_status(stale.data(), stale.size(), blocked) == static_cast<ssize_t>(stale.size()));
    queue.bind(old.fd[1], 2);
    assert(!queue.pending());
    assert(queue.write_status(stale.data(), stale.size(), blocked) == static_cast<ssize_t>(stale.size()));
    queue.bind(replacement.fd[1], 2);
    assert(!queue.pending());
    auto writer = [&](const void *bytes, size_t size) {
                      return sigpipe_safe_write(replacement.fd[1], bytes, size);
                  };
    std::string oversized(EventUplink::max_status_record + 1, 's');
    oversized[0] = 'S'; oversized[1] = '|'; oversized.back() = '\n';
    assert(queue.write_status(oversized.data(), oversized.size(), writer) == -1);
    assert(!queue.pending() && replacement.read_all().empty());
    assert(queue.write_status(current.data(), current.size(), writer) == static_cast<ssize_t>(current.size()));
    assert(replacement.read_all() == current && old.read_all().empty());
    close(replacement.fd[0]); replacement.fd[0] = -1;
    assert(queue.write_status(current.data(), current.size(), writer) == -1);
    assert(!queue.pending());
}

static void status_formatter_rejects_truncation_without_changing_log_bounds() {
    char bytes[4096];
    const std::string prefix = "S|1|canbus|snapshot|";
    std::string exact(sizeof(bytes) - prefix.size() - 2, 'x');
    int size = format_pipe_record(bytes, sizeof(bytes), 'S', 1, "canbus", "snapshot", exact.c_str());
    assert(size == sizeof(bytes) - 1);
    assert(std::string(bytes, size) == prefix + exact + "\n");
    exact += 'x';
    assert(format_pipe_record(bytes, sizeof(bytes), 'S', 1, "canbus", "snapshot", exact.c_str()) == -1);
    assert(format_pipe_record(bytes, sizeof(bytes), 'L', 1, "canbus", "3", std::string(8192, 'x').c_str()) == sizeof(bytes) - 1);
}

static void exact_64k_json_status_and_early_bootstrap_keep_the_whole_frame() {
    const std::string prefix = "{\"schemaVersion\":1,\"process\":\"com.qinggan.canbus.service\","
                               "\"agents\":[{\"id\":\"FEV\",\"state\":\"active\"},"
                               "{\"id\":\"PW\",\"state\":\"active\"}],\"details\":{\"padding\":\"";
    const std::string suffix = "\"}}";
    std::string document = prefix + std::string(StatusUplink::max_document - prefix.size() - suffix.size(), 'x') + suffix;
    assert(document.size() == StatusUplink::max_document);
    std::array<char, StatusUplink::max_record> bytes{};
    int size = format_status_record(bytes.data(), bytes.size(), 123, "com.qinggan.canbus.service", document.c_str());
    assert(size > 4096);
    std::string expected = "S|123|com.qinggan.canbus.service|snapshot|" + document + "\n";
    assert(std::string(bytes.data(), size) == expected);
    document += ' ';
    assert(format_status_record(bytes.data(), bytes.size(), 123, "com.qinggan.canbus.service", document.c_str()) == -1);
    assert(format_status_record(bytes.data(), bytes.size(), 123, std::string(256, 'p').c_str(), "{}") == -1);

    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const void *record, size_t count) {
                      return sigpipe_safe_write(pipe.fd[1], record, count);
                  };
    assert(queue.write_status(expected.data(), expected.size(), writer) == static_cast<ssize_t>(expected.size()));
    std::string actual = pipe.read_all();
    assert(actual.size() > 0 && actual.size() < expected.size());
    for (size_t tick = 0; queue.pending() && tick < 1000; ++tick) {
        assert(queue.flush(writer));
        actual += pipe.read_all();
    }
    assert(!queue.pending() && actual == expected);

    // The real BootstrapWorker capsule uses this same helper before Ready. It
    // coalesces before publication, preserves a partial prefix, and cannot
    // publish Ready until both the current frame and its latest successor drain.
    StatusUplink bootstrap;
    assert(bootstrap.submit(expected.data(), expected.size()));
    assert(bootstrap.flush_one(writer) == 1 && bootstrap.partial());
    actual = pipe.read_all();
    const std::string next = "S|124|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(bootstrap.submit(next.data(), next.size()));
    for (size_t tick = 0; bootstrap.pending() && tick < 1000; ++tick) {
        assert(bootstrap.flush_one(writer) >= 0);
        actual += pipe.read_all();
    }
    assert(!bootstrap.pending() && actual == expected + next);
}

static void early_bootstrap_status_waits_for_the_current_partial_event() {
    Pipe pipe;
    EventUplink resident;
    StatusUplink bootstrap;
    resident.bind(pipe.fd[1], 1);
    auto writer = [&](const void *record, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], record, size);
                  };
    bool first = true, blocked = true;
    auto partial = [&](const void *record, size_t size) -> ssize_t {
                       if (!first && blocked) {
                           errno = EAGAIN; return -1;
                       }
                       size_t limit = first && size > 3 ? 3 : size;
                       first = false;
                       return writer(record, limit);
                   };
    assert(resident.enqueue(1, "FEV", "CAN", "current"));
    assert(resident.flush(partial) && resident.partial());
    assert(resident.enqueue(2, "PW", "CAN", "next"));
    std::string actual = pipe.read_all();
    const std::string ready = "S|3|canbus|snapshot|{\"FEV\":\"ready\",\"PW\":\"ready\"}\n";
    assert(bootstrap.submit(ready.data(), ready.size()));
    auto tick = [&] {
                    if (!bootstrap.partial() && resident.partial()) {
                        assert(resident.flush(partial, 1));
                        if (resident.partial()) {
                            return;
                        }
                    }
                    assert(bootstrap.flush_one(partial) >= 0);
                };
    tick();
    assert(bootstrap.pending() && pipe.read_all().empty());
    blocked = false;
    tick();
    actual += pipe.read_all();
    assert(!bootstrap.pending() && resident.pending());
    assert(resident.flush(writer));
    actual += pipe.read_all();
    assert(actual == "E|1|FEV|CAN|current\n" + ready + "E|2|PW|CAN|next\n");
}

int main() {
    early_bootstrap_status_waits_for_the_current_partial_event();
    exact_64k_json_status_and_early_bootstrap_keep_the_whole_frame();
    status_formatter_rejects_truncation_without_changing_log_bounds();
    final_ready_snapshot_survives_a_pending_event_without_future_publications();
    status_retries_after_full_pipe_without_another_publication();
    partial_status_retains_its_suffix_and_only_the_latest_successor();
    pending_status_follows_current_partial_event_before_the_next_event();
    status_epoch_bounds_and_closed_endpoint_never_leak_or_claim_delivery();
    Pipe pipe;
    EventUplink queue;
    queue.bind(pipe.fd[1], 1);
    auto writer = [&](const char *bytes, size_t size) {
                      return sigpipe_safe_write(pipe.fd[1], bytes, size);
                  };
    // A fully saturated real nonblocking pipe retains the entire event.
    std::string filler(4096, 'f');
    size_t filled = 0;
    ssize_t written;
    while ((written = writer(filler.data(), filler.size())) > 0) {
        filled += written;
    }
    assert(filled > 0 && errno == EAGAIN);
    std::string payload = "section:{\"identities\":[";
    for (size_t i = 0; i < 256; ++i) {
        if (i) {
            payload += ',';
        }
        payload += '"' + std::string(189, 'a') + std::to_string(100 + i) + '"';
    }
    payload += "]}";
    assert(queue.enqueue(923456789, "launcher", "launcher-section-visibility", payload.c_str()));
    assert(queue.flush(writer));
    assert(queue.pending());
    char freed[4096];
    assert(read(pipe.fd[0], freed, sizeof(freed)) == sizeof(freed));
    assert(queue.flush(writer));
    std::string initial = pipe.read_all();
    assert(initial.substr(0, filled - sizeof(freed)) == std::string(filled - sizeof(freed), 'f'));
    initial.erase(0, filled - sizeof(freed));
    assert(!initial.empty() && queue.pending());
    // The real hook callback must not splice L bytes after this short E write.
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    assert(!write_hook_stage_record(pipe.fd[1], &mutex, 123, "mutation-end", 5, 6, 7,
                                    [&](int fd, const void *bytes, size_t size) {
        return queue.write_other(bytes, size, [fd](const void *record, size_t length) {
            return sigpipe_safe_write(fd, record, length);
        });
    }));
    assert(pipe.read_all().empty());
    assert(pthread_mutex_destroy(&mutex) == 0);


    std::string expected = "E|923456789|launcher|launcher-section-visibility|" + payload + "\n";
    assert(queue.enqueue(923456790, "settings", "checkbox", "next:true"));
    expected += "E|923456790|settings|checkbox|next:true\n";
    std::string actual = initial;
    bool partial = !initial.empty();
    for (size_t tick = 0; queue.pending() && tick < 1000; ++tick) {
        assert(queue.flush(writer));
        actual += pipe.read_all();
        if (!actual.empty() && queue.pending()) {
            partial = true;
        }
    }
    assert(!queue.pending() && actual == expected);
    assert(partial);
    // Saturation and fixed FIFO capacity report failure without overwriting.
    for (int i = 0; i < 4; ++i) {
        assert(queue.enqueue(i + 1, "s", "t", "p"));
    }
    assert(!queue.enqueue(5, "s", "t", "p"));
    queue.bind(pipe.fd[1], 2);
    assert(!queue.pending());
    std::string huge(EventUplink::max_record, 'x');
    assert(!queue.enqueue(1, "s", "t", huge.c_str()));
    // Epoch replacement discards a partially transferred old record.
    assert(queue.enqueue(10, "s", "t", payload.c_str()));
    size_t offset = 0;
    assert(queue.flush([&](const char *bytes, size_t size) -> ssize_t {
        if (offset) {
            errno = EAGAIN; return -1;
        }
        ssize_t sent = writer(bytes, size > 4096 ? 4096 : size);
        if (sent > 0) {
            offset += sent;
        }
        return sent;
    }));
    assert(offset > 0 && queue.pending());
    assert(queue.write_other("L|other\n", 8, [&](const void *bytes, size_t size) {
        return sigpipe_safe_write(pipe.fd[1], bytes, size);
    }) == -1);
    assert(errno == EAGAIN);
    assert(pipe.read_all() == ("E|10|s|t|" + payload + "\n").substr(0, offset));
    Pipe replacement;
    queue.bind(replacement.fd[1], 3);
    assert(!queue.pending());
    assert(queue.enqueue(11, "s", "t", "new"));
    assert(queue.flush([&](const char *bytes, size_t size) {
        return sigpipe_safe_write(replacement.fd[1], bytes, size);
    }));
    assert(replacement.read_all() == "E|11|s|t|new\n");
    // Closed endpoints cannot turn a queued event into successful delivery.
    assert(queue.enqueue(12, "s", "t", "closed"));
    close(replacement.fd[0]);
    replacement.fd[0] = -1;
    assert(!queue.flush([&](const char *bytes, size_t size) {
        return sigpipe_safe_write(replacement.fd[1], bytes, size);
    }));
    assert(!queue.pending());
    assert(!queue.enqueue(13, "s", "t", "closed"));
    std::puts("PASS: eight status transport scenarios including exact64KiB JSON/early-bootstrap and existing event FIFO/partial/EOF regressions");

}
