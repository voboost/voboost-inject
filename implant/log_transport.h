#ifndef VOBOOST_LOG_TRANSPORT_H
#define VOBOOST_LOG_TRANSPORT_H

#include "pipe_record_format.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

/* Caller holds the uplink mutex. Android pipe records fit PIPE_BUF (4096),
* so a nonblocking write either transfers the entire record or fails. This
* fixed queue never waits for pipe capacity and never allocates on a callback.
* Recovery requires another producer call; process death can lose pending
* records, so missing observations must still be treated as unavailable. */
class LogTransport {
struct Record {
    std::array<char, 4096> bytes{};
    size_t size = 0;
};
struct Queue {
    std::array<Record, 8> records{};
    size_t head = 0;
    size_t count = 0;
    bool push(const char *bytes, size_t size) {
        if (count == records.size()) {
            return false;
        }
        auto &record = records[(head + count++) % records.size()];
        memcpy(record.bytes.data(), bytes, size);
        record.size = size;
        return true;
    }
};
Queue errors;
Queue infos;
std::array<uint64_t, 3> dropped{};

void drop(int level) {
    auto &count = dropped[static_cast<size_t>(level - 1)];
    if (count != std::numeric_limits<uint64_t>::max()) {
        ++count;
    }
}

public:
/* A new endpoint cannot attribute queued records from its predecessor.
 * Account for discarded pending records; the unattributed implant receipt
 * may report these aggregate losses after a later channel recovery. */
void abandon_pending() {
    for (size_t i = 0; i < errors.count; ++i) {
        drop(1);
    }
    for (size_t i = 0; i < infos.count; ++i) {
        drop(2);
    }
    errors.head = errors.count = 0;
    infos.head = infos.count = 0;
}

/* The writer returns true only for a complete atomic write. At most one
 * recovery receipt, four queued records and one DEBUG record are written.
 * DEBUG cannot consume newly available capacity ahead of critical records.
 * INFO/ERROR overflow is explicitly reported rather than silently lost. */
template <typename Writer>
void submit(int level, long long timestamp, const char *bytes, size_t size,
            Writer write) {
    if (level < 1 || level > 3 || !bytes || size == 0 || size > 4096) {
        return;
    }
    if (level < 3 && !(level == 1 ? errors : infos).push(bytes, size)) {
        drop(level);
    }
    for (unsigned int attempt = 0; attempt < 4; ++attempt) {
        Queue &queue = errors.count ? errors : infos;
        if (!queue.count) {
            break;
        }
        const Record &record = queue.records[queue.head];
        if (!write(record.bytes.data(), record.size)) {
            if (level == 3) {
                drop(level);
            }
            return;
        }
        queue.head = (queue.head + 1) % queue.records.size();
        --queue.count;
    }
    if (errors.count || infos.count) {
        if (level == 3) {
            drop(level);
        }
        return;
    }
    if (dropped[0] || dropped[1] || dropped[2]) {
        char message[256];
        snprintf(message, sizeof(message),
                 "log.transport.dropped error=%llu info=%llu debug=%llu",
                 static_cast<unsigned long long>(dropped[0]),
                 static_cast<unsigned long long>(dropped[1]),
                 static_cast<unsigned long long>(dropped[2]));
        char receipt[512];
        int length = format_pipe_record(receipt, sizeof(receipt), 'L', timestamp,
                                        "implant", "1", message);
        if (!write(receipt, static_cast<size_t>(length))) {
            if (level == 3) {
                drop(level);
            }
            return;
        }
        dropped.fill(0);
    }
    if (level == 3 && !write(bytes, size)) {
        drop(level);
    }
}
};

#endif
