#ifndef VOBOOST_EVENT_UPLINK_H
#define VOBOOST_EVENT_UPLINK_H

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>

// Existing daemon contract: 64 KiB JSON plus a bounded process/header. One
// partial frame is immutable; only its successor may be coalesced.
class StatusUplink {
struct Record {
    std::array<char, 64 * 1024 + 512> bytes{};
    size_t size = 0;
    size_t offset = 0;
};
Record current, latest;
public:
static constexpr size_t max_document = 64 * 1024;
static constexpr size_t max_source = 255;
static constexpr size_t max_record = 64 * 1024 + 512;
void reset() {
    current.size = current.offset = latest.size = latest.offset = 0;
}
bool pending() const {
    return current.size != 0;
}
bool partial() const {
    return current.offset != 0;
}
bool submit(const void *bytes, size_t size) {
    const auto *frame = static_cast<const char *>(bytes);
    if (!frame || size < 3 || size > max_record || frame[0] != 'S'
        || frame[1] != '|' || frame[size - 1] != '\n') {
        return false;
    }
    auto &next = partial() ? latest : current;
    memcpy(next.bytes.data(), frame, size);
    next.size = size;
    next.offset = 0;
    if (!partial()) {
        latest.size = latest.offset = 0;
    }
    return true;
}
// One nonblocking write: -1 terminal error, 0 backpressure, 1 progress.
template <typename Writer>
int flush_one(Writer write) {
    if (!pending()) {
        return 1;
    }
    ssize_t written = write(current.bytes.data() + current.offset, current.size - current.offset);
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return 0;
    }
    if (written <= 0 || static_cast<size_t>(written) > current.size - current.offset) {
        if (written >= 0) {
            errno = EIO;
        }
        reset();
        return -1;
    }
    current.offset += static_cast<size_t>(written);
    if (current.offset == current.size) {
        current.size = latest.size;
        current.offset = 0;
        if (latest.size) {
            memcpy(current.bytes.data(), latest.bytes.data(), latest.size);
        }
        latest.size = latest.offset = 0;
    }
    return 1;
}
};

// Caller holds the pipe mutex. E records retain their bounded FIFO; S snapshots
// retain one in-flight frame and one coalesced latest frame. Other writers yield
// while either owns the stream, including between partial writes.
class EventUplink {
struct Record {
    std::array<char, 64 * 1024> bytes{};
    size_t size = 0;
    size_t offset = 0;
};
std::array<Record, 4> records;
StatusUplink status;
size_t head = 0;
size_t count = 0;
int endpoint = -1;
uint32_t epoch = 0;

public:
static constexpr size_t max_record = 64 * 1024;
static constexpr size_t max_status_record = StatusUplink::max_record;

void reset() {
    for (auto &record : records) {
        record.size = 0;
        record.offset = 0;
    }
    status.reset();
    head = count = 0;
    endpoint = -1;
}

void bind(int fd, uint32_t generation) {
    if (endpoint != fd || epoch != generation) {
        reset();
        endpoint = fd;
        epoch = generation;
    }
}

bool pending() const {
    return count != 0 || status.pending();
}

bool partial() const {
    return status.partial() || (count && records[head].offset != 0);
}

bool enqueue(long long request, const char *source, const char *type, const char *payload) {
    if (endpoint < 0 || count == records.size() || !source || !type || !payload) {
        return false;
    }
    // Bound every scan and reject rather than truncate.
    size_t source_size = strnlen(source, max_record);
    size_t type_size = strnlen(type, max_record);
    size_t payload_size = strnlen(payload, max_record);
    char prefix[32];
    int prefix_size = snprintf(prefix, sizeof(prefix), "E|%lld|", request);
    if (prefix_size < 0 || static_cast<size_t>(prefix_size) >= sizeof(prefix)
        || source_size + type_size + payload_size + prefix_size + 3 > max_record) {
        return false;
    }
    auto &record = records[(head + count) % records.size()];
    size_t size = static_cast<size_t>(prefix_size);
    memcpy(record.bytes.data(), prefix, size);
    memcpy(record.bytes.data() + size, source, source_size);
    size += source_size;
    record.bytes[size++] = '|';
    memcpy(record.bytes.data() + size, type, type_size);
    size += type_size;
    record.bytes[size++] = '|';
    for (size_t i = 0; i < payload_size; ++i) {
        record.bytes[size++] = payload[i] == '\n' ? '\r' : payload[i];
    }
    record.bytes[size++] = '\n';
    record.size = size;
    record.offset = 0;
    ++count;
    return true;
}

// Admission into a bounded retry slot is not a daemon acknowledgement.
template <typename Writer>
ssize_t write_status(const void *bytes, size_t size, Writer write) {
    if (endpoint < 0 || !status.submit(bytes, size)) {
        errno = EINVAL;
        return -1;
    }
    if (!flush(write)) {
        return -1;
    }
    return static_cast<ssize_t>(size);
}

// Existing log/RPC/ACK limits stay unchanged; only stream ownership is shared.
template <typename Writer>
ssize_t write_other(const void *bytes, size_t size, Writer write) {
    if (pending()) {
        errno = EAGAIN;
        return -1;
    }
    return write(bytes, size);
}

template <typename Writer>
bool flush(Writer write, size_t max_writes = 4) {
    // At most four writes per tick, never wait for pipe capacity. Complete any
    // partial E before S, then serve S before starting another queued E.
    for (size_t attempt = 0; attempt < records.size() && attempt < max_writes && pending(); ++attempt) {
        bool send_status = status.pending()
                           && (status.partial() || !count || records[head].offset == 0);
        if (send_status) {
            int result = status.flush_one(write);
            if (result < 0) {
                reset(); return false;
            }
            if (!result) {
                return true;
            }
            continue;
        }
        const char *bytes = records[head].bytes.data();
        size_t size = records[head].size;
        size_t offset = records[head].offset;
        ssize_t written = write(bytes + offset, size - offset);
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return true;
        }
        if (written <= 0 || static_cast<size_t>(written) > size - offset) {
            if (written == 0 || written > 0) {
                errno = EIO;
            }
            reset();
            return false;
        }
        offset += static_cast<size_t>(written);
        records[head].offset = offset;
        if (offset == size) {
            records[head].size = records[head].offset = 0;
            head = (head + 1) % records.size();
            --count;
        }
    }
    return true;
}
};

#endif
