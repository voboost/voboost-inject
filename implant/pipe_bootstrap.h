#pragma once

#include <cstdint>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <vector>

struct PipeBootstrapFile { std::string name; std::vector<uint8_t> bytes; };
struct PipeBootstrapEnvelope { std::string manifest; std::vector<PipeBootstrapFile> files; };

// One signed release may contain files for many processes, but one target is
// never allowed to receive more than this aggregate payload. Keep synchronized
// with daemon::bootstrap_pipe::MAX_PROCESS_PAYLOAD_BYTES.
static constexpr uint64_t PIPE_BOOTSTRAP_MAX_PROCESS_PAYLOAD = 64ULL * 1024ULL * 1024ULL;

/* Overall deadline for the whole envelope read. This runs on the ptrace-
 * hijacked thread of the TARGET process: if the daemon dies or stalls mid-
 * write, the host app's thread must not hang forever. Envelope delivery is
 * a boot-time operation bounded by the daemon writer; 10 s is orders of
 * magnitude above the normal <1 s completion. */
inline bool pipe_deadline_init(struct timespec *dl) {
    if (!dl || clock_gettime(CLOCK_MONOTONIC, dl) != 0) {
        return false;
    }
    dl->tv_sec += 10;
    return true;
}
inline bool pipe_deadline_passed(const struct timespec *dl) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec > dl->tv_sec ||
           (now.tv_sec == dl->tv_sec && now.tv_nsec >= dl->tv_nsec);
}

/* Milliseconds until the deadline, clamped to [0, 1000] for poll(). */
inline int pipe_deadline_ms_left_at(const struct timespec *dl,
                                    const struct timespec *now,
                                    bool clock_ok) {
    if (!dl || !now || !clock_ok) {
        return -1;
    }
    if (now->tv_sec > dl->tv_sec
        || (now->tv_sec == dl->tv_sec && now->tv_nsec >= dl->tv_nsec)) {
        return 0;
    }
    time_t seconds = dl->tv_sec - now->tv_sec;
    if (seconds > 1) {
        return 1000;
    }
    long nanoseconds = dl->tv_nsec - now->tv_nsec;
    if (seconds == 1) {
        nanoseconds += 1000000000L;
    }
    long milliseconds = (nanoseconds + 999999L) / 1000000L;
    return milliseconds > 1000 ? 1000 : static_cast<int>(milliseconds);
}

inline int pipe_deadline_ms_left(const struct timespec *dl) {
    struct timespec now {};
    int result = clock_gettime(CLOCK_MONOTONIC, &now);
    return pipe_deadline_ms_left_at(dl, &now, result == 0);
}

// One bounded poll slice. Callers must recheck their cancellation state on Retry.
enum class PipePollResult { Ready, Retry, Failed };
inline PipePollResult pipe_poll_writable(int fd, const struct timespec *deadline) {
    int timeout = pipe_deadline_ms_left(deadline);
    if (timeout <= 0) {
        return PipePollResult::Failed;
    }
    struct pollfd output = {fd, POLLOUT, 0};
    int result = poll(&output, 1, timeout);
    if (result == 0 || (result < 0 && errno == EINTR)) {
        return PipePollResult::Retry;
    }
    if (result < 0 || output.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return PipePollResult::Failed;
    }
    return PipePollResult::Ready;
}

inline bool pipe_read_exact(int fd, void *target, size_t size,
                            const struct timespec *dl) {
    auto *out = static_cast<uint8_t *>(target);
    while (size) {
        /* Poll before reading so an idle or dead writer cannot bypass
         * the overall deadline. */
        struct pollfd pfd = { fd, POLLIN, 0 };
        int timeout_ms = pipe_deadline_ms_left(dl);
        if (timeout_ms <= 0) {
            return false;
        }
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0 && errno == EINTR) {
            continue;
        }
        if (pr == 0) {
            continue;
        }
        if (pr < 0) {
            return false;
        }
        ssize_t count = read(fd, out, size);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (count == 0) {
            /* EOF: every writer closed before the envelope completed. Mark
             * it explicitly so read_pipe_bootstrap_diag can tell a dead
             * writer apart from a validation failure. */
            errno = ENODATA;
            return false;
        }
        if (count < 0) {
            return false;
        }
        out += count;
        size -= static_cast<size_t>(count);
    }
    return true;
}

inline uint16_t pipe_le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | static_cast<uint16_t>(p[1]) << 8;
}
inline uint32_t pipe_le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}
inline uint64_t pipe_le64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return value;
}

/* Diagnostics for a failed envelope read: which stage failed and the errno
   observed there (0 when the failure was a validation, not a syscall). Lets
   the daemon distinguish EOF (writer died mid-stream) from a corrupt or
   unrepresentable envelope from a bad fd. */
struct PipeBootstrapReadDiag {
    const char *stage;
    int error;
};

inline bool read_pipe_bootstrap_diag(int fd, PipeBootstrapEnvelope *out,
                                     PipeBootstrapReadDiag *diag) {
    struct timespec dl;
    if (!pipe_deadline_init(&dl)) {
        if (diag) {
            diag->stage = "deadline-init"; diag->error = errno;
        }
        return false;
    }
    if (!out) {
        if (diag) {
            diag->stage = "null-envelope"; diag->error = 0;
        }
        return false;
    }
    // Reset the envelope up front so every false return (including early
    // ones before any resize) leaves out empty - a retry never reuses stale
    // entries from a prior partial/failed read.
    out->manifest.clear();
    out->files.clear();
    if (fd < 0) {
        if (diag) {
            diag->stage = "negative-fd"; diag->error = EBADF;
        }
        return false;
    }
    uint8_t header[24];
    if (!pipe_read_exact(fd, header, sizeof(header), &dl)) {
        if (diag) {
            diag->stage = "header-read"; diag->error = errno;
        }
        return false;
    }
    if (memcmp(header, "VOBOOST1", 8) != 0) {
        if (diag) {
            diag->stage = "header-magic"; diag->error = 0;
        }
        return false;
    }
    uint32_t manifest_size = pipe_le32(header + 8);
    uint32_t file_count = pipe_le32(header + 12);
    uint64_t total = pipe_le64(header + 16);
    if (!manifest_size || manifest_size > 2 * 1024 * 1024 || !file_count || file_count > 64 ||
        !total || total > PIPE_BOOTSTRAP_MAX_PROCESS_PAYLOAD) {
        if (diag) {
            diag->stage = "header-bounds"; diag->error = 0;
        }
        return false;
    }
    out->manifest.resize(manifest_size);
    if (!pipe_read_exact(fd, out->manifest.data(), manifest_size, &dl)) {
        if (diag) {
            diag->stage = "manifest-read"; diag->error = errno;
        }
        out->manifest.clear();
        out->files.clear();
        return false;
    }
    uint64_t observed = 0;
    for (uint32_t index = 0; index < file_count; ++index) {
        uint8_t name_size_bytes[2];
        if (!pipe_read_exact(fd, name_size_bytes, 2, &dl)) {
            if (diag) {
                diag->stage = "file-name-length-read"; diag->error = errno;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        uint16_t name_size = pipe_le16(name_size_bytes);
        if (!name_size || name_size > 255) {
            if (diag) {
                diag->stage = "file-name-length-bounds"; diag->error = 0;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        PipeBootstrapFile file;
        file.name.resize(name_size);
        if (!pipe_read_exact(fd, file.name.data(), name_size, &dl)) {
            if (diag) {
                diag->stage = "file-name-read"; diag->error = errno;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        uint8_t size_bytes[8];
        if (!pipe_read_exact(fd, size_bytes, 8, &dl)) {
            if (diag) {
                diag->stage = "file-size-read"; diag->error = errno;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        uint64_t size = pipe_le64(size_bytes);
        if (!size || size > 67108864ULL || observed + size > total) {
            if (diag) {
                diag->stage = "file-size-bounds"; diag->error = 0;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        file.bytes.resize(static_cast<size_t>(size));
        if (!pipe_read_exact(fd, file.bytes.data(), file.bytes.size(), &dl)) {
            if (diag) {
                diag->stage = "file-bytes-read"; diag->error = errno;
            }
            out->manifest.clear();
            out->files.clear();
            return false;
        }
        observed += size;
        out->files.push_back(std::move(file));
    }
    if (observed != total) {
        if (diag) {
            diag->stage = "payload-total-mismatch"; diag->error = 0;
        }
        out->manifest.clear();
        out->files.clear();
        return false;
    }
    return true;
}

inline bool read_pipe_bootstrap(int fd, PipeBootstrapEnvelope *out) {
    return read_pipe_bootstrap_diag(fd, out, nullptr);
}
