#ifndef VOBOOST_HOOK_STAGE_RECORD_H
#define VOBOOST_HOOK_STAGE_RECORD_H

#include "pipe_record_format.h"
#include "sigpipe_safe_write.h"

#include <cstdint>
#include <fcntl.h>
#include <pthread.h>

/* Diagnostics cannot wait on a frozen peer or a full pipe. No JNI, heap
 * allocation, descriptor flag mutation or process signal-disposition change. */
template <typename Writer = decltype(&sigpipe_safe_write)>
inline bool write_hook_stage_record(int fd, pthread_mutex_t *mutex, long long timestamp,
                                    const char *stage, int pid, long tid, uint64_t elapsed,
                                    Writer write = sigpipe_safe_write) {
    if (fd < 0 || !mutex || !stage || pthread_mutex_trylock(mutex) != 0) {
        return false;
    }
    bool written = false;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0 && (flags & O_NONBLOCK)) {
        char message[256];
        int length = snprintf(message, sizeof(message),
                              "lsplant-stage: stage=%s pid=%d tid=%ld elapsed_ms=%llu",
                              stage, pid, tid, static_cast<unsigned long long>(elapsed));
        if (length >= 0 && static_cast<size_t>(length) < sizeof(message)) {
            char record[512];
            length = format_pipe_record(record, sizeof(record), 'L', timestamp,
                                        "implant", "2", message);
            if (length > 0) {
                written = write(fd, record, static_cast<size_t>(length)) == length;
            }
        }
    }
    pthread_mutex_unlock(mutex);
    return written;
}

#endif
