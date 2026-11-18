#ifndef VOBOOST_PIPE_RECORD_FORMAT_H
#define VOBOOST_PIPE_RECORD_FORMAT_H

#include <cstddef>
#include <cstdio>
#include <cstring>

inline int format_pipe_record(char *buffer, size_t capacity, char type, long long timestamp,
                              const char *source, const char *field3, const char *field4) {
    if (!buffer || capacity < 2 || !source || !field3 || !field4) {
        return -1;
    }
    int length = snprintf(buffer, capacity, "%c|%lld|%s|%s|", type, timestamp, source, field3);
    if (length < 0 || static_cast<size_t>(length) >= capacity) {
        return -1;
    }
    const char *p = field4;
    for (; *p && static_cast<size_t>(length) < capacity - 2; ++p) {
        buffer[length++] = *p == '\n' ? '\r' : *p;
    }
    if (*p && type == 'S') {
        return -1; // A truncated status JSON is never a valid snapshot.
    }
    buffer[length++] = '\n';
    return length;
}

inline int format_status_record(char *buffer, size_t capacity, long long timestamp,
                                const char *process, const char *document) {
    if (!process || !document || !process[0] || !document[0]
        || strnlen(process, 256) > 255 || strnlen(document, 64 * 1024 + 1) > 64 * 1024) {
        return -1;
    }
    return format_pipe_record(buffer, capacity, 'S', timestamp, process, "snapshot", document);
}

#endif
