#ifndef VBI_DIAGNOSTIC_TIME_H
#define VBI_DIAGNOSTIC_TIME_H

#include <errno.h>
#include <stdint.h>
#include <time.h>

/* A failed clock read is explicitly unavailable (zero), never a wall clock. */
static inline uint64_t vbi_diagnostic_millis(void) {
    int saved_errno = errno;
    struct timespec now;
    int result = clock_gettime(CLOCK_MONOTONIC, &now);
    errno = saved_errno;
    return result == 0 ? (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 : 0;
}

static inline uint64_t vbi_diagnostic_elapsed(uint64_t start, uint64_t now) {
    return start != 0 && now >= start ? now - start : 0;
}

#endif
