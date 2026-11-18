#ifndef VOBOOST_NATIVE_DIAGNOSTIC_H
#define VOBOOST_NATIVE_DIAGNOSTIC_H
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Private helper stderr is concurrently drained by the daemon. Stdout is IPC.
 * One bounded JSONL per write, no allocations or private diagnostic files. */
static inline size_t vbi_diag_quote(char *out, size_t cap, const char *text) {
    size_t n = 0;
    if (cap < 3) {
        return 0;
    }
    out[n++] = '"';
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        /* Preserve complete valid UTF-8, sanitize arbitrary native bytes. */
        if (*p >= 128) {
            size_t width = *p >= 0xc2 && *p <= 0xdf ? 2
                : *p >= 0xe0 && *p <= 0xef ? 3 : *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
            int valid = width != 0;
            for (size_t i = 1; valid && i < width; ++i) {
                if (!p[i] || (p[i] & 0xc0) != 0x80) {
                    valid = 0;
                }
            }
            if (valid && ((*p == 0xe0 && p[1] < 0xa0) || (*p == 0xed && p[1] >= 0xa0)
                          || (*p == 0xf0 && p[1] < 0x90) || (*p == 0xf4 && p[1] >= 0x90))) {
                valid = 0;
            }
            if (n + (valid ? width : 1) + 2 > cap) {
                break;
            }
            if (valid) {
                memcpy(out + n, p, width);
                n += width;
                p += width - 1;
            } else {
                out[n++] = '?';
            }
            continue;
        }
        const char hex[] = "0123456789abcdef";
        size_t need = (*p < 32 || *p == 127) ? 6 : (*p == '"' || *p == '\\') ? 2 : 1;
        if (n + need + 2 > cap) {
            break;
        }
        if (need == 6) {
            out[n++] = '\\';
            out[n++] = 'u';
            out[n++] = '0';
            out[n++] = '0';
            out[n++] = hex[*p >> 4];
            out[n++] = hex[*p & 15];
        } else {
            if (need == 2) {
                out[n++] = '\\';
            }
            out[n++] = (char)*p;
        }
    }
    out[n++] = '"';
    out[n] = 0;
    return n;
}
static inline void vbi_native_diagnostic(const char *level, const char *component,
                                         const char *fmt, ...) {
    int saved_errno = errno;
    if (!strcmp(level, "debug")) {
        const char *enabled = getenv("VOBOOST_HELPER_DEBUG");
        if (!enabled || strcmp(enabled, "1")) {
            errno = saved_errno;
            return;
        }
    }
    char message[256], quoted[1600], record[2048];
    va_list args;
    va_start(args, fmt);
    int count = vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    if (count >= 0) {
        /* A truncated diagnostic must not end in a partial UTF-8 codepoint. */
        if ((size_t)count >= sizeof(message)) {
            size_t end = strlen(message);
            while (end && ((unsigned char)message[end - 1] & 0xc0) == 0x80) {
                --end;
            }
            if (end && (unsigned char)message[end - 1] >= 0xc0) {
                --end;
            }
            message[end] = 0;
        }
        vbi_diag_quote(quoted, sizeof(quoted), message);
        int n = snprintf(record, sizeof(record),
                         "{\"level\":\"%s\",\"component\":\"%s\",\"message\":%s,\"fields\":{}}\n",
                         level, component, quoted);
        if (n > 0 && (size_t)n < sizeof(record)) {
            ssize_t result;
            do {
                result = write(STDERR_FILENO, record, (size_t)n);
            } while (result < 0 && errno == EINTR);
        }
    }
    errno = saved_errno;
}
#endif
