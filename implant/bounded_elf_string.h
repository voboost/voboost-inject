#pragma once

#include <cstddef>
#include <cstring>

inline bool bounded_elf_string_equals(const char *value, const char *end,
                                      const char *expected) {
    if (!value || !end || !expected || value > end) {
        return false;
    }
    const size_t available = static_cast<size_t>(end - value);
    const void *terminator = memchr(value, '\0', available);
    if (!terminator) {
        return false;
    }
    const size_t actual_size = static_cast<const char *>(terminator) - value;
    const size_t expected_size = strlen(expected);
    return actual_size == expected_size && memcmp(value, expected, actual_size) == 0;
}

inline bool exact_library_basename(const char *path, const char *expected) {
    if (!path || !expected || !*path || !*expected || strchr(expected, '/')) {
        return false;
    }
    const char *slash = strrchr(path, '/');
    const char *basename = slash ? slash + 1 : path;
    return strcmp(basename, expected) == 0;
}
