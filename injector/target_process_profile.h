#ifndef VBI_TARGET_PROCESS_PROFILE_H
#define VBI_TARGET_PROCESS_PROFILE_H

#include <string.h>

static inline int vbi_target_app_process_path_matches(const char *path, int bitness) {
    if (!path) {
        return 0;
    }
    if (bitness == 64) {
        return strcmp(path, "/system/bin/app_process64") == 0
               || strcmp(path, "/system/bin/app_process64_real") == 0;
    }
    if (bitness == 32) {
        return strcmp(path, "/system/bin/app_process32") == 0
               || strcmp(path, "/system/bin/app_process32_real") == 0;
    }
    return 0;
}

#endif
