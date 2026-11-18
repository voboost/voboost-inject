#pragma once

#include <cstring>

// Optional diagnostics for the two supported UI hosts, never arbitrary targets.
struct MainThreadSnapshotScope {
    template <typename Callback>
    static bool dispatch(const char *process, Callback &&callback) {
        if (!process || (std::strcmp(process, "com.qinggan.app.launcher") != 0
                         && std::strcmp(process, "com.qinggan.app.setting") != 0)) {
            return false;
        }
        callback(process);
        return true;
    }
};
