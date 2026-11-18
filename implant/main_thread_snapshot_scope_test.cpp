#include "main_thread_snapshot_scope.h"

#include <cstdio>
#include <string>

int main() {
    int calls = 0;
    std::string observed;
    auto callback = [&](const char *process) {
                        calls++; observed = process;
                    };
    if (!MainThreadSnapshotScope::dispatch("com.qinggan.app.launcher", callback) || calls != 1) {
        return 1;
    }
    if (!MainThreadSnapshotScope::dispatch("com.qinggan.app.setting", callback) || calls != 2
        || observed != "com.qinggan.app.setting") {
        std::fputs("Settings did not reach the native diagnostic callback\n", stderr);
        return 1;
    }
    if (MainThreadSnapshotScope::dispatch(nullptr, callback)
        || MainThreadSnapshotScope::dispatch("foreign.application", callback) || calls != 2) {
        return 1;
    }
    return 0;
}
