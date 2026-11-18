#pragma once

#include "bootstrap_descriptor.h"
#include <cstring>

inline bool system_server_bootstrap_authorized(unsigned int uid, const char *process,
                                               const BootstrapDescriptor &bootstrap) {
    if (uid != 1000 || process == nullptr || std::strcmp(process, "system_server") != 0
        || bootstrap.modules.size() != 1 || !bootstrap.executors.empty()
        || bootstrap.modules[0].id != "launcher") {
        return false;
    }
    for (const auto &declared : bootstrap.modules[0].processes) {
        if (declared == "system_server") {
            return true;
        }
    }
    return false;
}

inline bool system_server_framework_jar(const char *path) {
    if (path == nullptr || std::strncmp(path, "/system/framework/", 18) != 0) {
        return false;
    }
    const char *name = path + 18;
    const size_t length = std::strlen(name);
    return length > 4 && std::strchr(name, '/') == nullptr
           && std::strstr(name, "..") == nullptr && std::strcmp(name + length - 4, ".jar") == 0;
}
