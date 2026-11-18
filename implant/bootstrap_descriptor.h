#pragma once

#include <sys/stat.h>
#include <string>
#include <vector>

struct BootstrapModule {
    std::string id;
    std::string entry_class;
    std::vector<std::string> processes;
    std::string path;
    int fd = -1;  /* sealed memfd, read directly (SELinux forbids /proc/self/fd open) */
};

struct BootstrapArtifact { std::string id; std::string path; int fd = -1; };

struct BootstrapDescriptor {
    std::string generation;
    std::string catalog_sha256;
    std::string desired_json;
    std::string core_path;
    int core_fd = -1;
    std::vector<BootstrapModule> modules;
    std::vector<BootstrapModule> executors;
    std::vector<BootstrapArtifact> artifacts;
};

inline bool bootstrap_regular_file(const std::string &path, off_t maximum_size) {
    struct stat metadata {};
    return !path.empty() && stat(path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode) &&
           metadata.st_size > 0 && (maximum_size <= 0 || metadata.st_size <= maximum_size);
}

inline bool bootstrap_files_present(const BootstrapDescriptor &descriptor) {
    if (!bootstrap_regular_file(descriptor.core_path, (off_t)64 * 1024 * 1024)) {
        return false;
    }
    for (const BootstrapModule &module : descriptor.modules) {
        if (!bootstrap_regular_file(module.path, (off_t)64 * 1024 * 1024)) {
            return false;
        }
    }
    for (const BootstrapArtifact &artifact : descriptor.artifacts) {
        if (!bootstrap_regular_file(artifact.path, 0)) {
            return false;
        }
    }
    return true;
}
