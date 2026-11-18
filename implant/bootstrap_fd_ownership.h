#pragma once

#include <unistd.h>

#include <cstddef>
#include <vector>

/* Owns bootstrap memfds across their two different lifetimes. Core and module
 * DEX files are consumed synchronously by the Java seam. Ancillary artifacts
 * are registered as /proc/self/fd paths and must remain open for the resident
 * generation because agents may open them long after AgentEntry.init returns.
 *
 * A replacement is staged separately. Publishing closes consumed DEX fds and
 * only then rotates the prior resident artifact set, so a failed replacement
 * cannot invalidate the generation that is already running. */
class BootstrapFdOwnership {
public:
~BootstrapFdOwnership() {
    discard_staged();
    clear_resident();
}

void stage(int fd, bool artifact) {
    staged_.push_back({fd, artifact});
}

int staged_fd(size_t index) const {
    return index < staged_.size() ? staged_[index].fd : -1;
}

size_t staged_count() const {
    return staged_.size();
}

size_t resident_count() const {
    return resident_.size();
}

void discard_staged() {
    for (const Entry &entry : staged_) {
        close_if_valid(entry.fd);
    }
    staged_.clear();
}

void publish() {
    std::vector<int> replacement;
    replacement.reserve(staged_.size());
    for (const Entry &entry : staged_) {
        if (entry.artifact) {
            replacement.push_back(entry.fd);
        } else {
            close_if_valid(entry.fd);
        }
    }
    staged_.clear();
    clear_resident();
    resident_ = std::move(replacement);
}

void clear_resident() {
    for (int fd : resident_) {
        close_if_valid(fd);
    }
    resident_.clear();
}

private:
struct Entry {
    int fd;
    bool artifact;
};

static void close_if_valid(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

std::vector<Entry> staged_;
std::vector<int> resident_;
};
