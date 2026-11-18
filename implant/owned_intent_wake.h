#pragma once
#include <cstdint>
#include <cstddef>
// Producer never waits. EAGAIN means an existing eventfd notification already
// wakes the watcher; owned pending work remains in the lane either way.
template <typename Writer>
bool notify_owned_intent(int fd, Writer writer) {
    const uint64_t wake = 1;
    return fd >= 0 && writer(fd, &wake, sizeof(wake)) == static_cast<long>(sizeof(wake));
}
