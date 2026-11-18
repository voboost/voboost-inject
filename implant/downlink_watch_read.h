#pragma once

#include <poll.h>
#include <unistd.h>

#include <cstddef>
#include <string>

// Production downlink readers call this while holding the downlink mutex.
class DownlinkWatchRead {
public:
template <typename Framer, typename Snapshots>
static bool poll_and_drain(int fd, Framer &framer, Snapshots &snapshots) {
    struct pollfd observed {fd, POLLIN, 0};
    if (poll(&observed, 1, 0) == 1) {
        // A final ACK remains readable when its writer closes the transport.
        return drain(fd, observed.revents, framer, snapshots);
    }
    return false;
}

template <typename Framer, typename Snapshots>
static bool drain(int fd, short events, Framer &framer, Snapshots &snapshots) {
    if (events & (POLLIN | POLLHUP)) {
        for (int iteration = 0; iteration < 64; ++iteration) {
            char buffer[8192];
            ssize_t count = read(fd, buffer, sizeof(buffer));
            if (count <= 0) {
                break;
            }
            framer.feed(buffer, static_cast<size_t>(count),
                        [&snapshots](const std::string &line) {
                    if (line.rfind("D|", 0) == 0 || line.rfind("A|", 0) == 0
                        || line.rfind("C|", 0) == 0 || line.rfind("P|", 0) == 0
                        || line.rfind("I|", 0) == 0 || line.rfind("K|", 0) == 0 || line.rfind("V|", 0) == 0
                        || line.rfind("U|", 0) == 0) {
                        snapshots.consume(line);
                    }
                });
        }
    }
    const bool closed = (events & (POLLHUP | POLLERR)) != 0;
    if (closed) {
        snapshots.clear_vehicle_commands();
    }
    return closed;
}
};
