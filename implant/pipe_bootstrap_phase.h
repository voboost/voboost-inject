#pragma once

#include <cstddef>

inline bool pipe_resident_ready(bool initialized, bool startup_complete,
                                std::size_t generation_size, std::size_t catalog_size) {
    return initialized && startup_complete && generation_size == 64 && catalog_size == 64;
}

/* After phase one, the injector has duplicated the record read-end and state
 * write-end into the daemon and asked the implant to close those two local
 * copies. Phase two therefore requires only the target-owned record write-end
 * and state read-end. Requiring all four endpoints makes every valid phase-two
 * call fail after a successful handoff. */
inline bool pipe_bootstrap_phase_two_ready(bool channel_ready,
                                           int record_write_fd,
                                           int state_read_fd) {
    return channel_ready && record_write_fd >= 0 && state_read_fd >= 0;
}
