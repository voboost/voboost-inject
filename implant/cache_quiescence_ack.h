#pragma once
#include <cstdint>
#include <string_view>

// Transport replacement invalidates a buffered request and its eventual ACK.
// JNI cache drain runs outside both transport mutexes; the re-check follows it.
struct CacheQuiescenceAck {
    static bool may_apply(uint64_t captured_epoch, uint64_t current_epoch,
                          std::string_view command) {
        return captured_epoch == current_epoch && !command.empty() && command.size() <= 1024;
    }
    static bool may_ack(bool accepted, bool exception, uint64_t captured_epoch,
                        uint64_t current_epoch, std::string_view command,
                        std::string_view pending) {
        return accepted && !exception && may_apply(captured_epoch, current_epoch, command)
               && command == pending;
    }
};
