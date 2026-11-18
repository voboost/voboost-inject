#pragma once

#include <cstddef>
#include <string>

class DownlinkFramer {
public:
explicit DownlinkFramer(size_t maximum) : maximum_(maximum) {
}

void reset() {
    pending_.clear();
    discarding_ = false;
}

template <typename Consumer>
void feed(const char *bytes, size_t size, Consumer consumer) {
    for (size_t i = 0; i < size; ++i) {
        char byte = bytes[i];
        if (discarding_) {
            if (byte == '\n') {
                discarding_ = false;
            }
            continue;
        }
        if (byte == '\n') {
            consumer(pending_);
            pending_.clear();
            continue;
        }
        if (pending_.size() >= maximum_) {
            pending_.clear();
            discarding_ = true;
            continue;
        }
        pending_.push_back(byte);
    }
}

private:
size_t maximum_;
std::string pending_;
bool discarding_ = false;
};
