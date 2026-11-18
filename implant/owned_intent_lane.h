#pragma once
#include <array>
#include <charconv>
#include <cstdint>
#include <string>
inline constexpr std::array<const char *, 2> owned_intent_sources = {
    "vehicle-drive-forced-ev", "vehicle-drive-pedestrian-warning"
};
inline size_t owned_intent_source_index(const std::string &source) {
    for (size_t index = 0; index < owned_intent_sources.size(); ++index) {
        if (source == owned_intent_sources[index]) {
            return index;
        }
    }
    return owned_intent_sources.size();
}
// Caller synchronizes only small state copies/admission, never IPC or JSON.
// PENDING is memory-owned; root receipt is separate from backend CAN effect.
class OwnedIntentLane {
public:
explicit OwnedIntentLane(const char *source) : source_(source) {
}
const std::string &source() const {
    return source_;
}
enum class Receipt { None, Committed, Superseded };
bool submit(uint64_t id, uint32_t epoch, const std::string &choice, uint64_t capture_ns = 0) {
    if (owned_intent_source_index(source_) == owned_intent_sources.size() || !id || (choice != "on" && choice != "off")) {
        return false;
    }
    if (!capture_ns) {
        capture_ns = capture_ns_ + 1;
    }
    if (capture_ns <= capture_ns_) {
        return false;
    }
    request_ = id; epoch_ = epoch; choice_ = choice;
    capture_ns_ = capture_ns; delivered_ = false; pending_ = true;
    return true;
}
uint64_t capture_ns() const {
    return capture_ns_;
}
uint64_t accepted_ms() const {
    return capture_ns_ / 1000000;
}
bool mark_delivered() {
    bool first = !delivered_; delivered_ = true; return first;
}
bool pending() const {
    return pending_;
}
uint64_t request() const {
    return request_;
}
uint32_t epoch() const {
    return epoch_;
}
const std::string &choice() const {
    return choice_;
}
std::string record() const {
    if (!pending_) {
        return {};
    }
    return "E|" + std::to_string(request_) +
           "|" + source_ + "|owned-intent|" + source_ + "/intent:" +
           choice_ + "@" + std::to_string(capture_ns_) + "\n";
}
bool same(const OwnedIntentLane &other) const {
    return source_ == other.source_ && request_ == other.request_ && capture_ns_ == other.capture_ns_ && epoch_ == other.epoch_;
}
bool abandon(uint32_t current_epoch) {
    if (!pending_ || current_epoch == epoch_) {
        return false;
    }
    pending_ = false; return true;
}
Receipt confirm(const std::string &line) {
    if (!pending_ || line.rfind("I|", 0) != 0 || line.size() > 192) {
        return Receipt::None;
    }
    size_t end_source = line.find('|', 2);
    if (end_source == std::string::npos || line.substr(2, end_source - 2) != source_) {
        return Receipt::None;
    }
    size_t end_id = line.find('|', end_source + 1);
    size_t end_stamp = end_id == std::string::npos ? end_id : line.find('|', end_id + 1);
    size_t end_choice = end_stamp == std::string::npos ? end_stamp : line.find('|', end_stamp + 1);
    if (end_choice == std::string::npos) {
        return Receipt::None;
    }
    uint64_t id = 0, stamp = 0;
    if (!number(line, end_source + 1, end_id, id) || !number(line, end_id + 1, end_stamp, stamp) ||
        id != request_ || stamp != capture_ns_ ||
        line.substr(end_stamp + 1, end_choice - end_stamp - 1) != choice_) {
        return Receipt::None;
    }
    const auto status = line.substr(end_choice + 1);
    if (status != "committed" && status != "superseded") {
        return Receipt::None;
    }
    pending_ = false;
    return status == "committed" ? Receipt::Committed : Receipt::Superseded;
}
private:
static bool number(const std::string &s, size_t start, size_t end, uint64_t &value) {
    if (start >= end) {
        return false;
    }
    auto parsed = std::from_chars(s.data() + start, s.data() + end, value);
    return parsed.ec == std::errc{} && parsed.ptr == s.data() + end && value != 0;
}
std::string source_;
uint64_t capture_ns_ = 0;
uint64_t request_ = 0;
uint32_t epoch_ = 0;
std::string choice_;
bool delivered_ = false;
bool pending_ = false;
};
