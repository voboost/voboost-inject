#pragma once

#include <yyjson.h>
#include "owned_intent_lane.h"
#include "vehicle_commands.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>

// Bounded target-local state for daemon downlink snapshots. Ordinary desired
// state (D) and mutation acknowledgements (A) deliberately use separate
// slots: a live/rebind D frame is never evidence that a Settings mutation was
// committed. The caller serializes access with the downlink mutex.
class DownlinkSnapshots {
public:
explicit DownlinkSnapshots(size_t maximum_document_bytes)
    : maximum_document_bytes_(maximum_document_bytes) {
}

void reset() {
    vehicle_commands_.reset();
    desired_.clear();
    cluster_.clear();
    cache_command_.clear();
    page_command_.clear();
    mutation_ack_.clear();
    saved_.clear();
    for (auto &receipt : owned_intent_receipts_) {
        receipt.clear();
    }
    mutation_ack_id_ = 0;
    has_mutation_ack_ = false;
}

void consume(const std::string &line) {
    if (line.rfind("U|", 0) == 0) {
        size_t end = line.find('|', 2);
        uint64_t id = 0;
        if (end == std::string::npos || !parse_request_id(line, 2, end, &id)) {
            return;
        }
        std::string document = line.substr(end + 1);
        if (document.size() > 4096 || !valid_document(document)) {
            return;
        }
        yyjson_doc *parsed = yyjson_read(document.data(), document.size(), 0);
        yyjson_val *root = yyjson_doc_get_root(parsed);
        yyjson_val *request = yyjson_obj_get(root, "requestId");
        yyjson_val *revision = yyjson_obj_get(root, "userRevision");
        bool valid = yyjson_is_uint(request) && yyjson_get_uint(request) == id &&
                     yyjson_is_uint(revision) && yyjson_is_obj(yyjson_obj_get(root, "field")) &&
                     yyjson_obj_get(root, "value") &&
                     yyjson_is_str(yyjson_obj_get(root, "disposition"));
        uint64_t user_revision = yyjson_get_uint(revision);
        yyjson_doc_free(parsed);
        if (!valid) {
            return;
        }
        auto previous = saved_.find(id);
        if (previous != saved_.end() && previous->second.first > user_revision) {
            return;
        }
        // Exact request correlation: an unrelated field's receipt never covers this request.
        if (saved_.size() >= 64 && saved_.find(id) == saved_.end()) {
            saved_.erase(saved_.begin());
        }
        saved_[id] = std::make_pair(user_revision, std::move(document));
        return;
    }
    if (line.rfind("V|", 0) == 0) {
        vehicle_commands_.consume(line); return;
    }
    if (line.rfind("I|", 0) == 0) {
        size_t source_end = line.find('|', 2);
        if (source_end != std::string::npos && line.size() <= 192) {
            size_t index = owned_intent_source_index(line.substr(2, source_end - 2));
            if (index < owned_intent_receipts_.size()) {
                owned_intent_receipts_[index] = line;
            }
        }
        return;
    }
    if (line.rfind("P|", 0) == 0) {
        std::string command = line.substr(2);
        if (command.size() <= 1024 && valid_document(command)) {
            page_command_ = std::move(command);
        }
        return;
    }
    if (line.rfind("C|", 0) == 0) {
        std::string command = line.substr(2);
        if (command.size() <= 1024 && valid_document(command)) {
            cache_command_ = std::move(command);
        }
        return;
    }
    if (line.rfind("D|", 0) == 0) {
        std::string document = line.substr(2);
        if (valid_document(document)) {
            desired_ = std::move(document);
        }
        return;
    }
    if (line.rfind("K|", 0) == 0) {
        std::string document = line.substr(2);
        if (valid_document(document)) {
            cluster_ = std::move(document);
        }
        return;
    }
    if (line.rfind("A|", 0) != 0) {
        return;
    }

    size_t id_end = line.find('|', 2);
    if (id_end == std::string::npos) {
        return;
    }
    uint64_t request_id = 0;
    if (!parse_request_id(line, 2, id_end, &request_id)) {
        return;
    }
    std::string document = line.substr(id_end + 1);
    if (!valid_document(document)) {
        return;
    }
    if (!has_mutation_ack_ || request_id >= mutation_ack_id_) {
        mutation_ack_id_ = request_id;
        mutation_ack_ = std::move(document);
        has_mutation_ack_ = true;
    }
}

bool take_mutation_ack(uint64_t requested_id, std::string *document) {
    if (!document || requested_id == 0 || !has_mutation_ack_ ||
        mutation_ack_id_ < requested_id) {
        return false;
    }
    // Keep the latest ACK replayable until a newer ACK or endpoint reset.
    // Multiple Settings panels can coexist in one OEM process; an older
    // panel must not consume the coalesced latest state before the newest
    // panel observes it.
    *document = mutation_ack_;
    return true;
}

bool take_saved(uint64_t requested_id, std::string *document) const {
    auto receipt = saved_.find(requested_id);
    if (!document || receipt == saved_.end()) {
        return false;
    }
    *document = receipt->second.second;
    return true;
}

std::string take_vehicle_command(const std::string &source) {
    return vehicle_commands_.take(source);
}
std::string peek_vehicle_command(const std::string &source) const {
    return vehicle_commands_.peek(source);
}
void clear_vehicle_commands() {
    vehicle_commands_.reset();
}

const std::string &owned_intent_receipt(const std::string &source) const {
    static const std::string empty;
    const size_t index = owned_intent_source_index(source);
    return index < owned_intent_receipts_.size() ? owned_intent_receipts_[index] : empty;
}

const std::string &cluster() const {
    return cluster_;
}

const std::string &desired() const {
    return desired_;
}

const std::string &page_command() const {
    return page_command_;
}
void acknowledge_page_command(const std::string &command) {
    if (page_command_ == command) {
        page_command_.clear();
    }
}

const std::string &cache_command() const {
    return cache_command_;
}
void acknowledge_cache_command(const std::string &command) {
    if (cache_command_ == command) {
        cache_command_.clear();
    }
}

bool has_mutation_ack() const {
    return has_mutation_ack_;
}

uint64_t mutation_ack_id() const {
    return mutation_ack_id_;
}

private:
bool valid_document(const std::string &document) const {
    if (document.empty() || document.size() > maximum_document_bytes_) {
        return false;
    }
    yyjson_doc *parsed = yyjson_read(document.data(), document.size(), 0);
    if (!parsed) {
        return false;
    }
    bool valid = yyjson_is_obj(yyjson_doc_get_root(parsed));
    yyjson_doc_free(parsed);
    return valid;
}

static bool parse_request_id(const std::string &line, size_t begin,
                             size_t end, uint64_t *request_id) {
    if (!request_id || begin >= end) {
        return false;
    }
    uint64_t parsed = 0;
    for (size_t index = begin; index < end; ++index) {
        unsigned char byte = static_cast<unsigned char>(line[index]);
        if (byte < '0' || byte > '9') {
            return false;
        }
        uint64_t digit = static_cast<uint64_t>(byte - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            return false;
        }
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0) {
        return false;
    }
    *request_id = parsed;
    return true;
}

VehicleCommands vehicle_commands_;
size_t maximum_document_bytes_;
std::string desired_;
std::string cluster_;
std::string cache_command_;
std::string page_command_;
std::string mutation_ack_;
std::map<uint64_t, std::pair<uint64_t, std::string>> saved_;
std::array<std::string, owned_intent_sources.size()> owned_intent_receipts_;
uint64_t mutation_ack_id_ = 0;
bool has_mutation_ack_ = false;
};
