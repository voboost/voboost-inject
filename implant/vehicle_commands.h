#pragma once
#include "owned_intent_lane.h"
#include <yyjson.h>
#include <array>
#include <charconv>
#include <climits>
#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>

// Its small local mutex is independent of state RPC waits. No execution or IPC belongs here.
class VehicleCommands {
public:
void reset() {
    std::lock_guard<std::mutex> lock(mutex_); slots_ = {}; boot_id_.clear();
}
void consume(const std::string &line) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (line.size() > 4224 || line.rfind("V|", 0) != 0) {
        return;
    }
    const size_t source_end = line.find('|', 2);
    const size_t id_end = source_end == std::string::npos
        ? source_end : line.find('|', source_end + 1);
    if (id_end == std::string::npos) {
        return;
    }
    const std::string source = line.substr(2, source_end - 2);
    const size_t index = owned_intent_source_index(source);
    uint64_t event = 0;
    if (index >= slots_.size() ||
        !number(line.substr(source_end + 1, id_end - source_end - 1), &event)) {
        return;
    }
    const std::string body = line.substr(id_end + 1);
    if (body.empty() || body.size() > 4096) {
        return;
    }
    yyjson_doc *doc = yyjson_read(body.data(), body.size(), 0);
    if (!doc) {
        return;
    }
    auto *root = yyjson_doc_get_root(doc);
    Slot &slot = slots_[index];
    const std::string kind = text(yyjson_obj_get(root, "status"));
    bool valid = false;
    if (kind == "unavailable" && shape(root, {"status"})) {
        slot.grant.clear();
        slot.command_publication.clear();
        slot.publication.clear();
        valid = true;
    } else if (kind == "native-transport-registered" && shape(root, {"status", "receipt"})) {
        auto *receipt = yyjson_obj_get(root, "receipt");
        const std::string session = text(yyjson_obj_get(receipt, "ownerSession"));
        auto *pid_value = yyjson_obj_get(receipt, "pid");
        valid = shape(receipt, {"ownerSession", "bootId", "source", "pid",
                                "endpointEpoch", "available"})
                && text(yyjson_obj_get(receipt, "source")) == source && hex(session, 32)
                && boot(text(yyjson_obj_get(receipt, "bootId")))
                && positive(pid_value) && yyjson_get_uint(pid_value) > 1
                && yyjson_get_uint(pid_value) <= INT32_MAX
                && positive(yyjson_obj_get(receipt, "endpointEpoch"))
                && yyjson_is_bool(yyjson_obj_get(receipt, "available"))
                && owner(slot, session, text(yyjson_obj_get(receipt, "bootId")));
        if (valid) {
            const uint64_t pid = yyjson_get_uint(yyjson_obj_get(receipt, "pid"));
            const uint64_t epoch = yyjson_get_uint(yyjson_obj_get(receipt, "endpointEpoch"));
            const bool available = yyjson_get_bool(yyjson_obj_get(receipt, "available"));
            if (!available || (slot.transport_known && (slot.pid != pid || slot.epoch != epoch))) {
                slot.grant.clear();
                slot.command_publication.clear();
            }
            slot.pid = pid; slot.epoch = epoch; slot.transport_known = true;
        }
    } else if (kind == "native-command" && shape(root, {"status", "source", "command"})
               && text(yyjson_obj_get(root, "source")) == source) {
        auto *command = yyjson_obj_get(root, "command");
        if (yyjson_is_null(command)) {
            cancel(slot); valid = true;
        }else {
            Identity identity;
            const std::string phase = text(yyjson_obj_get(command, "phase"));
            valid = shape(command, {"schemaVersion", "identity", "phase"})
                    && yyjson_is_uint(yyjson_obj_get(command, "schemaVersion"))
                    && yyjson_get_uint(yyjson_obj_get(command, "schemaVersion")) == 1
                    && parse_identity(yyjson_obj_get(command, "identity"), source, &identity)
                    && (phase == "offered" || phase == "execute" || phase == "cancelled")
                    && owner(slot, identity.session, identity.boot_id);
            if (valid && slot.has_identity) {
                if (identity.id < slot.identity.id) {
                    valid = false;
                }else if (identity.id == slot.identity.id) {
                    if (!(identity == slot.identity)) {
                        cancel(slot); valid = false;
                    }else if ((slot.phase == "cancelled" && phase != "cancelled")
                              || (slot.phase == "execute" && phase == "offered")) {
                        valid = false;
                    }
                }
            }
            if (valid) {
                slot.identity = identity; slot.has_identity = true; slot.phase = phase;
                slot.grant = phase == "cancelled" ? "" : body;
            }
        }
    } else if (kind == "native-command-reported" && shape(root, {"status", "identity", "result"})) {
        Identity identity;
        const std::string result = text(yyjson_obj_get(root, "result"));
        valid = parse_identity(yyjson_obj_get(root, "identity"), source, &identity)
                && (result == "accepted" || result == "cancelled"
                    || result == "failed" || result == "unknown")
                && owner(slot, identity.session, identity.boot_id);
        if (valid && slot.has_identity && identity.id == slot.identity.id) {
            if (!(identity == slot.identity)) {
                valid = false;
            }else {
                cancel(slot);
            }
        }
    }
    if (valid && !slot.poisoned) {
        (kind == "native-command" ? slot.command_publication : slot.publication) = body;
    }
    yyjson_doc_free(doc);
}
std::string take(const std::string &source) {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t index = owned_intent_source_index(source);
    if (index >= slots_.size()) {
        return {};
    }
    Slot &slot = slots_[index];
    std::string result;
    result.swap(slot.publication.empty() ? slot.command_publication : slot.publication);
    return result;
}
std::string peek(const std::string &source) const {
    std::lock_guard<std::mutex> lock(mutex_);
    static const std::string empty;
    const size_t index = owned_intent_source_index(source);
    return index < slots_.size() ? slots_[index].grant : empty;
}
private:
struct Identity {
    std::string session, boot_id, source, state;
    uint64_t id = 0, revision = 0;
    int64_t value = 0;
    bool operator==(const Identity &) const = default;
};
struct Slot {
    std::string publication, command_publication, grant, session, phase;
    uint64_t pid = 0, epoch = 0;
    bool transport_known = false;
    std::array<std::string, 8> retired;
    size_t retired_count = 0;
    Identity identity;
    bool has_identity = false, poisoned = false;
};
static void cancel(Slot &slot) {
    slot.grant.clear();

    slot.command_publication.clear();
    if (slot.has_identity) {
        slot.phase = "cancelled";
    }
}
bool owner(Slot &slot, const std::string &session, const std::string &boot_id) {
    if (!boot_id_.empty() && boot_id_ != boot_id) {
        return false;
    }
    if (boot_id_.empty()) {
        boot_id_ = boot_id;
    }
    if (slot.poisoned) {
        return false;
    }
    if (slot.session == session) {
        return true;
    }
    for (size_t i = 0; i < slot.retired_count; ++i) {
        if (slot.retired[i] == session) {
            return false;
        }
    }
    if (!slot.session.empty()) {
        if (slot.retired_count == slot.retired.size()) {
            cancel(slot); slot.poisoned = true; return false;
        }
        slot.retired[slot.retired_count++] = slot.session;
    }
    slot.session = session;
    slot.has_identity = false;
    slot.phase.clear();
    slot.grant.clear();
    slot.publication.clear();
    slot.command_publication.clear();
    slot.transport_known = false;
    return true;
}
static bool number(const std::string &s, uint64_t *out) {
    if (s.empty()) {
        return false;
    }
    const auto result = std::from_chars(s.data(), s.data() + s.size(), *out);
    return result.ec == std::errc{}
           && result.ptr == s.data() + s.size()
           && *out <= INT64_MAX && std::to_string(*out) == s;
}
static bool positive(yyjson_val *value) {
    return yyjson_is_uint(value) && yyjson_get_uint(value) > 0
           && yyjson_get_uint(value) <= INT64_MAX;
}
static std::string text(yyjson_val *value) {
    return yyjson_is_str(value) ? std::string(yyjson_get_str(value), yyjson_get_len(value)) : "";
}
static bool shape(yyjson_val *value, std::initializer_list<const char *> keys) {
    if (!yyjson_is_obj(value) || yyjson_obj_size(value) != keys.size()) {
        return false;
    }
    for (auto *key : keys) {
        if (!yyjson_obj_get(value, key)) {
            return false;
        }
    }
    return true;
}
static bool hex(const std::string &value, size_t length) {
    if (value.size() != length) {
        return false;
    }
    for (char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}
static bool boot(const std::string &value) {
    if (value.size() != 36) {
        return false;
    }
    std::string digits;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') {
                return false;
            }
        }else {
            digits += value[i];
        }
    }
    return hex(digits, 32);
}
static bool parse_identity(yyjson_val *root, const std::string &source, Identity *identity) {
    if (!shape(root, {"ownerSession", "bootId", "source", "commandId",
                      "revision", "state", "value"})) {
        return false;
    }
    identity->session = text(yyjson_obj_get(root, "ownerSession"));
    identity->boot_id = text(yyjson_obj_get(root, "bootId"));
    identity->source = text(yyjson_obj_get(root, "source"));
    identity->state = text(yyjson_obj_get(root, "state"));
    auto *value = yyjson_obj_get(root, "value");
    if (!hex(identity->session, 32) || !boot(identity->boot_id) || identity->source != source
        || identity->state.empty() || identity->state.size() > 96
        || !positive(yyjson_obj_get(root, "commandId"))
        || !positive(yyjson_obj_get(root, "revision"))
        || !yyjson_is_int(value)) {
        return false;
    }
    for (char c : identity->state) {
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    identity->id = yyjson_get_uint(yyjson_obj_get(root, "commandId"));
    identity->revision = yyjson_get_uint(yyjson_obj_get(root, "revision"));
    identity->value = yyjson_get_sint(value);
    return identity->value >= INT32_MIN && identity->value <= INT32_MAX;
}
mutable std::mutex mutex_;
std::array<Slot, owned_intent_sources.size()> slots_;
std::string boot_id_;
};
