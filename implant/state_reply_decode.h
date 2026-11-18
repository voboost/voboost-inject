#pragma once

/*
 * state_reply_decode.h — pure, host-testable conversion for the tagged JNI
 * state read (review-0901 F4). The production JNI bridge (implant.cpp) and
 * the native host behavioral tests share THIS code so the tests exercise
 * the real conversion, never a re-implementation.
 *
 * Wire protocol (downlink, one line per frame):
 *   R|<request-id>|<status>|<value>\n
 *   D|... / A|... — unrelated snapshot/ack frames that pass through
 *   untouched while a tagged State.get reply is being awaited.
 *
 * Java-visible tagged reply (the JNI bridge turns it into a jstring):
 *   "value|<value>" → VALUE   (daemon answered ok; <value> may be empty)
 *   "absent|"       → ABSENT  (daemon answered missing)
 *   empty string    → UNAVAILABLE marker: no reply / error / timeout /
 *                     unsafe token / failed Java string materialization.
 */

#include <cstdlib>
#include <string>
#include <string_view>

namespace state_reply {

/*
 * Outcome of matching one downlink line against an awaited request id.
 * matched=false → the line is foreign (D/A frame, malformed line, wrong
 * request id): the caller must keep waiting.
 */
struct Reply {
    bool matched = false;
    unsigned long long request_id = 0;
    std::string status;
    std::string value;
};

/* Parse a downlink line. Pure; never touches Java or fds. */
inline Reply parse_reply_line(std::string_view line, unsigned long long awaited_request_id) {
    Reply reply;
    if (line.rfind("D|", 0) == 0 || line.rfind("A|", 0) == 0) {
        // Interleaved snapshot/ack frames stay invisible to the waiter.
        return reply;
    }
    if (line.rfind("R|", 0) != 0) {
        return reply;
    }
    size_t id_end = line.find('|', 2);
    size_t status_end =
        id_end == std::string_view::npos ? id_end : line.find('|', id_end + 1);
    if (id_end == std::string_view::npos || status_end == std::string_view::npos) {
        return reply; // malformed: no id/status separator
    }
    std::string id_text(line.substr(2, id_end - 2));
    char *parse_end = nullptr;
    unsigned long long parsed_id = strtoull(id_text.c_str(), &parse_end, 10);
    if (!parse_end || *parse_end != '\0' || parsed_id != awaited_request_id) {
        return reply; // not our reply (wrong or unparseable request id)
    }
    reply.matched = true;
    reply.request_id = parsed_id;
    reply.status.assign(line.substr(id_end + 1, status_end - id_end - 1));
    reply.value.assign(line.substr(status_end + 1));
    return reply;
}

/*
 * Tagged conversion of the matched daemon status into the Java-visible
 * string. ok_string_non_null reports whether the ok frame's value actually
 * materialized as a Java string (a failed strict-UTF8 decode or a string
 * allocation must NOT be reported as an invented empty VALUE); contents is
 * its UTF-8 bytes.
 *
 *   status "ok" + string materialized     → "value|<contents>"
 *   status "ok" + materialization failed  → empty → nullptr (UNAVAILABLE)
 *   status "missing"                      → "absent|"
 *   anything else (error, unknown status) → empty → nullptr (UNAVAILABLE)
 */
inline std::string tagged_reply(const std::string &status, bool ok_string_non_null,
                                std::string_view contents) {
    if (status == "ok") {
        if (!ok_string_non_null) {
            return std::string();
        }
        return std::string("value|").append(contents);
    }
    if (status == "missing") {
        return std::string("absent|");
    }
    return std::string();
}

} // namespace state_reply
