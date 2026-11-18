// state_reply_decode_test.cpp — native host behavioral tests for the
// tagged JNI state read conversion (review-0901 F4). Exercises the SAME
// state_reply_decode.h the production JNI bridge calls, plus the
// production DownlinkFramer for fragmented reads. No Android required:
// the framing and tag conversion are pure.
//
// RED control documented in the fix plan: the pre-fix ok-branch built
// "value|" even when the Java materialization failed (result==nullptr),
// turning a failed decode/allocation into an invented empty VALUE; these
// tests must fail against that variant.

#include "state_reply_decode.h"
#include "downlink_framer.h"
#include "state_rpc_serialization.h"

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static int failures = 0;

static void check(bool condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "state_reply_decode_test: FAILED: %s\n", what);
        failures++;
    }
}

// Feed arbitrary bytes through the PRODUCTION framer and collect lines.
static std::vector<std::string> framed_lines(const std::vector<std::string> &chunks) {
    DownlinkFramer framer(8192);
    std::vector<std::string> lines;
    for (const std::string &chunk : chunks) {
        framer.feed(chunk.data(), chunk.size(), [&](const std::string &line) {
            lines.push_back(line);
        });
    }
    return lines;
}

int main() noexcept try {
    const unsigned long long awaited = 42;

    // --- R| reply parsed into its parts ---------------------------------
    {
        state_reply::Reply r = state_reply::parse_reply_line("R|42|ok|true", awaited);
        check(r.matched, "ok reply with matching id must match");
        check(r.status == "ok", "ok status parsed");
        check(r.value == "true", "ok value parsed");
    }
    // --- missing → absent ------------------------------------------------
    {
        state_reply::Reply r = state_reply::parse_reply_line("R|42|missing|", awaited);
        check(r.matched, "missing reply must match");
        check(r.status == "missing", "missing status parsed");
        std::string tagged = state_reply::tagged_reply(r.status, true, "");
        check(tagged == "absent|", "missing must convert to absent|");
    }
    // --- ok with a value --------------------------------------------------
    {
        std::string tagged = state_reply::tagged_reply("ok", true, "true");
        check(tagged == "value|true", "ok + materialized string → value|true");
    }
    // --- ok with EMPTY value is still a VALUE -----------------------------
    {
        std::string tagged = state_reply::tagged_reply("ok", true, "");
        check(tagged == "value|", "ok + materialized EMPTY string → value| (VALUE, not absent)");
    }
    // --- ok with a value containing a pipe tail stays one value ----------
    {
        std::string tagged = state_reply::tagged_reply("ok", true, "a|b|c");
        check(tagged == "value|a|b|c", "pipe tail belongs to the value field");
        // and the parser keeps everything after the second '|':
        state_reply::Reply r = state_reply::parse_reply_line("R|42|ok|a|b|c", awaited);
        check(r.matched && r.value == "a|b|c", "parser keeps the pipe tail in the value");
    }
    // --- error / unknown status → UNAVAILABLE ----------------------------
    {
        std::string tagged = state_reply::tagged_reply("error", true, "x");
        check(tagged.empty(), "error status → UNAVAILABLE marker (empty)");
        std::string unknown = state_reply::tagged_reply("weird", true, "x");
        check(unknown.empty(), "unknown status → UNAVAILABLE marker (empty)");
    }
    // --- wrong request id does not match ----------------------------------
    {
        state_reply::Reply r = state_reply::parse_reply_line("R|43|ok|v", awaited);
        check(!r.matched, "wrong request id must not match");
    }
    // --- non-numeric request id does not match ----------------------------
    {
        state_reply::Reply r = state_reply::parse_reply_line("R|4x2|ok|v", awaited);
        check(!r.matched, "non-numeric request id must not match");
    }
    // --- malformed lines (missing separators) do not match ----------------
    {
        check(!state_reply::parse_reply_line("R|42", awaited).matched,
              "R|id without status separator must not match");
        check(!state_reply::parse_reply_line("R|", awaited).matched, "bare R| must not match");
        check(!state_reply::parse_reply_line("", awaited).matched, "empty line must not match");
        check(!state_reply::parse_reply_line("X|42|ok|v", awaited).matched,
              "unknown frame type must not match");
    }
    // --- interleaved D/A frames never satisfy the waiter ------------------
    {
        check(!state_reply::parse_reply_line("D|anything", awaited).matched,
              "interleaved D frame must not match the state waiter");
        check(!state_reply::parse_reply_line("A|7|1", awaited).matched,
              "interleaved A frame must not match the state waiter");
        // The exact production sequence: D, our reply, A — waiter still
        // finds its reply between the passes.
        auto lines = framed_lines({"D{\"snap\":1}\nR|42|ok|true\nA|9|1\n"});
        state_reply::Reply found = {};
        for (const std::string &line : lines) {
            state_reply::Reply r = state_reply::parse_reply_line(line, awaited);
            if (r.matched) {
                found = r; break;
            }
        }
        check(found.matched && found.value == "true",
              "our reply is found amid interleaved D/A frames");
    }
    // --- fragmented reads through the PRODUCTION framer --------------------
    {
        auto lines = framed_lines({"R|4", "2|ok|tr", "ue\n"});
        check(lines.size() == 1 && lines[0] == "R|42|ok|true",
              "a reply split across three read() chunks reassembles");
        auto partial = framed_lines({"R|42|ok|true"});
        check(partial.empty(), "a reply without the newline stays pending (no match)");
        // A stateful framer fed the pending prefix accepts the tail from a
        // LATER read() chunk and reassembles the same complete line.
        DownlinkFramer stateful(8192);
        std::vector<std::string> tail_lines;
        auto collect = [&](const std::string &line) {
                           tail_lines.push_back(line);
                       };
        stateful.feed("R|42|ok|tr", 10, collect);
        stateful.feed("ue\n", 3, collect);
        check(tail_lines.size() == 1 && tail_lines[0] == "R|42|ok|true",
              "stateful framer reassembles the tail chunk");
    }
    // --- newline-terminated multi-frame single read ------------------------
    {
        auto lines = framed_lines({"A|1|0\nR|42|missing|\nD|x\n"});
        check(lines.size() == 3, "three frames in one read yield three lines");
        state_reply::Reply r = state_reply::parse_reply_line(lines[1], awaited);
        check(r.matched && r.status == "missing", "missing reply found in multi-frame read");
    }
    // --- FAILED Java string materialization must NOT invent empty VALUE ---
    {
        // The pre-fix defect: result==nullptr on ok still built "value|".
        // The shared conversion must map failed materialization to the
        // UNAVAILABLE marker instead.
        std::string tagged = state_reply::tagged_reply("ok", false, "");
        check(tagged.empty(), "ok + FAILED materialization → UNAVAILABLE, never value|");
    }
    // --- malformed UTF-8 value in the ok frame -----------------------------
    // The production bridge materializes through new_strict_utf8_string,
    // which rejects invalid UTF-8 by returning nullptr: model that as
    // materialization failure → UNAVAILABLE (never an invented VALUE).
    {
        std::string bad_value = "en\xC3\x28"; // invalid UTF-8 sequence
        state_reply::Reply r = state_reply::parse_reply_line(
            std::string("R|42|ok|") + bad_value, awaited);
        check(r.matched, "frame still parses");
        // production strict_utf8 would reject these bytes: materialization
        // fails → UNAVAILABLE
        std::string tagged = state_reply::tagged_reply(r.status, false, r.value);
        check(tagged.empty(), "malformed UTF-8 value → UNAVAILABLE, never a VALUE");
    }

    // --- LATE reply for an already-abandoned request id --------------------
    // Production contract: the RPC window times out and the request id moves
    // on; a daemon reply stamped with the OLD id must never satisfy a later
    // call waiting on a NEW id. This is the pure, host-testable half of the
    // bounded wait (the poll/timeout loop itself lives in the JNI bridge).
    {
        const unsigned long long second_call_id = 43;
        state_reply::Reply stale =
            state_reply::parse_reply_line("R|42|ok|old-value", second_call_id);
        check(!stale.matched,
              "reply carrying the PREVIOUS request id must not match the new call");
        state_reply::Reply fresh =
            state_reply::parse_reply_line("R|43|ok|new-value", second_call_id);
        check(fresh.matched && fresh.value == "new-value",
              "the reply for the awaited id still matches after a stale one");
    }
    // --- request id SEQUENCE: each waiter sees only its own reply ----------
    // Models two serialized RPCs (StateRpcGuard serializes them in
    // production): id 1 answers late, id 2 answers first; the second waiter
    // must skip id 1's frame and match id 2's, and after both calls a
    // duplicated frame for id 1 matches nothing still awaited.
    {
        auto lines = framed_lines(
            {"R|2|ok|second\nR|1|ok|first-late\nR|2|ok|duplicate\n"});
        state_reply::Reply second = {};
        for (const std::string &line : lines) {
            state_reply::Reply r = state_reply::parse_reply_line(line, 2);
            if (r.matched) { second = r; break; }
        }
        check(second.matched && second.value == "second",
              "waiter for id 2 finds its reply even when id 1 arrives late");
        state_reply::Reply first = {};
        for (const std::string &line : lines) {
            state_reply::Reply r = state_reply::parse_reply_line(line, 1);
            if (r.matched) { first = r; break; }
        }
        check(first.matched && first.value == "first-late",
              "waiter for id 1 still matches its late reply by id");
        for (const std::string &line : lines) {
            check(!state_reply::parse_reply_line(line, 3).matched,
                  "no frame matches an id that was never issued");
        }
    }
    // --- corrupted id field: empty or numeric-garbage ids stay foreign -----
    {
        check(!state_reply::parse_reply_line("R||ok|v", awaited).matched,
              "empty request id field must not match");
        check(!state_reply::parse_reply_line("R|4.2|ok|v", awaited).matched,
              "non-integer request id must not match");
        check(!state_reply::parse_reply_line("R|42x|ok|v", awaited).matched,
              "request id with trailing garbage must not match");
    }
    // --- corrupted frame inside the stream must not poison the framer ------
    // A truncated id-less R line (lost bytes between frames) is a malformed
    // DOWNLINK line: it must not match, and the framer must still deliver the
    // following well-formed reply intact.
    {
        auto lines = framed_lines({"R|4\nR|42|ok|recovered\n"});
        check(lines.size() == 2,
              "corrupt frame plus intact reply yield two framed lines");
        bool hit_corrupt = false, hit_reply = false;
        for (const std::string &line : lines) {
            state_reply::Reply r = state_reply::parse_reply_line(line, awaited);
            if (line == "R|4") {
                hit_corrupt = true;
                check(!r.matched,
                      "truncated R|4 frame must not match (no status/value)");
            } else if (r.matched) {
                hit_reply = r.value == "recovered";
            }
        }
        check(hit_reply, "framer recovers and delivers the reply after corruption");
        (void)hit_corrupt;
    }
    // --- oversized/corrupted line is discarded and the stream resyncs ------
    // Production caps the downlink framer at MAX_DESIRED_DOCUMENT_BYTES + 128
    // = 61568 bytes (implant.cpp); a runaway/corrupted
    // frame larger than the buffer must be dropped by the PRODUCTION framer
    // (discard until newline) instead of being split into fake frames, and
    // the next well-formed reply must come through whole.
    {
        DownlinkFramer capped(24);
        std::vector<std::string> out;
        auto collect = [&](const std::string &line) { out.push_back(line); };
        std::string junk(40, 'x');
        std::string stream = junk + "\nR|42|ok|after-junk\n";
        capped.feed(stream.data(), stream.size(), collect);
        bool matched_reply = false;
        for (const std::string &line : out) {
            check(line != junk,
                  "oversized frame is discarded, never delivered");
            state_reply::Reply r = state_reply::parse_reply_line(line, awaited);
            if (r.matched) matched_reply = r.value == "after-junk";
        }
        check(matched_reply,
              "framer resyncs after a discarded oversized frame");
    }
    // --- PRODUCTION serializer: StateRpcGuard holds the RPC gate RAII -------
    // The same StateRpcSerialization every State.get call takes. Tested only
    // through the PUBLIC lock()/unlock() behavior: while one guard is alive
    // a second caller's lock() must stay blocked; after the guard is
    // destroyed the next lock() must go through. This is the host-testable
    // serialization half of "replies cannot be consumed by another thread".
    {
        StateRpcSerialization serialization;
        std::atomic<bool> acquired{false};
        std::thread waiter;
        {
            // The guard MUST take the gate before the waiter thread exists:
            // otherwise the waiter could win the mutex race, acquire and
            // release before the guard is constructed, flaky-failing the
            // "stays blocked" check below without any production defect.
            StateRpcGuard guard(&serialization);
            waiter = std::thread([&] {
                // Blocks in lock() until the guard above is destroyed.
                serialization.lock();
                acquired.store(true);
                serialization.unlock();
            });
            // Bounded wait, no sleeps: while the guard is alive lock() must
            // never return. If acquired flips here, the gate is broken.
            bool leaked = false;
            for (int spin = 0; spin < 2000000; ++spin) {
                if (acquired.load()) {
                    leaked = true;
                    break;
                }
                std::this_thread::yield();
            }
            check(!leaked,
                  "lock() stays blocked while a StateRpcGuard is alive");
        }
        // Guard destroyed: the gate must be released and the waiter must
        // get through without any external timeout.
        waiter.join();
        check(acquired.load(),
              "destroyed guard releases the RPC gate for the next call");
    }

    if (failures > 0) {
        fprintf(stderr, "state_reply_decode_test: %d check(s) failed\n", failures);
        return 1;
    }
    printf("state_reply_decode_test: all checks passed\n");
    return 0;
}
catch (...) {
    return 1;
}
