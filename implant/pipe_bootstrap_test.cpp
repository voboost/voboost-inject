#include "pipe_bootstrap.h"
#include "downlink_framer.h"
#include "downlink_snapshots.h"
#include "state_rpc_serialization.h"
#include "strict_utf8.h"
#include <cassert>
#include <fcntl.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

static void le32(std::vector<uint8_t> &v, uint32_t n) {
    for (int i=0; i<4; i++) {
        v.push_back(n>>(8*i));
    }
}
static void le64(std::vector<uint8_t> &v, uint64_t n) {
    for (int i=0; i<8; i++) {
        v.push_back(n>>(8*i));
    }
}

int main() {
    try {
        {
            std::vector<uint16_t> utf16;
            assert(strict_utf8_to_utf16("{\"value\":\"A\xF0\x9F\x98\x80Z\"}", &utf16));
            bool found_pair = false;
            for (size_t i = 1; i < utf16.size(); i++) {
                found_pair = found_pair || (utf16[i - 1] == 0xd83d && utf16[i] == 0xde00);
            }
            assert(found_pair);
            const std::string malformed[] = {
                std::string("\xc0\x80", 2), std::string("\xed\xa0\x80", 3),
                std::string("\xf4\x90\x80\x80", 4), std::string("\xe2\x82", 2)
            };
            for (const auto &value : malformed) {
                assert(!strict_utf8_to_utf16(value, &utf16));
                assert(utf16.empty());
            }
        }

        {
            struct timespec deadline {10, 100};
            struct timespec submillisecond {10, 99};
            struct timespec expired {10, 100};
            assert(pipe_deadline_ms_left_at(&deadline, &submillisecond, true) == 1);
            assert(pipe_deadline_ms_left_at(&deadline, &expired, true) == 0);
            assert(pipe_deadline_ms_left_at(&deadline, &submillisecond, false) == -1);
        }

// A full nonblocking pipe becomes writable after the first poll slice.
        {
            int channel[2];
            assert(pipe(channel) == 0);
            assert(fcntl(channel[1], F_SETFL, O_NONBLOCK) == 0);
            char bytes[4096] = {};
            while (write(channel[1], bytes, sizeof(bytes)) > 0) {
            }
            assert(errno == EAGAIN || errno == EWOULDBLOCK);
            std::thread reader([&] {
                               std::this_thread::sleep_for(std::chrono::milliseconds(1300));
                               while (read(channel[0], bytes, sizeof(bytes)) > 0) {
                               }
                });
            struct timespec deadline {};
            assert(pipe_deadline_init(&deadline));
            PipePollResult result;
            do {
                result = pipe_poll_writable(channel[1], &deadline);
            } while (result == PipePollResult::Retry);
            close(channel[1]);
            reader.join();
            close(channel[0]);
            assert(result == PipePollResult::Ready);
        }

// Full pipe expires at the overall deadline; a closed reader fails promptly.
        {
            int channel[2];
            assert(pipe(channel) == 0);
            assert(fcntl(channel[1], F_SETFL, O_NONBLOCK) == 0);
            char bytes[4096] = {};
            while (write(channel[1], bytes, sizeof(bytes)) > 0) {
            }
            struct timespec deadline {};
            assert(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
            deadline.tv_nsec += 100000000;
            if (deadline.tv_nsec >= 1000000000) {
                ++deadline.tv_sec;
                deadline.tv_nsec -= 1000000000;
            }
            PipePollResult result;
            do {
                result = pipe_poll_writable(channel[1], &deadline);
            } while (result == PipePollResult::Retry);
            assert(result == PipePollResult::Failed && pipe_deadline_passed(&deadline));
            close(channel[0]);
            assert(pipe_deadline_init(&deadline));
            assert(pipe_poll_writable(channel[1], &deadline) == PipePollResult::Failed);
            close(channel[1]);
        }

        // The commit arrives after one poll slice but before the total deadline.
        {
            int channel[2];
            assert(pipe(channel) == 0);
            std::thread writer([&] {
                               std::this_thread::sleep_for(std::chrono::milliseconds(1300));
                               const char commit = 42;
                               assert(write(channel[1], &commit, 1) == 1);
                               close(channel[1]);
                });
            struct timespec deadline {};
            assert(pipe_deadline_init(&deadline));
            char commit = 0;
            bool delivered = pipe_read_exact(channel[0], &commit, 1, &deadline);
            writer.join();
            close(channel[0]);
            assert(delivered && commit == 42);
        }

        // An open but idle channel must stop at the overall deadline.
        {
            int channel[2];
            assert(pipe(channel) == 0);
            struct timespec deadline {};
            assert(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
            deadline.tv_nsec += 100000000;
            if (deadline.tv_nsec >= 1000000000) {
                ++deadline.tv_sec;
                deadline.tv_nsec -= 1000000000;
            }
            char commit = 0;
            assert(!pipe_read_exact(channel[0], &commit, 1, &deadline));
            assert(pipe_deadline_passed(&deadline));
            close(channel[0]);
            close(channel[1]);
        }

        // EOF remains terminal even when the overall deadline has time left.
        {
            int channel[2];
            assert(pipe(channel) == 0);
            close(channel[1]);
            struct timespec deadline {};
            assert(pipe_deadline_init(&deadline));
            char commit = 0;
            assert(!pipe_read_exact(channel[0], &commit, 1, &deadline));
            assert(errno == ENODATA);
            close(channel[0]);
        }

        // One RPC gate covers request publication through reply consumption. The
        // second caller cannot publish a request while the first reply is pending.
        {
            StateRpcSerialization gate;
            std::atomic<int> phase{0};
            std::atomic<bool> second_attempting{false};
            std::thread first([&] {
                              StateRpcGuard guard(&gate);
                              phase.store(1);
                              while (phase.load() != 2) {
                                  std::this_thread::yield();
                              }
                });
            while (phase.load() != 1) {
                std::this_thread::yield();
            }
            std::thread second([&] {
                               second_attempting.store(true);
                               StateRpcGuard guard(&gate);
                               phase.store(3);
                });
            while (!second_attempting.load()) {
                std::this_thread::yield();
            }
            for (int i = 0; i < 1000; i++) {
                assert(phase.load() == 1);
                std::this_thread::yield();
            }
            phase.store(2);
            first.join();
            second.join();
            assert(phase.load() == 3);
        }

        std::vector<uint8_t> frame{'V','O','B','O','O','S','T','1'};
        std::string manifest = "{}";
        std::string name = "agents.dex";
        std::string dex = "dex";
        le32(frame, manifest.size()); le32(frame, 1); le64(frame, dex.size());
        frame.insert(frame.end(), manifest.begin(), manifest.end());
        frame.push_back(name.size()); frame.push_back(0);
        frame.insert(frame.end(), name.begin(), name.end()); le64(frame, dex.size());
        frame.insert(frame.end(), dex.begin(), dex.end());
        int fds[2]; assert(pipe(fds) == 0);
        std::thread writer([&] {
                           assert(write(fds[1], frame.data(), frame.size()) == (ssize_t)frame.size()); close(fds[1]);
            });
        PipeBootstrapEnvelope envelope;
        assert(read_pipe_bootstrap(fds[0], &envelope));
        assert(envelope.manifest == "{}");
        assert(envelope.files.size() == 1 && envelope.files[0].name == "agents.dex");
        close(fds[0]); writer.join();

        frame[0] = 'X'; assert(pipe(fds) == 0);
        assert(write(fds[1], frame.data(), frame.size()) == (ssize_t)frame.size()); close(fds[1]);
        PipeBootstrapEnvelope hostile; assert(!read_pipe_bootstrap(fds[0], &hostile)); close(fds[0]);

        // Partial read (truncated mid-file): the envelope must be cleared on
        // failure so a retry never reuses stale/partial entries.
        {
            std::vector<uint8_t> partial(frame.begin(), frame.begin() + frame.size() / 2);
            assert(pipe(fds) == 0);
            assert(write(fds[1], partial.data(), partial.size()) == (ssize_t)partial.size()); close(fds[1]);
            PipeBootstrapEnvelope env;
            assert(!read_pipe_bootstrap(fds[0], &env));
            assert(env.files.empty() && env.manifest.empty());
            close(fds[0]);
        }

        // Zero file count: rejected by the header bound check (file_count == 0).
        {
            std::vector<uint8_t> zcount{'V','O','B','O','O','S','T','1'};
            le32(zcount, 2); le32(zcount, 0); le64(zcount, 0);
            assert(pipe(fds) == 0);
            assert(write(fds[1], zcount.data(), zcount.size()) == (ssize_t)zcount.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env)); close(fds[0]);
        }

        // Empty manifest: rejected (manifest_size == 0).
        {
            std::vector<uint8_t> emptyman{'V','O','B','O','O','S','T','1'};
            le32(emptyman, 0); le32(emptyman, 1); le64(emptyman, 4);
            assert(pipe(fds) == 0);
            assert(write(fds[1], emptyman.data(), emptyman.size()) == (ssize_t)emptyman.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env)); close(fds[0]);
        }

        // Oversized single file (dex.size > 64 MiB cap): rejected.
        {
            std::vector<uint8_t> big{'V','O','B','O','O','S','T','1'};
            std::string m = "{}"; std::string nm = "x";
            le32(big, m.size()); le32(big, 1); le64(big, 67108864ULL + 1);
            big.insert(big.end(), m.begin(), m.end());
            big.push_back(1); big.push_back(0);
            big.insert(big.end(), nm.begin(), nm.end()); le64(big, 67108864ULL + 1);
            assert(pipe(fds) == 0);
            assert(write(fds[1], big.data(), big.size()) == (ssize_t)big.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env)); close(fds[0]);
        }

        // Per-process aggregate cap is independent of the 256 MiB signed-release
        // cap. Reject it from the header before any manifest/payload allocation.
        {
            std::vector<uint8_t> over{'V','O','B','O','O','S','T','1'};
            le32(over, 2); le32(over, 2);
            le64(over, PIPE_BOOTSTRAP_MAX_PROCESS_PAYLOAD + 1);
            assert(pipe(fds) == 0);
            assert(write(fds[1], over.data(), over.size()) == (ssize_t)over.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env));
            assert(env.files.empty() && env.manifest.empty());
            close(fds[0]);
        }

        // Zero-length file name (name_size == 0): rejected.
        {
            std::vector<uint8_t> zname{'V','O','B','O','O','S','T','1'};
            std::string m = "{}"; std::string dx = "d";
            le32(zname, m.size()); le32(zname, 1); le64(zname, dx.size());
            zname.insert(zname.end(), m.begin(), m.end());
            zname.push_back(0); zname.push_back(0); // name_size = 0
            assert(pipe(fds) == 0);
            assert(write(fds[1], zname.data(), zname.size()) == (ssize_t)zname.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env)); close(fds[0]);
        }

        // File count == 64 boundary (accepted) vs 65 (rejected).
        {
            std::vector<uint8_t> many{'V','O','B','O','O','S','T','1'};
            std::string m = "{}"; std::string dx = "d";
            le32(many, m.size()); le32(many, 65); le64(many, uint64_t(dx.size()) * 65);
            many.insert(many.end(), m.begin(), m.end());
            assert(pipe(fds) == 0);
            assert(write(fds[1], many.data(), many.size()) == (ssize_t)many.size()); close(fds[1]);
            PipeBootstrapEnvelope env; assert(!read_pipe_bootstrap(fds[0], &env)); close(fds[0]);
        }

        // Shared downlink framing survives split/coalesced frames and a large D
        // immediately before the correlated R reply.
        {
            DownlinkFramer framer((size_t)128 * 1024);
            std::vector<std::string> lines;
            std::string large = "D|" + std::string((size_t)64 * 1024, 'x') + "\nR|7|ok|value\n";
            framer.feed(large.data(), 17, [&](const std::string &line) {
                lines.push_back(line);
            });
            framer.feed(large.data() + 17, large.size() - 17,
                        [&](const std::string &line) {
                lines.push_back(line);
            });
            assert(lines.size() == 2);
            assert(lines[0].rfind("D|", 0) == 0);
            assert(lines[1] == "R|7|ok|value");
        }

        // Oversized input is discarded through its newline; its tail can never
        // become a synthetic frame, and the next real frame remains aligned.
        {
            DownlinkFramer framer(16);
            std::vector<std::string> lines;
            std::string bytes = "D|0123456789R|fake\nR|8|ok|real\n";
            framer.feed(bytes.data(), bytes.size(),
                        [&](const std::string &line) {
                lines.push_back(line);
            });
            assert(lines.size() == 1 && lines[0] == "R|8|ok|real");
        }

        // Rebind starts a new transport epoch: an old partial frame must not be
        // completed with bytes from the fresh daemon pipe.
        {
            DownlinkFramer framer(128);
            std::vector<std::string> lines;
            std::string old_partial = "D|{\"old\":";
            framer.feed(old_partial.data(), old_partial.size(),
                        [&](const std::string &line) {
                lines.push_back(line);
            });
            framer.reset();
            std::string fresh = "R|9|ok|fresh\n";
            framer.feed(fresh.data(), fresh.size(),
                        [&](const std::string &line) {
                lines.push_back(line);
            });
            assert(lines.size() == 1 && lines[0] == "R|9|ok|fresh");
        }

        // Ordinary D snapshots are retained independently and can never satisfy a
        // Settings mutation waiter. Only a correlated A is consumable.
        {
            DownlinkSnapshots snapshots(256);
            snapshots.consume("D|{\"documentGeneration\":1}");
            std::string document;
            assert(snapshots.desired() == "{\"documentGeneration\":1}");
            assert(!snapshots.take_mutation_ack(7, &document));

            snapshots.consume("A|7|{\"documentGeneration\":2}");
            assert(snapshots.has_mutation_ack());
            assert(snapshots.mutation_ack_id() == 7);
            assert(snapshots.take_mutation_ack(7, &document));
            assert(document == "{\"documentGeneration\":2}");
            assert(snapshots.take_mutation_ack(7, &document));
            assert(snapshots.desired() == "{\"documentGeneration\":1}");
        }

        // A later ordered ACK semantically covers an older request. A lower ACK
        // cannot replace it or satisfy a newer waiter.
        {
            DownlinkSnapshots snapshots(256);
            std::string document;
            snapshots.consume("A|11|{\"documentGeneration\":11}");
            snapshots.consume("A|10|{\"documentGeneration\":10}");
            assert(snapshots.mutation_ack_id() == 11);
            assert(!snapshots.take_mutation_ack(12, &document));
            assert(snapshots.take_mutation_ack(10, &document));
            assert(document == "{\"documentGeneration\":11}");
            assert(snapshots.take_mutation_ack(11, &document));
            assert(document == "{\"documentGeneration\":11}");
        }

        // Malformed ids, non-object JSON and oversized documents fail closed.
        {
            DownlinkSnapshots snapshots(32);
            const char *invalid[] = {
                "A||{}", "A|0|{}", "A|+1|{}", "A| 1|{}", "A|1|[]",
                "A|18446744073709551616|{}", "A|1|{broken}",
                "A|1|{\"documentGeneration\":12345678901234567890}"
            };
            for (const char *line : invalid) {
                snapshots.consume(line);
            }
            assert(!snapshots.has_mutation_ack());
        }

        // Endpoint replacement clears ordinary and mutation snapshot state, so
        // an old epoch cannot confirm a fresh request.
        {
            DownlinkSnapshots snapshots(256);
            snapshots.consume("D|{\"documentGeneration\":1}");
            snapshots.consume("A|7|{\"documentGeneration\":2}");
            snapshots.reset();
            std::string document;
            assert(snapshots.desired().empty());
            assert(!snapshots.take_mutation_ack(7, &document));
        }
    }
    catch (...) {
        return 1;
    }
}
