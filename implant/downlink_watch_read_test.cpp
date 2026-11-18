#include "downlink_watch_read.h"
#include "downlink_snapshots.h"
#include "downlink_framer.h"
#include "settings_loaded.h"

#include <sys/socket.h>

#include <cassert>
#include <chrono>
#include <fcntl.h>
#include <string>

int main() noexcept try {
    {
        DownlinkSnapshots snapshots(8192);
        const std::string saved = "{\"requestId\":21,\"userRevision\":4,"
                                  "\"disposition\":\"saved\",\"field\":{\"kind\":\"enabled\","
                                  "\"agent\":\"launcher\"},\"value\":false}";
        int channel[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
        assert(fcntl(channel[0], F_SETFL, O_NONBLOCK) == 0);
        const std::string frame = "U|21|" + saved + "\n";
        assert(write(channel[1], frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()));
        DownlinkFramer framer(8192);
        DownlinkWatchRead::poll_and_drain(channel[0], framer, snapshots);
        close(channel[0]);
        close(channel[1]);
        snapshots.consume("A|99|{\"effective\":true}");
        std::string document;
        assert(snapshots.take_saved(21, &document) && document == saved);
        assert(snapshots.take_saved(21, &document));
        std::string stale = saved;
        stale.replace(stale.find("\"userRevision\":4"), 16, "\"userRevision\":3");
        snapshots.consume("U|21|" + stale);
        assert(snapshots.take_saved(21, &document) && document == saved);
        assert(!snapshots.take_saved(20, &document));
        snapshots.consume("U|22|" + saved);
        assert(!snapshots.take_saved(22, &document));
        snapshots.reset();
        assert(!snapshots.take_saved(21, &document));
    }
    {
        int owned[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, owned) == 0);
        assert(fcntl(owned[0], F_SETFL, O_NONBLOCK) == 0);
        const std::string receipt = "I|vehicle-drive-forced-ev|900|10|off|committed";
        assert(write(owned[1], (receipt + "\n").data(), receipt.size() + 1) == static_cast<ssize_t>(receipt.size() + 1));
        DownlinkFramer framer(8192);
        DownlinkSnapshots snapshots(8192);
        DownlinkWatchRead::poll_and_drain(owned[0], framer, snapshots);
        assert(snapshots.owned_intent_receipt("vehicle-drive-forced-ev") == receipt);
        snapshots.consume("I|vehicle-drive-pedestrian-warning|900|10|on|committed");
        assert(snapshots.owned_intent_receipt("vehicle-drive-forced-ev") == receipt);
        assert(snapshots.owned_intent_receipt("vehicle-drive-pedestrian-warning") == "I|vehicle-drive-pedestrian-warning|900|10|on|committed");
        snapshots.consume("I|unknown|900|10|on|committed");
        assert(snapshots.owned_intent_receipt("unknown").empty());
        snapshots.reset();
        assert(snapshots.owned_intent_receipt("vehicle-drive-forced-ev").empty());
        close(owned[0]); close(owned[1]);
    }

    {
        DownlinkSnapshots snapshots(64);
        const std::string cluster = "{\"snapshotRevision\":1}";
        snapshots.consume("K|" + cluster);
        assert(snapshots.cluster() == cluster);
        snapshots.consume("D|{\"desiredRevision\":9}");
        snapshots.consume("A|4|{\"ack\":true}");
        assert(snapshots.cluster() == cluster);
        snapshots.consume("K|not-json");
        snapshots.consume("K|[]");
        snapshots.consume("K|{\"value\":\"" + std::string(64, 'x') + "\"}");
        assert(snapshots.cluster() == cluster);
        snapshots.consume("K|{\"snapshotRevision\":2}");
        assert(snapshots.cluster() == "{\"snapshotRevision\":2}");
        snapshots.reset();
        assert(snapshots.cluster().empty());
        snapshots.consume("K|" + cluster);
        assert(snapshots.cluster() == cluster);
    }

    {
        int channel[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
        assert(fcntl(channel[0], F_SETFL, O_NONBLOCK) == 0);
        const std::string source = "vehicle-drive-forced-ev";
        const std::string frame = "V|" + source + "|0|{\"status\":\"unavailable\"}\n";
        assert(write(channel[1], frame.data(), 3) == 3);
        DownlinkFramer framer(8192);
        DownlinkSnapshots state(8192);
        DownlinkWatchRead::poll_and_drain(channel[0], framer, state);
        assert(state.take_vehicle_command(source).empty());
        assert(write(channel[1], frame.data() + 3, frame.size() - 3) == static_cast<ssize_t>(frame.size() - 3));
        DownlinkWatchRead::poll_and_drain(channel[0], framer, state);
        assert(state.take_vehicle_command(source) == "{\"status\":\"unavailable\"}");
        state.consume("V|" + source + "|0|{\"status\":\"native-command\",\"source\":\"" + source +
                      "\",\"command\":{\"schemaVersion\":1,\"identity\":{\"ownerSession\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                      "\"bootId\":\"11111111-1111-4111-8111-111111111111\",\"source\":\"" + source +
                      "\",\"commandId\":1,\"revision\":1,\"state\":\"IVI_SOC_MODESET\",\"value\":5},\"phase\":\"execute\"}}");
        assert(!state.peek_vehicle_command(source).empty());
        close(channel[1]);
        assert(DownlinkWatchRead::poll_and_drain(channel[0], framer, state));
        assert(state.peek_vehicle_command(source).empty());
        assert(state.take_vehicle_command(source).empty());
        close(channel[0]);
    }

    const std::string generation(64, 'a');
    const std::string catalog(64, 'b');
    const auto desired = [&](const std::string &mode, bool cleanup = false) {
                             return "{\"generationId\":\"" + generation + "\",\"catalogSha256\":\"" + catalog +
                                    "\",\"uninstallCleanup\":" + (cleanup ? "true" : "false") +
                                    ",\"agents\":[{\"id\":\"settings\",\"enabled\":true}],"
                                    "\"profile\":{\"startup\":\"" + mode + "\"}}";
                         };
    SettingsLoaded eligibility;
    eligibility.bootstrap(desired("interface"), generation, catalog, false);
    assert(!eligibility.loaded());
    eligibility.bootstrap(desired("hidden"), generation, catalog, true);
    assert(!eligibility.loaded());
    eligibility.bootstrap(desired("none"), generation, catalog, true);
    assert(!eligibility.loaded());
    eligibility.bootstrap(desired("interface"), generation, catalog, true);
    assert(eligibility.loaded());
    eligibility.accepted(desired("hidden"), generation, catalog);
    assert(eligibility.loaded());
    eligibility.accepted(desired("none"), generation, catalog);
    assert(eligibility.loaded());
    eligibility.accepted(desired("none", true), generation, catalog);
    assert(!eligibility.loaded());
    eligibility.accepted(desired("interface"), generation, std::string(64, 'c'));
    assert(!eligibility.loaded());
    eligibility.accepted(desired("interface"), generation, catalog);
    assert(eligibility.loaded());
    const std::string copied = desired("interface");
    const std::string newer = desired("hidden");
    eligibility.rejected(copied, newer);
    assert(eligibility.loaded());
    eligibility.rejected(newer, newer);
    assert(!eligibility.loaded());
    eligibility.accepted(copied, generation, catalog);
    eligibility.rejected("invalid current document", "invalid current document");
    assert(!eligibility.loaded());
    eligibility.accepted(copied, generation, catalog);
    eligibility.accepted(desired("none", true), generation, catalog);
    assert(!eligibility.loaded());
    eligibility.reset();
    assert(!eligibility.loaded());
    int endpoints[2];
    assert(pipe(endpoints) == 0);
    assert(fcntl(endpoints[0], F_SETFL, O_NONBLOCK) == 0);
    const std::string document = "{\"documentGeneration\":12,\"profile\":{\"startup\":\"none\"}}";
    const std::string command = "{\"schemaVersion\":1,\"operation\":\"launcher-cache-quiesce\"}";
    const std::string frames = "D|" + document + "\nC|" + command + "\nK|" + document + "\nA|31|" + document + "\n";
    assert(write(endpoints[1], frames.data(), frames.size()) ==
           static_cast<ssize_t>(frames.size()));
    close(endpoints[1]);
    struct pollfd observed {endpoints[0], POLLIN, 0};
    assert(poll(&observed, 1, 100) == 1);
    assert(observed.revents & (POLLIN | POLLHUP));
    DownlinkFramer framer(size_t{60} *1024U);
    DownlinkSnapshots snapshots(size_t{60} *1024U);
    DownlinkWatchRead::drain(endpoints[0], observed.revents | POLLHUP, framer, snapshots);
    assert(snapshots.desired() == document);
    assert(snapshots.cluster() == document);
    assert(snapshots.cache_command() == command);
    snapshots.consume("C|not-json");
    assert(snapshots.cache_command() == command);
    snapshots.consume("C|{\"oversized\":\"" + std::string(1024, 'x') + "\"}");
    assert(snapshots.cache_command() == command);
    snapshots.acknowledge_cache_command("different request");
    assert(snapshots.cache_command() == command);
    snapshots.acknowledge_cache_command(command);
    assert(snapshots.cache_command().empty());
    std::string acknowledgement;
    assert(snapshots.take_mutation_ack(31, &acknowledgement));
    assert(acknowledgement == document);
    close(endpoints[0]);
    // Real socket close reports both readable bytes and HUP: the JNI ACK
    // reader must consume the authenticated bounded frames before returning.
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
    const std::string final_ack = "A|32|" + document + "\n";
    assert(write(sockets[1], final_ack.data(), final_ack.size()) ==
           static_cast<ssize_t>(final_ack.size()));
    close(sockets[1]);
    struct pollfd final_ready {sockets[0], POLLIN, 0};
    assert(poll(&final_ready, 1, 100) == 1);
    assert((final_ready.revents & POLLIN) != 0);
    assert((final_ready.revents & POLLHUP) != 0);
    DownlinkWatchRead::poll_and_drain(sockets[0], framer, snapshots);
    assert(snapshots.take_mutation_ack(32, &acknowledgement));
    assert(acknowledgement == document);
    assert(!snapshots.take_mutation_ack(33, &acknowledgement));
    close(sockets[0]);
    int idle[2];
    assert(pipe(idle) == 0);
    assert(fcntl(idle[0], F_SETFL, O_NONBLOCK) == 0);
    assert((fcntl(idle[0], F_GETFL) & O_NONBLOCK) != 0);
    const auto started = std::chrono::steady_clock::now();
    // A stale POLLIN on an empty live pipe must return EAGAIN, never wait under the mutex.
    assert(!DownlinkWatchRead::drain(idle[0], POLLIN, framer, snapshots));
    assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(100));
    close(idle[0]);
    close(idle[1]);
    const std::string page = "{\"schemaVersion\":1,\"operation\":\"launcher-page-observe\"}";
    snapshots.consume("P|" + page);
    assert(snapshots.page_command() == page);
    snapshots.consume("P|{broken");
    assert(snapshots.page_command() == page);
    snapshots.acknowledge_page_command("foreign");
    assert(snapshots.page_command() == page);
    snapshots.acknowledge_page_command(page);
    assert(snapshots.page_command().empty());
    snapshots.consume("P|" + page);
    snapshots.reset();
    assert(snapshots.page_command().empty());
    return 0;
}
catch (...) {
    return 1;
}
