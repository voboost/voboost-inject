#include "owned_intent_lane.h"
#include "owned_intent_wake.h"
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cassert>
#include <iostream>
static std::string receipt(uint64_t id, uint64_t stamp, const char *choice, const char *status = "committed") {
    return "I|vehicle-drive-forced-ev|" + std::to_string(id) + "|" + std::to_string(stamp) + "|" + choice + "|" + status;
}
int main() {
    int wake[2];
    assert(pipe(wake) == 0);
    assert(fcntl(wake[1], F_SETFL, O_NONBLOCK) == 0);
    assert(notify_owned_intent(wake[1], [](int fd, const void *bytes, size_t size) {
        return write(fd, bytes, size);
    }));
    struct pollfd ready {wake[0], POLLIN, 0};
    assert(poll(&ready, 1, 0) == 1 && (ready.revents & POLLIN)); // No 1s timeout.
    uint64_t value = 0;
    assert(read(wake[0], &value, sizeof(value)) == sizeof(value) && value == 1);
    assert(!notify_owned_intent(-1, [](int, const void *, size_t) {
        return 0L;
    }));
    close(wake[0]); close(wake[1]);
    OwnedIntentLane lane("vehicle-drive-forced-ev");
    using Receipt = OwnedIntentLane::Receipt;
    assert(!lane.submit(0, 1, "off", 10));
    assert(!lane.submit(1, 1, "invalid", 10));
    assert(lane.submit(900, 1, "off", 10));
    assert(lane.pending()); // Java close has no cancellation capability.
    const auto exact = lane.record();
    assert(exact == "E|900|vehicle-drive-forced-ev|owned-intent|vehicle-drive-forced-ev/intent:off@10\n");
    assert(lane.record() == exact);
    assert(lane.confirm(receipt(899, 10, "off")) == Receipt::None);
    assert(lane.confirm(receipt(901, 10, "off")) == Receipt::None);
    assert(lane.confirm(receipt(900, 11, "off")) == Receipt::None);
    assert(lane.confirm(receipt(900, 10, "on")) == Receipt::None);
    assert(lane.confirm("A|900|{\"agents\":[]}") == Receipt::None);
    assert(lane.confirm("I|vehicle-drive-forced-ev|900x|10|off|committed") == Receipt::None);
    assert(lane.confirm(receipt(900, 10, "off", "backend-applied")) == Receipt::None);
    assert(lane.pending());
    OwnedIntentLane in_flight = lane;
    assert(lane.submit(1, 1, "on", 20)); // Lower random classloader id is valid.
    assert(!lane.same(in_flight)); // Late worker result cannot replace new input.
    assert(!lane.submit(999, 1, "off", 10));
    assert(lane.confirm(receipt(900, 10, "off")) == Receipt::None);
    assert(lane.confirm(receipt(1, 20, "on")) == Receipt::Committed);
    assert(!lane.pending());
    assert(lane.submit(2, 1, "off", 30));
    assert(lane.confirm(receipt(2, 30, "off", "superseded")) == Receipt::Superseded);
    assert(lane.submit(3, 1, "off", 40));
    assert(!lane.abandon(1));
    assert(lane.abandon(2)); // Teardown is uncertain, never successful receipt.
    assert(!lane.pending());
    assert(lane.submit(4, 2, "off", 50));
    assert(lane.confirm(receipt(4, 50, "off")) == Receipt::Committed);
    OwnedIntentLane pw("vehicle-drive-pedestrian-warning");
    assert(pw.submit(4, 2, "off", 50));
    assert(pw.record() == "E|4|vehicle-drive-pedestrian-warning|owned-intent|vehicle-drive-pedestrian-warning/intent:off@50\n");
    assert(pw.confirm(receipt(4, 50, "off")) == Receipt::None);
    assert(pw.pending());
    assert(pw.confirm("I|vehicle-drive-pedestrian-warning|4|50|off|committed") == Receipt::Committed);
    assert(lane.submit(5, 2, "on", 60));
    assert(pw.submit(5, 2, "off", 60));
    assert(lane.confirm("I|vehicle-drive-pedestrian-warning|5|60|on|committed") == Receipt::None);
    assert(pw.confirm("I|vehicle-drive-forced-ev|5|60|off|committed") == Receipt::None);
    assert(lane.pending() && pw.pending());
    assert(!lane.same(pw));
    assert(pw.confirm("I|vehicle-drive-pedestrian-warning|5|60|off|committed|extra") == Receipt::None);
    OwnedIntentLane unsupported("unknown");
    assert(!unsupported.submit(1, 1, "on", 1));
    std::cout << "owned-intent-lane: all checks passed\n";
}
