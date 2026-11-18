#include "downlink_snapshots.h"
#include <cassert>
#include <string>
static const std::string source = "vehicle-drive-forced-ev";
static std::string frame(const std::string &phase, uint64_t id = 1, const std::string &session = std::string(32, 'a'), int value = 5) {
    return "V|" + source + "|0|{\"status\":\"native-command\",\"source\":\"" + source +
           "\",\"command\":{\"schemaVersion\":1,\"identity\":{\"ownerSession\":\"" + session +
           "\",\"bootId\":\"11111111-1111-4111-8111-111111111111\",\"source\":\"" + source +
           "\",\"commandId\":" + std::to_string(id) + ",\"revision\":1,\"state\":\"IVI_SOC_MODESET\",\"value\":" +
           std::to_string(value) + "},\"phase\":\"" + phase + "\"}}";
}
static std::string registered(bool available = true) {
    return "V|" + source + "|19|{\"status\":\"native-transport-registered\",\"receipt\":{\"ownerSession\":\"" + std::string(32, 'a') +
           "\",\"bootId\":\"11111111-1111-4111-8111-111111111111\",\"source\":\"" + source +
           "\",\"pid\":100,\"endpointEpoch\":7,\"available\":" + (available ? "true" : "false") + "}}";
}
int main() {
    DownlinkSnapshots snapshots(8192);    snapshots.consume(registered());
    snapshots.consume("V|" + source + "|0|{\"status\":\"native-command\",\"source\":\"" + source + "\",\"command\":null}");
    assert(snapshots.take_vehicle_command(source).find("native-transport-registered") != std::string::npos);
    snapshots.reset();

    snapshots.consume(registered());
    snapshots.consume(frame("offered"));
    assert(snapshots.take_vehicle_command(source).find("native-transport-registered") != std::string::npos);
    assert(snapshots.take_vehicle_command(source).find("native-command") != std::string::npos);
    const auto offered = snapshots.peek_vehicle_command(source);
    snapshots.consume(registered());
    assert(snapshots.peek_vehicle_command(source) == offered);
    snapshots.consume(frame("execute"));
    assert(snapshots.peek_vehicle_command(source).find("execute") != std::string::npos);
    snapshots.consume(registered(false));
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(registered());
    snapshots.consume(frame("execute"));
    assert(snapshots.peek_vehicle_command(source).find("execute") != std::string::npos);
    snapshots.reset();

    snapshots.consume(frame("offered"));
    assert(!snapshots.take_vehicle_command(source).empty());
    assert(!snapshots.peek_vehicle_command(source).empty());
    assert(snapshots.take_vehicle_command(source).empty());
    snapshots.consume(frame("offered"));
    assert(!snapshots.take_vehicle_command(source).empty());
    snapshots.consume(frame("execute"));
    const auto execute = snapshots.peek_vehicle_command(source);
    assert(execute.find("execute") != std::string::npos);
    snapshots.consume(frame("offered"));
    assert(snapshots.peek_vehicle_command(source) == execute);
    snapshots.consume(frame("execute", 1, std::string(32, 'a'), 2));
    assert(snapshots.peek_vehicle_command(source).empty());
    assert(snapshots.take_vehicle_command(source).empty());
    snapshots.consume(frame("execute"));
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("execute", 2));
    assert(!snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("cancelled", 2));
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("execute", 2));
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("execute", 3, std::string(32, 'b')));
    auto current = snapshots.peek_vehicle_command(source);
    assert(!current.empty());
    snapshots.consume(frame("execute", 100, std::string(32, 'a')));
    assert(snapshots.peek_vehicle_command(source) == current);
    auto wrong_source = frame("execute", 4, std::string(32, 'b'));
    wrong_source.replace(2, source.size(), "vehicle-drive-pedestrian-warning");
    snapshots.consume(wrong_source);
    assert(snapshots.peek_vehicle_command(source) == current);
    snapshots.consume("V|" + source + "|18446744073709551616|{}");
    snapshots.consume("V|" + source + "|0|{\"status\":\"unavailable\",\"extra\":true}");
    snapshots.consume("V|" + source + "|0|{\"status\":\"unavailable\",\"status\":\"unavailable\"}");
    snapshots.consume("V|" + source + "|0|{\"status\":\"" + std::string(4096, 'x') + "\"}");
    assert(snapshots.peek_vehicle_command(source) == current);
    snapshots.consume("V|" + source + "|0|{\"status\":\"native-command\",\"source\":\"" + source + "\",\"command\":null}");
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("execute", 5, std::string(32, 'b')));
    snapshots.reset();
    assert(snapshots.peek_vehicle_command(source).empty());
    assert(snapshots.take_vehicle_command(source).empty());
    snapshots.consume(frame("execute"));
    assert(!snapshots.peek_vehicle_command(source).empty());
    snapshots.consume("V|" + source + "|8|{\"status\":\"unavailable\"}");
    assert(snapshots.peek_vehicle_command(source).empty());
    snapshots.consume(frame("execute"));
    assert(!snapshots.peek_vehicle_command(source).empty());
    const auto typed = frame("execute");
    const auto identity_begin = typed.find("\"identity\":") + 11;
    const auto identity_end = typed.find(",\"phase\"");
    const auto identity = typed.substr(identity_begin, identity_end - identity_begin);
    snapshots.consume("V|" + source + "|9|{\"status\":\"native-command-reported\",\"identity\":" + identity + ",\"result\":\"accepted\"}");
    assert(snapshots.peek_vehicle_command(source).empty());
    assert(snapshots.take_vehicle_command(source).find("reported") != std::string::npos);
    snapshots.consume(frame("execute", 2));
    const auto higher = snapshots.peek_vehicle_command(source);
    snapshots.consume("V|" + source + "|9|{\"status\":\"native-command-reported\",\"identity\":" + identity + ",\"result\":\"accepted\"}");
    assert(snapshots.peek_vehicle_command(source) == higher);
    snapshots.clear_vehicle_commands();
    assert(snapshots.peek_vehicle_command(source).empty());

}
