// Hostile-input tests for the strict pipe-bootstrap manifest parser.
#include "pipe_bootstrap_manifest.h"

#include <cassert>
#include <string>
#include <vector>

static const char *valid_manifest() {
    return R"({"schemaVersion":2,"generationId":"gen","catalogSha256":"cat",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"forced-ev","entryClass":"E","processes":["system"],"fileIndex":1}],
        "executors":[{"id":"ui-qinggan","entryClass":"Q","processes":["system","setting"],"fileIndex":3}],
        "artifacts":[{"id":"ui","fileIndex":2}]})";
}

static std::vector<std::string> valid_names() {
    return {"agents.dex", "forced-ev.dex", "voboost-ui.apk", "ui-qinggan.dex"};
}

static bool parse(const std::string &manifest, const std::vector<std::string> &names) {
    PipeBootstrapManifest out;
    return parse_pipe_bootstrap_manifest(manifest.data(), manifest.size(), names, &out);
}

int main() {
    try {
        // Baseline: the daemon-produced manifest parses.
        {
            PipeBootstrapManifest out;
            assert(parse_pipe_bootstrap_manifest(valid_manifest(), strlen(valid_manifest()),
                                                 valid_names(), &out));
            assert(out.core_index == 0);
            assert(out.modules.size() == 1 && out.modules[0].file_index == 1);
            assert(out.modules[0].processes == std::vector<std::string>{"system"});
            assert(out.artifacts.size() == 1 && out.artifacts[0].file_index == 2);
            assert(out.executors.size() == 1 && out.executors[0].file_index == 3);
            const std::vector<std::string> expected_processes{"system", "setting"};
            assert(out.executors[0].processes == expected_processes);
        }

        // Duplicate root key (yyjson would silently keep the last).
        assert(!parse(R"({"schemaVersion":2,"schemaVersion":2,"generationId":"g",
        "catalogSha256":"c","desiredJson":"{}","coreFileIndex":0,
        "modules":[],"artifacts":[]})",
                      valid_names()));

        // Duplicate nested key inside a module object.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","id":"b","entryClass":"E","processes":["p"],"fileIndex":1}],
        "artifacts":[]})",
                      valid_names()));

        // Unknown root field (obj size mismatch).
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,"extra":true,
        "modules":[],"artifacts":[]})",
                      valid_names()));

        // Out-of-range file index.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":9}],
        "artifacts":[]})",
                      valid_names()));

        // Boundary: file index == file count. Three files → valid indices are
        // 0,1,2; index 3 is one-past-the-end and must be rejected (not silently
        // wrapping or accepting as the last file).
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":3}],
        "artifacts":[]})",
                      valid_names()));

        // Duplicate index: two modules claiming the same payload.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":1},
                   {"id":"b","entryClass":"E","processes":["p"],"fileIndex":1}],
        "artifacts":[]})",
                      valid_names()));

        // Module claiming the core index 0.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":0}],
        "artifacts":[]})",
                      valid_names()));

        // Nonzero coreFileIndex.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":1,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":0}],
        "artifacts":[]})",
                      valid_names()));

        // Unreferenced sibling payload: no module claims file index 1.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[],"artifacts":[{"id":"ui","fileIndex":2}]})",
                      valid_names()));

        // Duplicate module id.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p"],"fileIndex":1},
                   {"id":"a","entryClass":"F","processes":["q"],"fileIndex":2}],
        "artifacts":[]})",
                      valid_names()));

        // Empty module id.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"","entryClass":"E","processes":["p"],"fileIndex":1}],
        "artifacts":[]})",
                      valid_names()));

        // Process bindings are mandatory, exact and unique.
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":[],"fileIndex":1}],
        "artifacts":[{"id":"ui","fileIndex":2}]})",
                      valid_names()));
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":["p","p"],"fileIndex":1}],
        "artifacts":[{"id":"ui","fileIndex":2}]})",
                      valid_names()));
        assert(!parse(R"({"schemaVersion":2,"generationId":"g","catalogSha256":"c",
        "desiredJson":"{}","coreFileIndex":0,
        "modules":[{"id":"a","entryClass":"E","processes":[""],"fileIndex":1}],
        "artifacts":[{"id":"ui","fileIndex":2}]})",
                      valid_names()));

        // Unsafe file names: traversal, path separator, absolute path.
        assert(!parse(valid_manifest(), std::vector<std::string>{
            "agents.dex", "../evil.dex", "voboost-ui.apk"}));
        assert(!parse(valid_manifest(), std::vector<std::string>{
            "agents.dex", "sub/dir.dex", "voboost-ui.apk"}));
        assert(!parse(valid_manifest(), std::vector<std::string>{
            "/agents.dex", "forced-ev.dex", "voboost-ui.apk"}));
        assert(!parse(valid_manifest(), std::vector<std::string>{
            "agents.dex", "..", "voboost-ui.apk"}));

        // Duplicate file names.
        assert(!parse(valid_manifest(), std::vector<std::string>{
            "agents.dex", "agents.dex", "voboost-ui.apk"}));

        // Truncated/malformed JSON.
        assert(!parse(R"({"schemaVersion":2,)", valid_names()));
        assert(!parse("", valid_names()));

        // The hostile parser must reject an empty inventory before claiming core
        // index zero; this used to write through vector<bool>::operator[](0).
        assert(!parse(valid_manifest(), {}));
        return 0;
    }
    catch (...) {
        return 1;
    }
}
