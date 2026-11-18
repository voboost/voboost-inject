#include "settings_loaded.h"
#include <cassert>
#include <string>

static std::string desired(const std::string &revision, const std::string &generation = "generation") {
    return "{\"generationId\":\"" + generation +
           "\",\"catalogSha256\":\"catalog\",\"documentGeneration\":" + revision +
           ",\"uninstallCleanup\":false,\"agents\":[],\"profile\":{\"startup\":\"none\"}}";
}
int main() {
    SettingsLoaded proof;
    assert(proof.document_generation() == -1);
    // A launcher runtime need not contain the Settings module.
    proof.bootstrap(desired("1770000000000000000"), "generation", "catalog", false);
    assert(!proof.loaded());
    assert(proof.document_generation() == 1770000000000000000LL);
    proof.rejected(desired("1770000000000000001"), desired("1770000000000000001"));
    assert(proof.document_generation() == 1770000000000000000LL);
    for (const auto &bad : {"-1", "null", "\"7\"", "1.5"}) {
        proof.accepted(desired(bad), "generation", "catalog");
        assert(proof.document_generation() == 1770000000000000000LL);
    }
    proof.accepted(desired("99", "foreign"), "generation", "catalog");
    assert(proof.document_generation() == 1770000000000000000LL);
    proof.accepted(desired("1770000000000000002"), "generation", "catalog");
    assert(proof.document_generation() == 1770000000000000002LL);
    proof.reset();
    assert(proof.document_generation() == -1);
}
