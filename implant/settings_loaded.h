#pragma once

#include "pipe_bootstrap_manifest.h"

#include <atomic>
#include <string>

// Only the owned loader and accepted native downlink upcall update this proof.
class SettingsLoaded {
public:
int64_t document_generation() const {
    return document_generation_.load(std::memory_order_acquire);
}
bool loaded() const {
    return loaded_.load(std::memory_order_acquire);
}
void reset() {
    loaded_.store(false, std::memory_order_release);
    document_generation_.store(-1, std::memory_order_release);
}
void rejected(const std::string &attempt, const std::string &current) {
    // Called under the native downlink mutex: a stale Java rejection cannot
    // revoke proof while a newer root-owned document awaits its own apply.
    if (attempt == current) {
        loaded_.store(false, std::memory_order_release);
    }
}

void bootstrap(const std::string &document, const std::string &generation,
               const std::string &catalog, bool module_loaded) {
    reset();
    accepted(document, generation, catalog);
    if (!module_loaded) loaded_.store(false, std::memory_order_release);
}

void accepted(const std::string &document, const std::string &generation,
              const std::string &catalog) {
    yyjson_doc *parsed = yyjson_read(document.data(), document.size(), 0);
    bool eligible = false;
    if (parsed) {
        yyjson_val *root = yyjson_doc_get_root(parsed);
        yyjson_val *gen = pipe_bootstrap_unique_key(root, "generationId");
        yyjson_val *cat = pipe_bootstrap_unique_key(root, "catalogSha256");
        yyjson_val *revision = pipe_bootstrap_unique_key(root, "documentGeneration");
        if (yyjson_is_str(gen) && generation == yyjson_get_str(gen) &&
            yyjson_is_str(cat) && catalog == yyjson_get_str(cat) &&
            yyjson_is_int(revision) && yyjson_get_sint(revision) >= 0) {
            document_generation_.store(yyjson_get_sint(revision), std::memory_order_release);
        }
        yyjson_val *cleanup = pipe_bootstrap_unique_key(root, "uninstallCleanup");
        yyjson_val *agents = pipe_bootstrap_unique_key(root, "agents");
        yyjson_val *profile = pipe_bootstrap_unique_key(root, "profile");
        yyjson_val *startup = pipe_bootstrap_unique_key(profile, "startup");
        if (yyjson_is_str(gen) && generation == yyjson_get_str(gen) &&
            yyjson_is_str(cat) && catalog == yyjson_get_str(cat) &&
            yyjson_is_bool(cleanup) && !yyjson_get_bool(cleanup) &&
            yyjson_is_arr(agents) && yyjson_is_str(startup)) {
            std::string mode = yyjson_get_str(startup);
            bool permitted = mode == "interface" ||
                             (loaded() && (mode == "hidden" || mode == "none"));
            size_t index, maximum;
            yyjson_val *entry;
            yyjson_arr_foreach(agents, index, maximum, entry) {
                yyjson_val *id = pipe_bootstrap_unique_key(entry, "id");
                yyjson_val *enabled = pipe_bootstrap_unique_key(entry, "enabled");
                if (yyjson_is_str(id) && std::string(yyjson_get_str(id)) == "settings" &&
                    yyjson_is_true(enabled) && permitted) {
                    eligible = true;
                }
            }
        }
        yyjson_doc_free(parsed);
    }
    loaded_.store(eligible, std::memory_order_release);
}

private:
std::atomic<bool> loaded_{false};
std::atomic<int64_t> document_generation_{-1};
};
