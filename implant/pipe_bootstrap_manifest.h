#pragma once

// Strict parser for the pipe-bootstrap manifest (the JSON payload inside the
// VOBOOST1 envelope). Hostile-input contract: the manifest arrives over a
// pipe but is still parsed as untrusted. Every object key must be unique,
// file names must be safe unique basenames, the core payload must be file
// index 0, and every declared file must be referenced by exactly one
// manifest index — no unreferenced sibling payload. Header-only so the same
// code is unit-testable on the host and used by implant.cpp on Android.

#include <yyjson.h>

#include <cctype>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

struct PipeBootstrapManifest {
    struct Module {
        std::string id;
        std::string entry_class;
        std::vector<std::string> processes;
        size_t file_index;
    };
    struct Artifact {
        std::string id;
        size_t file_index;
    };
    std::string generation;
    std::string catalog_sha256;
    std::string desired_json;
    size_t core_index;
    std::vector<Module> modules;
    // Catalog kind "executor": started before the first desired-snapshot
    // reconcile, not plan-gated (schemaVersion 2).
    std::vector<Module> executors;
    std::vector<Artifact> artifacts;
};

// Strict unique-key lookup: returns the value only when `key` occurs in the
// object exactly once. Duplicate keys (yyjson would silently keep the last)
// and absent keys both fail closed as nullptr.
inline yyjson_val *pipe_bootstrap_unique_key(yyjson_val *obj, const char *key) {
    yyjson_val *value = nullptr;
    size_t count = 0, index = 0, maximum = 0;
    yyjson_val *item_key = nullptr, *item_value = nullptr;
    yyjson_obj_foreach(obj, index, maximum, item_key, item_value) {
        if (strcmp(yyjson_get_str(item_key), key) == 0) {
            value = item_value;
            count++;
        }
    }
    return count == 1 ? value : nullptr;
}

// File names must be non-empty bounded basenames without traversal or path
// separators, and unique across the envelope.
inline bool pipe_bootstrap_safe_file_name(const std::string &name) {
    if (name.empty() || name.size() > 255) {
        return false;
    }
    if (name.find("..") != std::string::npos) {
        return false;
    }
    for (char c : name) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!(isalnum(u) || c == '-' || c == '_' || c == '.')) {
            return false;
        }
    }
    return true;
}

inline bool parse_pipe_bootstrap_manifest(const char *manifest_data,
                                          size_t manifest_size,
                                          const std::vector<std::string> &file_names,
                                          PipeBootstrapManifest *out) {
    if (!manifest_data || !out || file_names.empty()) {
        return false;
    }
    std::unordered_set<std::string> names;
    for (const auto &name : file_names) {
        if (!pipe_bootstrap_safe_file_name(name) || !names.insert(name).second) {
            return false;
        }
    }

    yyjson_doc *document = yyjson_read(manifest_data, manifest_size, 0);
    if (!document) {
        return false;
    }
    yyjson_val *root = yyjson_doc_get_root(document);
    if (!yyjson_is_obj(root) || yyjson_obj_size(root) != 8) {
        yyjson_doc_free(document);
        return false;
    }
    yyjson_val *schema = pipe_bootstrap_unique_key(root, "schemaVersion");
    yyjson_val *generation = pipe_bootstrap_unique_key(root, "generationId");
    yyjson_val *catalog = pipe_bootstrap_unique_key(root, "catalogSha256");
    yyjson_val *desired = pipe_bootstrap_unique_key(root, "desiredJson");
    yyjson_val *core = pipe_bootstrap_unique_key(root, "coreFileIndex");
    yyjson_val *modules = pipe_bootstrap_unique_key(root, "modules");
    yyjson_val *executors = pipe_bootstrap_unique_key(root, "executors");
    yyjson_val *artifacts = pipe_bootstrap_unique_key(root, "artifacts");
    if (!yyjson_is_uint(schema) || yyjson_get_uint(schema) != 2 || !yyjson_is_str(generation) ||
        !yyjson_is_str(catalog) || !yyjson_is_str(desired) || !yyjson_is_uint(core) ||
        yyjson_get_uint(core) != 0 || !yyjson_is_arr(modules) || !yyjson_is_arr(artifacts) ||
        !yyjson_is_arr(executors)) {
        yyjson_doc_free(document);
        return false;
    }

    std::vector<bool> used(file_names.size(), false);
    used[yyjson_get_uint(core)] = true;
    std::unordered_set<std::string> module_ids;
    std::unordered_set<std::string> artifact_ids;
    bool valid = true;
    auto claim_index = [&](yyjson_val *index_value) -> size_t {
                           if (!yyjson_is_uint(index_value) ||
                               yyjson_get_uint(index_value) >= file_names.size() ||
                               used[yyjson_get_uint(index_value)]) {
                               valid = false;
                               return 0;
                           }
                           size_t slot = yyjson_get_uint(index_value);
                           used[slot] = true;
                           return slot;
                       };
    size_t index, maximum;
    yyjson_val *item;
    // Executors share the exact module shape; ids live in one namespace with
    // modules (a catalog id is either an agent or an executor, never both).
    auto parse_module_array = [&](yyjson_val *array, std::vector<PipeBootstrapManifest::Module> &sink) {
                                  yyjson_arr_foreach(array, index, maximum, item) {
                                      if (!valid || !yyjson_is_obj(item) || yyjson_obj_size(item) != 4) {
                                          valid = false;
                                          break;
                                      }
                                      yyjson_val *id = pipe_bootstrap_unique_key(item, "id");
                                      yyjson_val *entry = pipe_bootstrap_unique_key(item, "entryClass");
                                      yyjson_val *processes = pipe_bootstrap_unique_key(item, "processes");
                                      yyjson_val *file_index = pipe_bootstrap_unique_key(item, "fileIndex");
                                      if (!yyjson_is_str(id) || !*yyjson_get_str(id) || !yyjson_is_str(entry) ||
                                          !*yyjson_get_str(entry) || !yyjson_is_arr(processes) ||
                                          yyjson_arr_size(processes) == 0 || yyjson_arr_size(processes) > 64 ||
                                          !module_ids.insert(yyjson_get_str(id)).second) {
                                          valid = false;
                                          break;
                                      }
                                      std::vector<std::string> declared_processes;
                                      std::unordered_set<std::string> unique_processes;
                                      size_t process_index, process_maximum;
                                      yyjson_val *process;
                                      yyjson_arr_foreach(processes, process_index, process_maximum, process) {
                                          if (!yyjson_is_str(process) || !*yyjson_get_str(process) ||
                                              !unique_processes.insert(yyjson_get_str(process)).second) {
                                              valid = false;
                                              break;
                                          }
                                          declared_processes.emplace_back(yyjson_get_str(process));
                                      }
                                      if (!valid) {
                                          break;
                                      }
                                      size_t slot = claim_index(file_index);
                                      if (!valid) {
                                          break;
                                      }
                                      sink.push_back(
                                          {yyjson_get_str(id), yyjson_get_str(entry), std::move(declared_processes), slot});
                                  }
                              };
    parse_module_array(modules, out->modules);
    if (valid) {
        parse_module_array(executors, out->executors);
    }
    yyjson_arr_foreach(artifacts, index, maximum, item) {
        if (!valid || !yyjson_is_obj(item) || yyjson_obj_size(item) != 2) {
            valid = false;
            break;
        }
        yyjson_val *id = pipe_bootstrap_unique_key(item, "id");
        yyjson_val *file_index = pipe_bootstrap_unique_key(item, "fileIndex");
        if (!yyjson_is_str(id) || !*yyjson_get_str(id) ||
            !artifact_ids.insert(yyjson_get_str(id)).second) {
            valid = false;
            break;
        }
        size_t slot = claim_index(file_index);
        if (!valid) {
            break;
        }
        out->artifacts.push_back({yyjson_get_str(id), slot});
    }
    if (valid) {
        for (bool referenced : used) {
            if (!referenced) {
                valid = false;
                break;
            }
        }
    }
    if (!valid) {
        out->modules.clear();
        out->executors.clear();
        out->artifacts.clear();
        yyjson_doc_free(document);
        return false;
    }
    out->generation = yyjson_get_str(generation);
    out->catalog_sha256 = yyjson_get_str(catalog);
    out->desired_json = yyjson_get_str(desired);
    out->core_index = yyjson_get_uint(core);
    yyjson_doc_free(document);
    return true;
}
