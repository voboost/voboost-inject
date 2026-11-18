#ifndef VOBOOST_CLUSTER_V2_H
#define VOBOOST_CLUSTER_V2_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_HOST_ABI_V2 2u
#define VBC_RUNTIME_ABI_V2 2u
#define VBC_MAX_REASON_BYTES 128u
#define VBC_MAX_MODULES 64u
/* All strings are NUL-terminated UTF-8, except reasons: bounded printable ASCII.
 * Call arguments are borrowed for the call. Runtime copies authorization and
 * desired values. The host table remains valid until runtime stop completes. */
typedef struct { const char *key; const char *value; } VbcKeyValueV2;
typedef enum {
    VBC_MODULE_WAITING_UI = 1, VBC_MODULE_APPLIED = 2,
    VBC_MODULE_FAILED = 3, VBC_MODULE_RELOAD_REQUIRED = 4
} VbcModuleStateV2;
typedef enum {
    VBC_STOP_RESTORED = 0, VBC_STOP_RELOAD_REQUIRED = 1, VBC_STOP_FAILED = 2
} VbcStopOutcomeV2;
typedef enum {
    VBC_OBSERVED_WAITING_PROCESS = 1, VBC_OBSERVED_INJECTING = 2,
    VBC_OBSERVED_LOADED = 3, VBC_OBSERVED_WAITING_UI = 4,
    VBC_OBSERVED_APPLIED = 5, VBC_OBSERVED_RESTORING = 6,
    VBC_OBSERVED_DISABLED = 7, VBC_OBSERVED_FAILED = 8,
    VBC_OBSERVED_QUARANTINED = 9, VBC_OBSERVED_RELOAD_REQUIRED = 10
} VbcObservedStateV2;
typedef struct {
    uint32_t size;
    const char *id;
    VbcObservedStateV2 state;
    const char *reason;
    uint64_t desired_revision;
    uint64_t lifecycle_generation;
} VbcModuleObservationV2;
typedef struct {
    uint32_t abi, size;
    void *(*resolve)(const char *library, const char *symbol);
    uint64_t (*monotonic_ms)(void);
    void (*log)(const char *message);
    int (*compatible)(const char *path, const char *build_id);
    /* True only after observing the current attached OEM Screen on UI thread. */
    int (*ui_ready)(void);
    void *report_user;
    void (*report)(void *user, const VbcModuleObservationV2 *observation);
} VbcHostV2;
typedef struct {
    uint32_t size;
    const char *id, *domain, *file, *entry;
    const VbcKeyValueV2 *configuration;
    uint32_t configuration_count;
} VbcAuthorizedModuleV2;
typedef struct {
    uint32_t abi, size;
    const char *catalog_sha256, *generation_id;
    const VbcAuthorizedModuleV2 *modules;
    uint32_t module_count;
} VbcRuntimeAuthorizationV2;
typedef struct {
    uint32_t size;
    const char *id;
    uint32_t enabled;
    const VbcKeyValueV2 *options;
    uint32_t option_count;
} VbcModuleDesiredV2;
typedef struct {
    uint32_t abi, size;
    const char *generation_id, *desired_sha256;
    uint64_t desired_revision;
    const VbcModuleDesiredV2 *modules;
    uint32_t module_count;
} VbcRuntimeDesiredV2;
typedef struct {
    uint32_t abi, size;
    int (*initialize)(const VbcHostV2 *host, const VbcRuntimeAuthorizationV2 *authorization);
    int (*apply_desired)(const VbcRuntimeDesiredV2 *desired);
    void (*engine_init)(void *original, void *info, void *callbacks, void *action, void *name);
    void (*engine_update)(void *original);
    void (*gauge_data)(void *original, void *input, void *output, uint32_t size);
    VbcStopOutcomeV2 (*stop)(void);
} VbcRuntimeV2;
typedef const VbcRuntimeV2 *(*VbcRuntimeEntryV2)(void);
/* Exact export name: vbc_runtime_v2. Late attach never replays engine_init. */
#ifdef __cplusplus
}
#endif
#endif
