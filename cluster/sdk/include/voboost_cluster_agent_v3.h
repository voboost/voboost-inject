#ifndef VOBOOST_CLUSTER_AGENT_V3_H
#define VOBOOST_CLUSTER_AGENT_V3_H
#include "voboost_cluster_v2.h"
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_AGENT_ABI_V3 3u
/* Runtime owns this immutable context and configuration through stop return.
 * report is valid from start entry through stop return; modules must stop all
 * callbacks before returning RESTORED. Module reports cannot claim disabled. */
typedef struct {
    uint32_t abi, size;
    const VbcHostV2 *host;
    const char *id, *domain;
    const VbcKeyValueV2 *configuration;
    uint32_t configuration_count;
    void *report_user;
    void (*report)(void *user, VbcModuleStateV2 state, const char *reason);
} VbcNativeAgentContextV3;
typedef struct {
    uint32_t abi, size;
    const char *id, *domain;
    int (*start)(const VbcNativeAgentContextV3 *context);
    void (*engine_ready)(void);
    void (*frame)(void);
    void (*gauge_data)(const void *input, uint32_t context_count);
    VbcStopOutcomeV2 (*stop)(void);
} VbcNativeAgentV3;
typedef const VbcNativeAgentV3 *(*VbcNativeAgentEntryV3)(void);
/* Exact export name: vbc_native_agent_v3. */
#ifdef __cplusplus
}
#endif
#endif
