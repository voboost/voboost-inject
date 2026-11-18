#ifndef VOBOOST_PW_LIVE_HOST_V1_H
#define VOBOOST_PW_LIVE_HOST_V1_H
#include <stdint.h>
#define VBC_PW_LIVE_HOST_ABI 1u
#define VBC_PW_LIVE_HOST_PATH "voboost.pw.live.v1"
#define VBC_PW_LIVE_HOST_SYMBOL "snapshot"
/* Canonical read-only 64-byte lease ABI. No publication/mutation entry exists.
 * Caller initializes size and abi. Return 1=fresh,0=unknown,-1=ABI mismatch.
 * No value in this record proves OEM lifecycle or rendered visibility. */
typedef struct {
 uint32_t size,abi;
 uint64_t config_revision,endpoint_identity,lifecycle_generation,
          document_generation,observation_sequence;
 uint32_t enabled,desired_disabled,actual,remaining_ms;
} VbcPwLiveHostV1;
typedef int (*VbcPwLiveSnapshotV1)(VbcPwLiveHostV1 *);
#if defined(__cplusplus)
static_assert(sizeof(VbcPwLiveHostV1)==64,"PW live host ABI size");
#endif
#endif
