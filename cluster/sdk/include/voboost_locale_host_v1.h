#ifndef VOBOOST_LOCALE_HOST_V1_H
#define VOBOOST_LOCALE_HOST_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_LOCALE_HOST_ABI_V1 1u
#define VBC_LOCALE_NAME_BYTES 32u
typedef enum { VBC_LOCALE_GAUGE = 1, VBC_LOCALE_POINT = 2,
    VBC_LOCALE_LIGHT = 3, VBC_LOCALE_IGNOFF = 4 } VbcLocaleOwnerV1;
typedef enum { VBC_LOCALE_OK = 0, VBC_LOCALE_UNSUPPORTED = 1,
    VBC_LOCALE_WAITING_UI = 2, VBC_LOCALE_READBACK_FAILED = 3,
    VBC_LOCALE_WAITING_IDENTITY = 4 } VbcLocaleResultV1;
enum { VBC_LOCALE_CAN_OBSERVE = 1u };
typedef struct {
    uint32_t size, owner, capabilities;
    /* Opaque current Screen identity, valid only during this frame. Never retain
     * or dereference it. A changed identity invalidates the prior observation. */
    uint64_t screen_identity;
    char locale[VBC_LOCALE_NAME_BYTES];
} VbcLocaleObservationV1;
/* Optional capability resolved as vbc_locale_host_v1. This version observes the
 * actual OEM Node.Locale property. It does not admit resource loading or locale
 * selection. Success is fresh readback on the owner's verified UI frame;
 * WAITING_IDENTITY, WAITING_UI and UNSUPPORTED never mean applied. No C++ object crosses this ABI. */
typedef struct {
    uint32_t abi, size;
    VbcLocaleResultV1 (*observe)(VbcLocaleOwnerV1 owner, VbcLocaleObservationV1 *out);
    /* Starts one detached identity worker. Returns WAITING_IDENTITY until its
     * receipt is ready; performs no filesystem work in the caller. Explicitly
     * call before observe. Observation never starts preparation or waits. */
    VbcLocaleResultV1 (*prepare)(VbcLocaleOwnerV1 owner);
} VbcLocaleHostV1;
typedef const VbcLocaleHostV1 *(*VbcLocaleHostEntryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
