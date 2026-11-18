#ifndef VOBOOST_SYSTEM_LOCALE_HOST_V1_H
#define VOBOOST_SYSTEM_LOCALE_HOST_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_SYSTEM_LOCALE_HOST_ABI_V1 1u
typedef enum { VBC_SYSTEM_LOCALE_EN = 1, VBC_SYSTEM_LOCALE_ZH = 2,
    VBC_SYSTEM_LOCALE_RU = 3 } VbcSystemLocaleV1;
typedef enum { VBC_SYSTEM_LOCALE_CONFIRMED = 0,
    VBC_SYSTEM_LOCALE_UNAVAILABLE = 1, VBC_SYSTEM_LOCALE_UNSUPPORTED = 2
} VbcSystemLocaleResultV1;
typedef struct {
    uint32_t size, locale;
    /* Monotonic within lifecycle_generation. Equal revision must retain locale
     * and endpoint_identity. Zero is never a confirmed observation. */
    /* lifecycle_generation strictly increases during the native host lifetime.
     * A different endpoint requires a new lifecycle, even at a newer revision. */
    uint64_t revision, endpoint_identity, lifecycle_generation;
} VbcSystemLocaleObservationV1;
/* Optional read-only capability resolved as vbc_system_locale_host_v1.
 * observe is bounded/atomic, only on an admitted OEM UI frame; no file/network
 * work and no request generation. CONFIRMED means authenticated global Android
 * locale readback for the currently authorized product/endpoint/lifecycle.
 * Agent enable, a desired setting or a queued picker operation are not proof.
 * Producer fences stale callbacks before publication. Other results clear every
 * output field except size. Changing lifecycle invalidates old revisions and
 * requires a fresh confirmed endpoint observation; never reuse cached locale. */
typedef struct {
    uint32_t abi, size;
    VbcSystemLocaleResultV1 (*observe)(VbcSystemLocaleObservationV1 *);
} VbcSystemLocaleHostV1;
typedef const VbcSystemLocaleHostV1 *(*VbcSystemLocaleHostEntryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
