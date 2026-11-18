#ifndef VBC_SYSTEM_LOCALE_STATE_H
#define VBC_SYSTEM_LOCALE_STATE_H
#include "voboost_system_locale_host_v1.h"
/* Controller only: call after signed desired and current endpoint admission.
 * Not exposed by the module resolver. No caller-supplied authentication flag. */
#ifdef __cplusplus
extern "C" {
#endif
int vbc_system_locale_publish(uint32_t locale, uint64_t revision,
                              uint64_t endpoint, uint64_t lifecycle, uint64_t deadline_ms);
void vbc_system_locale_invalidate(void);
const VbcSystemLocaleHostV1 *vbc_system_locale_host_v1(void);
#ifdef __cplusplus
}
#endif
#endif
