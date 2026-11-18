#ifndef VBC_LOCALE_OBJECT_HOST_V1_H
#define VBC_LOCALE_OBJECT_HOST_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_LOCALE_OBJECT_HOST_ABI_V1 1u
typedef enum { VBC_LOCALE_SCREEN_OBJECT=1, VBC_LOCALE_DICTIONARY_SELECTOR_OBJECT=2 } VbcLocaleObjectKindV1;
/* Read-only, owning UI-frame capability. The caller must retain its genuine
 * strong reference across the returned borrowed subobject/descriptor use.
 * The host independently matches the live current Screen/Locales selector and
 * uses the loaded GNU RTTI upcast; no firmware member offset is assumed. */
typedef struct {
 uint32_t abi,size;
 void *(*property_object)(VbcLocaleObjectKindV1,void *pinned_object);
 /* Address of the original OEM PropertyType slot, after its concrete descriptor
  * type was checked. SCREEN => string; SELECTOR => shared_ptr<Resource>. */
 const void *(*property_descriptor)(VbcLocaleObjectKindV1);
 /* Preparation performs no work on the caller; current_owner returns zero
  * until the actual executable role and structural probes are admitted. */
 int (*prepare_current)(void);
 uint32_t (*current_owner)(void);
 /* Actual attached Screen on its observed UI frame; no OEM calls before admission. */
 int (*ui_ready)(void);
} VbcLocaleObjectHostV1;
typedef const VbcLocaleObjectHostV1 *(*VbcLocaleObjectHostEntryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
