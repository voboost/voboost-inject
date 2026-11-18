#ifndef VBC_STOCK_LOCALE_HOST_V2_H
#define VBC_STOCK_LOCALE_HOST_V2_H
#include "voboost_locale_host_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_STOCK_LOCALE_HOST_ABI_V2 2u
#define VBC_STOCK_LOCALE_URI_BYTES 256u
/* Actual live OEM objects and measured dictionary coverage, not file digests,
 * caller options, or a claimed complete/readiness boolean. */
typedef struct {
 uint32_t size,owner,origin_kind;
 uint64_t project_epoch,resource_epoch,screen_identity,manager_identity,directory_identity;
 uint32_t english_entries,russian_entries,matched_entries;
 char dictionary_uri[3][VBC_STOCK_LOCALE_URI_BYTES];
 uint64_t dictionary_identity[3];
} VbcStockLocaleSnapshotV2;
typedef struct {
 uint32_t abi,size;
 VbcLocaleResultV1 (*prepare)(VbcLocaleOwnerV1);
 VbcLocaleResultV1 (*observe)(VbcStockLocaleSnapshotV2 *);
} VbcStockLocaleHostV2;
typedef const VbcStockLocaleHostV2 *(*VbcStockLocaleHostEntryV2)(void);
#ifdef __cplusplus
}
#endif
#endif
