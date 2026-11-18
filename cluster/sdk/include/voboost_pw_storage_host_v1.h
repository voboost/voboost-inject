#ifndef VOBOOST_PW_STORAGE_HOST_V1_H
#define VOBOOST_PW_STORAGE_HOST_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_PW_STORAGE_HOST_ABI 1u
#define VBC_PW_STORAGE_HOST_PATH "voboost.pw.storage.v1"
#define VBC_PW_LOOKUP_HOST_PATH "voboost.pw.lookup.v1"
#define VBC_PW_LOOKUP_NODE_SHARED_BOOST "node-shared-boost-v1"
typedef struct {uint32_t kind,bytes,offset;} VbcPwStorageFieldV1;
typedef struct {
 uint32_t size,abi;
 int (*query)(const char *type,const char *path,VbcPwStorageFieldV1 *out);
} VbcPwStorageHostV1;
/* Fixed read-only factory; null until actual current-light admission finishes.
 * The capability is not lifecycle/PW truth or permission to mutate a property. */
typedef const VbcPwStorageHostV1*(*VbcPwStorageFactoryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
