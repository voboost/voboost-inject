#ifndef VOBOOST_PW_OEM_HOST_V1_H
#define VOBOOST_PW_OEM_HOST_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_PW_OEM_HOST_PATH "voboost.pw.oem.v1"
typedef struct {uint32_t kind,bytes,offset,count;} VbcPwOemFieldV1;
typedef struct {
 uint32_t size,abi,family,reserved;
 uint64_t (*thread_identity)(void);
 uint64_t (*process_identity)(void);
 int (*bind)(const char*method,uint32_t return_kind,void**original);
 void*(*getter)(void);
 int (*field)(const char*method,const char*type,const char*member,VbcPwOemFieldV1*out);
} VbcPwOemHostV1;
/* Read-only proof access; no setter and no hook installation authority. */
typedef const VbcPwOemHostV1*(*VbcPwOemFactoryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
