#ifndef VOBOOST_FONT_LOADER_V1_H
#define VOBOOST_FONT_LOADER_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Optional host capability resolved as vbc_font_loader_v1. remove waits for all
 * admitted transform callbacks. Returned font buffers remain valid for the
 * process lifetime; the host pins the module even after removing callbacks. */
typedef const unsigned char *(*VbcFontTransformV1)(void *, const unsigned char *, size_t, size_t *);
/* Invoked only after the original loader returns. A zero result and a nonzero
 * face_created prove one face accepted the supplied bytes, not UI cache reload. */
typedef void (*VbcFontResultV1)(void *, const unsigned char *, size_t,
    const unsigned char *, size_t, int result, uint32_t face_created);
typedef struct {
    uint32_t abi, size;
    int (*install)(const char *owner, VbcFontTransformV1 transform, void *user);
    int (*remove)(const char *owner);
    /* Optional tail; feature-detect size before access. Removal drains both
     * transform and result callbacks. prior_faces counts successful original
     * loads before installation, so late hooks cannot claim existing faces. */
    int (*install_observed)(const char *owner, VbcFontTransformV1 transform,
        VbcFontResultV1 result, void *user, uint64_t *prior_faces);
} VbcFontLoaderV1;
typedef const VbcFontLoaderV1 *(*VbcFontLoaderEntryV1)(void);
#ifdef __cplusplus
}
#endif
#endif
