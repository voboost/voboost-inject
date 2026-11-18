#ifndef VOBOOST_NAMESPACE_ABI_H
#define VOBOOST_NAMESPACE_ABI_H

#include <stddef.h>
#include <stdint.h>

/* Private bionic linker constants shared by Android 9 and 11. */
#define VBI_ANDROID_NAMESPACE_TYPE_ISOLATED UINT64_C(1)
#define VBI_ANDROID_DLEXT_USE_NAMESPACE UINT64_C(0x200)

struct vbi_dlextinfo_layout {
    size_t size;
    size_t flags_offset;
    size_t reserved_addr_offset;
    size_t reserved_size_offset;
    size_t relro_fd_offset;
    size_t library_fd_offset;
    size_t library_fd_offset_offset;
    size_t library_namespace_offset;
};

/* Returns the target-ABI layout, never the host compiler's layout. */
int vbi_dlextinfo_layout_for_bitness(int bitness,
                                     struct vbi_dlextinfo_layout *layout);

/* AAPCS32 layout for
 *   (const char *, const char *, const char *, uint64_t,
 *    const char *, void *, const void *)
 * as used by __loader_android_create_namespace. */
struct vbi_namespace32_call_layout {
    uint32_t register_words[4];
    uint32_t stack_words[5];
    size_t stack_word_count;
};

int vbi_build_namespace32_create_layout(
    const uint32_t args[8], struct vbi_namespace32_call_layout *layout);

/* Build the target-ABI android_dlextinfo bytes. Pointers are supplied already
 * narrowed to the target address width by the caller. */
int vbi_build_dlextinfo(int bitness, uint64_t namespace_handle,
                        uint8_t *buffer, size_t buffer_size);

#endif
