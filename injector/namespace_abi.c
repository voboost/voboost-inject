#include "namespace_abi.h"

#include <string.h>

static void put_u32(uint8_t *buffer, size_t offset, uint32_t value) {
    memcpy(buffer + offset, &value, sizeof(value));
}

static void put_u64(uint8_t *buffer, size_t offset, uint64_t value) {
    memcpy(buffer + offset, &value, sizeof(value));
}

int vbi_dlextinfo_layout_for_bitness(int bitness,
                                     struct vbi_dlextinfo_layout *layout) {
    if (!layout) {
        return 0;
    }
    memset(layout, 0, sizeof(*layout));
    layout->flags_offset = 0;
    layout->relro_fd_offset = bitness == 64 ? 24 : 16;
    layout->library_fd_offset = bitness == 64 ? 28 : 20;
    layout->library_fd_offset_offset = bitness == 64 ? 32 : 24;
    layout->reserved_addr_offset = 8;
    layout->reserved_size_offset = bitness == 64 ? 16 : 12;
    layout->library_namespace_offset = bitness == 64 ? 40 : 32;
    layout->size = bitness == 64 ? 48 : 36;
    return bitness == 32 || bitness == 64;
}

int vbi_build_namespace32_create_layout(
    const uint32_t args[8], struct vbi_namespace32_call_layout *layout) {
    if (!args || !layout) {
        return 0;
    }
    memset(layout, 0, sizeof(*layout));
    /* r0-r2 carry the first three pointers. The aligned uint64_t starts at
     * stack[0], so r3 is intentionally unused. */
    layout->register_words[0] = args[0];
    layout->register_words[1] = args[1];
    layout->register_words[2] = args[2];
    layout->stack_words[0] = args[3];
    layout->stack_words[1] = args[4];
    layout->stack_words[2] = args[5];
    layout->stack_words[3] = args[6];
    layout->stack_words[4] = args[7];
    layout->stack_word_count = 5;
    return 1;
}

int vbi_build_dlextinfo(int bitness, uint64_t namespace_handle,
                        uint8_t *buffer, size_t buffer_size) {
    struct vbi_dlextinfo_layout layout;
    if (!buffer || !vbi_dlextinfo_layout_for_bitness(bitness, &layout)
        || buffer_size < layout.size
        || (bitness == 32 && namespace_handle > UINT32_MAX)) {
        return 0;
    }
    memset(buffer, 0, layout.size);
    put_u64(buffer, layout.flags_offset, VBI_ANDROID_DLEXT_USE_NAMESPACE);
    if (bitness == 64) {
        put_u64(buffer, layout.library_namespace_offset, namespace_handle);
    } else {
        put_u32(buffer, layout.library_namespace_offset,
                (uint32_t)namespace_handle);
    }
    return 1;
}
