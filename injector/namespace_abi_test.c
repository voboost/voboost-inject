#include "namespace_abi.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

int main(void) {
    struct vbi_dlextinfo_layout layout;
    check(vbi_dlextinfo_layout_for_bitness(64, &layout), "arm64 layout");
    check(layout.size == 48 && layout.library_namespace_offset == 40,
          "arm64 extinfo size/namespace offset");
    check(vbi_dlextinfo_layout_for_bitness(32, &layout), "arm32 layout");
    check(layout.size == 36 && layout.library_namespace_offset == 32,
          "arm32 extinfo size/namespace offset");
    check(!vbi_dlextinfo_layout_for_bitness(16, &layout), "reject unknown ABI");

    uint32_t args[8] = {1, 2, 3, 0x11223344U, 0x55667788U, 6, 7, 8};
    struct vbi_namespace32_call_layout call;
    check(vbi_build_namespace32_create_layout(args, &call), "arm32 call layout");
    check(call.register_words[0] == 1 && call.register_words[1] == 2
          && call.register_words[2] == 3 && call.register_words[3] == 0,
          "arm32 pointer registers and aligned r3 hole");
    check(call.stack_word_count == 5 && call.stack_words[0] == 0x11223344U
          && call.stack_words[1] == 0x55667788U
          && call.stack_words[2] == 6 && call.stack_words[3] == 7
          && call.stack_words[4] == 8,
          "arm32 uint64 and trailing stack arguments");

    uint8_t bytes[48];
    memset(bytes, 0xff, sizeof(bytes));
    check(vbi_build_dlextinfo(64, UINT64_C(0x1122334455667788), bytes,
                              sizeof(bytes)), "arm64 extinfo serialization");
    uint64_t value = 0;
    memcpy(&value, bytes + 40, sizeof(value));
    check(value == UINT64_C(0x1122334455667788),
          "arm64 namespace pointer serialization");
    check(!vbi_build_dlextinfo(32, UINT64_C(0x100000000), bytes,
                               sizeof(bytes)), "reject wide arm32 pointer");

    return failures ? 1 : 0;
}
