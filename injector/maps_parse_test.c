#include "maps_parse.h"

#include <stdint.h>
#include <stdio.h>

static int failures;

static void check(int condition, const char *label) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", label);
        failures++;
    }
}

int main(void) {
    struct vbi_map_entry entry;
    check(vbi_parse_map_line(
              "70000000-70012000 r-xp 00000000 fd:00 42 /system/bin/linker64\n",
              &entry),
          "parse canonical linker64");
    check(vbi_map_is_linker(&entry, 1), "exact linker64 accepted");
    check(!vbi_map_is_linker(&entry, 0), "wrong linker bitness rejected");
    size_t offset = 1, size = 1, end = 1;
    check(vbi_map_checked_extent(&entry, VBI_MAX_LINKER_IMAGE_BYTES,
                                 &offset, &size, &end),
          "checked canonical extent");
    check(offset == 0 && size == 0x12000 && end == 0x12000,
          "canonical extent values");

    check(vbi_parse_map_line(
              "70000000-70012000 r-xp 0 fd:00 42 /data/local/tmp/linker64\n",
              &entry),
          "parse attacker basename");
    check(!vbi_map_is_linker(&entry, 1), "substring linker path rejected");
    check(vbi_parse_map_line(
              "70000000-70012000 r-xp 0 fd:00 42 /system/bin/linker64 (deleted)\n",
              &entry),
          "parse deleted linker");
    check(!vbi_map_is_linker(&entry, 1), "deleted linker rejected");

    check(!vbi_parse_map_line(
              "70012000-70000000 r-xp 0 fd:00 42 /system/bin/linker64\n",
              &entry),
          "reversed range rejected");
    check(vbi_parse_map_line(
              "70000000-74000000 r-xp 0 fd:00 42 /system/bin/linker64\n",
              &entry),
          "parse over-cap range");
    check(!vbi_map_checked_extent(&entry, VBI_MAX_LINKER_IMAGE_BYTES,
                                  &offset, &size, &end),
          "over-cap linker image rejected");
    check(vbi_parse_map_line(
              "70000000-70001000 r--p fffffffffffff000 fd:00 42 /system/bin/linker64\n",
              &entry),
          "parse overflowing offset");
    check(!vbi_map_checked_extent(&entry, VBI_MAX_LINKER_IMAGE_BYTES,
                                  &offset, &size, &end),
          "offset addition overflow rejected");

    size_t bytes = 0;
    size_t lines = 0;
    check(vbi_maps_budget_add(128, 1, &bytes, &lines),
          "maps budget accepts complete line");
    check(bytes == 128 && lines == 1, "maps budget accounts exact input");
    check(!vbi_maps_budget_add(128, 0, &bytes, &lines),
          "maps budget rejects truncated line");
    bytes = VBI_MAX_PROC_MAPS_BYTES;
    check(!vbi_maps_budget_add(1, 1, &bytes, &lines),
          "maps byte cap rejects overflow");
    bytes = 0;
    lines = VBI_MAX_PROC_MAPS_LINES;
    check(!vbi_maps_budget_add(1, 1, &bytes, &lines),
          "maps line cap rejects overflow");

    size_t mappings = 0;
    size_t mapped = 0;
    for (size_t i = 0; i < VBI_MAX_LINKER_MAPPINGS; i++) {
        check(vbi_linker_budget_add(1, &mappings, &mapped),
              "linker mapping accepted within count cap");
    }
    check(!vbi_linker_budget_add(1, &mappings, &mapped),
          "linker mapping count cap rejects overflow");
    mappings = 0;
    mapped = VBI_MAX_LINKER_MAPPED_BYTES;
    check(!vbi_linker_budget_add(1, &mappings, &mapped),
          "linker total mapped byte cap rejects overflow");

    check(vbi_parse_map_line(
              "7f000000-80000000 rw-p 0 00:00 0 [stack:42]\n", &entry),
          "parse exact thread stack");
    check(vbi_scratch_range_in_stack(&entry, 42, 0x7ffff000,
                                     0x7fff5000, 0xa000),
          "one contiguous scratch range accepted");
    check(!vbi_scratch_range_in_stack(&entry, 41, 0x7ffff000,
                                      0x7fff5000, 0xa000),
          "different thread stack rejected");
    check(!vbi_scratch_range_in_stack(&entry, 42, 0x7ffff000,
                                      0x7efff000, 0x1000),
          "scratch below mapping rejected");
    check(!vbi_scratch_range_in_stack(&entry, 42, 0x7ffff000,
                                      UINT64_MAX - 1, 8),
          "scratch end overflow rejected");
    struct vbi_scratch_layout layout;
    check(vbi_build_scratch_layout(0x80000000, 128, 256, 32, &layout),
          "scratch layout checked arithmetic succeeds");
    check(layout.path == 0x7fff8000 && layout.config == 0x7fff4000
          && layout.start == 0x7fff1fd0
          && layout.size == 0xe030,
          "scratch layout uses one exact contiguous range");
    check(!vbi_build_scratch_layout(0x1000, 128, 256, 32, &layout),
          "small stack pointer subtraction rejected");
    check(!vbi_build_scratch_layout(0x80000000, 32769, 256, 32, &layout),
          "path crossing stack pointer rejected");
    check(vbi_parse_map_line(
              "7f000000-80000000 r--p 0 00:00 0 [stack:42]\n", &entry),
          "parse read-only stack label");
    check(!vbi_scratch_range_in_stack(&entry, 42, 0x7ffff000,
                                      0x7fff5000, 0xa000),
          "read-only stack rejected");
    check(vbi_parse_map_line(
              "7f000000-80000000 rw-p 0 00:00 0 [stack:42] (deleted)\n", &entry),
          "parse spoofed stack suffix");
    check(!vbi_scratch_range_in_stack(&entry, 42, 0x7ffff000,
                                      0x7fff5000, 0xa000),
          "non-exact stack label rejected");

    check(vbi_parse_map_line(
              "708d7a1000-708d8c1000 r-xp 0 00:00 1 /system/bin/linker64\n", &entry),
          "parse observed Settings linker mapping");
    check(vbi_map_blocks_loader_entry(&entry, 64, 0x708d869ac8, 0x7007957000),
          "Settings original mprotect PC blocks loader reentry");
    check(vbi_map_blocks_loader_entry(&entry, 64, 0x7007957000, 0x708d7c2704),
          "Settings protect_all return address blocks loader reentry");
    check(!vbi_map_blocks_loader_entry(&entry, 64, 0x7007957000, 0x7007957004),
          "unrelated PC and LR do not block entry");
    check(!vbi_map_blocks_loader_entry(&entry, 32, 0x708d869ac8, 0),
          "wrong ABI linker is not accepted");
    check(!vbi_map_blocks_loader_entry(&entry, 64, entry.end, entry.start - 1),
          "linker bounds are half open");
    check(vbi_parse_map_line(
              "1000-2000 r-xp 0 00:00 1 /apex/com.android.runtime/bin/linker\n", &entry),
          "parse ARM32 APEX linker");
    check(vbi_map_blocks_loader_entry(&entry, 32, 0x1001, 0),
          "Thumb PC is normalized before range check");
    check(vbi_map_blocks_loader_entry(&entry, 32, 0, 0x1fff),
          "Thumb return address blocks loader reentry");
    check(!vbi_map_blocks_loader_entry(&entry, 32, 0x2001, 0),
          "Thumb address after mapping is outside");
    check(vbi_parse_map_line(
              "1000-2000 r--p 0 00:00 1 /system/bin/linker64\n", &entry),
          "parse non executable linker mapping");
    check(!vbi_map_blocks_loader_entry(&entry, 64, 0x1100, 0),
          "data mapping does not represent executing linker");
    check(!vbi_map_blocks_loader_entry(NULL, 64, 0x1100, 0),
          "absent mapping is not consumed");

    return failures ? 1 : 0;
}
