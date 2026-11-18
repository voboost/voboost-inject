#include "maps_parse.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

int vbi_parse_map_line(const char *line, struct vbi_map_entry *entry) {
    if (!line || !entry) {
        return 0;
    }
    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long file_offset = 0;
    char perms[5] = {0};
    int path_at = 0;
    int fields = sscanf(line, "%llx-%llx %4s %llx %*x:%*x %*llu %n",
                        &start, &end, perms, &file_offset, &path_at);
    if (fields != 4 || path_at <= 0 || start >= end || strlen(perms) != 4) {
        return 0;
    }
    const char *path = line + path_at;
    while (*path == ' ' || *path == '\t') {
        path++;
    }
    size_t path_len = strcspn(path, "\r\n");
    if (!path_len) {
        return 0;
    }
    entry->start = (uint64_t)start;
    entry->end = (uint64_t)end;
    entry->file_offset = (uint64_t)file_offset;
    memcpy(entry->perms, perms, sizeof(entry->perms));
    entry->path = path;
    entry->path_len = path_len;
    return 1;
}

int vbi_map_path_equals(const struct vbi_map_entry *entry, const char *expected) {
    if (!entry || !expected) {
        return 0;
    }
    size_t expected_len = strlen(expected);
    return entry->path_len == expected_len
           && memcmp(entry->path, expected, expected_len) == 0;
}

int vbi_map_is_linker(const struct vbi_map_entry *entry, int is64) {
    /* API 29+ moves the dynamic linker into the runtime APEX; the emulator
    * (and any modern build) maps it from /apex/com.android.runtime/bin. */
    return vbi_map_path_equals(entry,
                               is64 ? "/apex/com.android.runtime/bin/linker64"
                                    : "/apex/com.android.runtime/bin/linker")
           || vbi_map_path_equals(entry,
                                  is64 ? "/system/bin/linker64"
                                    : "/system/bin/linker");
}

int vbi_map_blocks_loader_entry(const struct vbi_map_entry *entry, int bitness,
                                uint64_t pc, uint64_t lr) {
    if (!entry || (bitness != 32 && bitness != 64)
        || entry->perms[2] != 'x' || !vbi_map_is_linker(entry, bitness == 64)) {
        return 0;
    }
    if (bitness == 32) {
        pc &= ~UINT64_C(1);
        lr &= ~UINT64_C(1);
    }
    return (pc >= entry->start && pc < entry->end)
           || (lr >= entry->start && lr < entry->end);
}

int vbi_map_checked_extent(const struct vbi_map_entry *entry,
                           size_t max_image_bytes, size_t *offset,
                           size_t *size, size_t *end_offset) {
    if (!entry || !offset || !size || !end_offset || entry->start >= entry->end) {
        return 0;
    }
    uint64_t span64 = entry->end - entry->start;
    if (entry->file_offset > SIZE_MAX || span64 > SIZE_MAX) {
        return 0;
    }
    size_t local_offset = (size_t)entry->file_offset;
    size_t local_size = (size_t)span64;
    if (local_offset > max_image_bytes || local_size > max_image_bytes - local_offset) {
        return 0;
    }
    *offset = local_offset;
    *size = local_size;
    *end_offset = local_offset + local_size;
    return 1;
}

int vbi_maps_budget_add(size_t line_bytes, int complete_line,
                        size_t *total_bytes, size_t *total_lines) {
    if (!line_bytes || !complete_line || !total_bytes || !total_lines
        || *total_lines >= VBI_MAX_PROC_MAPS_LINES
        || line_bytes > VBI_MAX_PROC_MAPS_BYTES
        || *total_bytes > VBI_MAX_PROC_MAPS_BYTES - line_bytes) {
        return 0;
    }
    *total_bytes += line_bytes;
    (*total_lines)++;
    return 1;
}

int vbi_linker_budget_add(size_t mapping_bytes, size_t *mapping_count,
                          size_t *total_mapped_bytes) {
    if (!mapping_bytes || !mapping_count || !total_mapped_bytes
        || *mapping_count >= VBI_MAX_LINKER_MAPPINGS
        || mapping_bytes > VBI_MAX_LINKER_MAPPED_BYTES
        || *total_mapped_bytes > VBI_MAX_LINKER_MAPPED_BYTES - mapping_bytes) {
        return 0;
    }
    (*mapping_count)++;
    *total_mapped_bytes += mapping_bytes;
    return 1;
}

int vbi_map_is_exact_thread_stack(const struct vbi_map_entry *entry, int tid) {
    if (!entry || tid <= 0 || entry->perms[0] != 'r' || entry->perms[1] != 'w') {
        return 0;
    }
    if (vbi_map_path_equals(entry, "[stack]")) {
        return 1;
    }
    char expected[48];
    int length = snprintf(expected, sizeof(expected), "[stack:%d]", tid);
    return length > 0 && (size_t)length < sizeof(expected)
           && vbi_map_path_equals(entry, expected);
}

int vbi_scratch_range_in_stack(const struct vbi_map_entry *entry, int tid,
                               uint64_t stack_pointer, uint64_t scratch_start,
                               size_t scratch_size) {
    if (!vbi_map_is_exact_thread_stack(entry, tid) || scratch_size == 0
        || scratch_start > UINT64_MAX - scratch_size) {
        return 0;
    }
    uint64_t scratch_end = scratch_start + scratch_size;
    return stack_pointer >= entry->start && stack_pointer < entry->end
           && scratch_start >= entry->start && scratch_end <= entry->end
           && scratch_end <= stack_pointer;
}

int vbi_build_scratch_layout(uint64_t stack_pointer, size_t path_size,
                             size_t config_size, size_t symbol_size,
                             struct vbi_scratch_layout *layout) {
    enum {
        /* Linker namespace create/link calls may use a deep stack frame;
         * keep the payload path below that frame, not merely below the first
         * ordinary dlopen call frame. */
        PATH_GAP = 32768,
        CONFIG_GAP = 16384,
        AUXILIARY_GAP = 8192,
        SYMBOL_PADDING = 16
    };
    if (!layout || !path_size || !config_size || !symbol_size
        || stack_pointer < PATH_GAP + CONFIG_GAP
        || path_size > PATH_GAP || config_size > CONFIG_GAP) {
        return 0;
    }
    uint64_t path = stack_pointer - PATH_GAP;
    uint64_t config = path - CONFIG_GAP;
    if (symbol_size > config || config - symbol_size < SYMBOL_PADDING) {
        return 0;
    }
    uint64_t symbol = config - symbol_size - SYMBOL_PADDING;
    if (symbol < AUXILIARY_GAP) {
        return 0;
    }
    uint64_t auxiliary = symbol - AUXILIARY_GAP;
    if (stack_pointer - auxiliary > SIZE_MAX) {
        return 0;
    }
    layout->path = path;
    layout->config = config;
    layout->symbol = symbol;
    layout->auxiliary = auxiliary;
    layout->start = auxiliary;
    layout->size = (size_t)(stack_pointer - auxiliary);
    return 1;
}
