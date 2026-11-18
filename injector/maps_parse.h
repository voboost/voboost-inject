#ifndef VOBOOST_MAPS_PARSE_H
#define VOBOOST_MAPS_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define VBI_MAX_PROC_MAPS_BYTES ((size_t)8U * 1024U * 1024U)
#define VBI_MAX_PROC_MAPS_LINES 65536U
#define VBI_MAX_LINKER_IMAGE_BYTES ((size_t)32U * 1024U * 1024U)
#define VBI_MAX_LINKER_MAPPINGS 64U
#define VBI_MAX_LINKER_MAPPED_BYTES ((size_t)32U * 1024U * 1024U)

struct vbi_map_entry {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    char perms[5];
    const char *path;
    size_t path_len;
};

struct vbi_scratch_layout {
    uint64_t path;
    uint64_t config;
    uint64_t symbol;
    uint64_t auxiliary;
    uint64_t start;
    size_t size;
};

int vbi_parse_map_line(const char *line, struct vbi_map_entry *entry);
int vbi_map_path_equals(const struct vbi_map_entry *entry, const char *expected);
int vbi_map_is_linker(const struct vbi_map_entry *entry, int is64);
int vbi_map_blocks_loader_entry(const struct vbi_map_entry *entry, int bitness,
                                uint64_t pc, uint64_t lr);
int vbi_map_checked_extent(const struct vbi_map_entry *entry,
                           size_t max_image_bytes, size_t *offset,
                           size_t *size, size_t *end_offset);
int vbi_maps_budget_add(size_t line_bytes, int complete_line,
                        size_t *total_bytes, size_t *total_lines);
int vbi_linker_budget_add(size_t mapping_bytes, size_t *mapping_count,
                          size_t *total_mapped_bytes);
int vbi_map_is_exact_thread_stack(const struct vbi_map_entry *entry, int tid);
int vbi_scratch_range_in_stack(const struct vbi_map_entry *entry, int tid,
                               uint64_t stack_pointer, uint64_t scratch_start,
                               size_t scratch_size);
int vbi_build_scratch_layout(uint64_t stack_pointer, size_t path_size,
                             size_t config_size, size_t symbol_size,
                             struct vbi_scratch_layout *layout);

#endif
