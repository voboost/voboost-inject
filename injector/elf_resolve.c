/*
 * elf_resolve.c — runtime ELF symbol resolution in the target process.
 *
 * Resolves __loader_dlopen, __loader_dlsym, and __loader_dlerror from the
 * target's linker (linker64 for 64-bit targets, linker for 32-bit) by
 * walking PT_DYNAMIC (DT_SYMTAB / DT_STRTAB) in the target's memory. Does
 * NOT use a hardcoded offset — addresses are computed from the live
 * process at runtime (injector-linker-reconstruction: runtime ELF symbol resolution).
 *
 * The pure parser (resolve_elf32/64_symbol) is split from target I/O so it
 * can be unit-tested on the host against a real linker image with no ptrace.
 *
 * Android 9 and APEX linkers may use different split PT_LOAD layouts. The
 * resolver reconstructs the mapped file by file offset and derives load bias
 * from every matching live PT_LOAD. The parser handles DT_GNU_HASH-era
 * images by bounded DT_SYMTAB/DT_STRTAB adjacency.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

/* Runtime resolver diagnosis (free-09-chinese 6.0.3: every __loader_* symbol
 * resolved to 0). Same sink as the injector DBG trace. */
#include "native_diagnostic.h"
#define ELFDBG(...) vbi_native_diagnostic("debug", "injector.elf", __VA_ARGS__)

#include "injector.h"
#include "elf_parse.h"
#include "maps_parse.h"

/* ---- memory read/write helpers (operate on the target process) ---- */

typedef unsigned long long u64;
typedef uint8_t u8;

static int maps_line_within_budget(FILE *f, const char *line,
                                   size_t *bytes, size_t *lines) {
    size_t length = strlen(line);
    /* A full buffer without newline is a truncated logical maps record. */
    int complete = length && (line[length - 1] == '\n' || feof(f));
    return vbi_maps_budget_add(length, complete, bytes, lines);
}

/*
 * Read N bytes from target memory at addr.
 * Uses process_vm_readv (efficient).
 */
int target_read_mem(int pid, u64 addr, void *buf, size_t len) {
    if (!buf || len == 0 || addr > UINTPTR_MAX
        || len - 1 > UINTPTR_MAX - (uintptr_t)addr) {
        return -1;
    }
    size_t word_size = sizeof(long);
    if (len > SIZE_MAX - (word_size - 1)) {
        return -1;
    }
    size_t aligned = (len + word_size - 1) & ~(word_size - 1);
    if (aligned - 1 > UINTPTR_MAX - (uintptr_t)addr) {
        return -1;
    }
    struct iovec local = { buf, len };
    struct iovec remote = { (void *)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n != (ssize_t)len) {
        /* Fall back to PTRACE_PEEKDATA word-at-a-time. */
        for (size_t i = 0; i < len; i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
            if (errno != 0) {
                return -1;
            }
            size_t n = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
            memcpy((char *)buf + i, &word, n);
        }
    }
    return 0;
}

/*
 * Write N bytes to target memory at addr.
 * Tries process_vm_writev first, falls back to PTRACE_POKEDATA.
 */
int target_write_mem(int pid, u64 addr, const void *buf, size_t len) {
    enum { MAX_REMOTE_WRITE_BYTES = 64 * 1024 };
    if (!buf || len == 0 || len > MAX_REMOTE_WRITE_BYTES
        || addr > UINTPTR_MAX || len - 1 > UINTPTR_MAX - (uintptr_t)addr) {
        return -1;
    }
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len) {
        return 0;
    }

    /* Fallback: PTRACE_POKEDATA word-at-a-time (arm64 word = 8 bytes).
     * Contract note: the zero-padded tail (up to 7
     * bytes past len) lands in the below-SP scratch area of the stopped
     * target — callers must only use this for scratch writes, never for
     * in-place data where trailing zeros would corrupt live bytes. */
    size_t word_size = sizeof(long);
    if (len > SIZE_MAX - (word_size - 1)) {
        return -1;
    }
    size_t aligned = (len + word_size - 1) & ~(word_size - 1);
    if (aligned - 1 > UINTPTR_MAX - (uintptr_t)addr) {
        return -1;
    }
    char *tmp = (char *)calloc(aligned, 1);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, buf, len);
    for (size_t i = 0; i < aligned; i += sizeof(long)) {
        long word;
        memcpy(&word, tmp + i, sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0) {
            free(tmp);
            return -1;
        }
    }
    free(tmp);
    return 0;
}

/*
 * Verify a memory read matches expected data.
 */
int target_verify_mem(int pid, u64 addr, const void *expected, size_t len) {
    char tmp[256];
    if (!expected || len == 0 || len > sizeof(tmp)) {
        return -1;
    }
    if (target_read_mem(pid, addr, tmp, len) < 0) {
        return -1;
    }
    return memcmp(tmp, expected, len) == 0 ? 0 : -1;
}

/* ---- linker64 base finding ---- */

static u8 *load_linker_image(int pid, int is64, size_t *out_sz);
static size_t collect_linker_mappings(int pid, int is64,
                                      struct vbi_load_mapping *mappings,
                                      size_t capacity);

/* Derive linker load bias from the live PT_LOAD/file-offset correspondence.
 * The old Android 9 r-xp-at-zero shortcut is intentionally not used: APEX
 * linkers and split legacy layouts both pass through the same checked path. */
u64 find_linker_rxp_base(int pid, int is64) {
    size_t image_sz = 0;
    u8 *image = load_linker_image(pid, is64, &image_sz);
    if (!image || !image_sz) {
        free(image);
        return 0;
    }
    struct vbi_load_mapping mappings[VBI_MAX_LINKER_MAPPINGS];
    size_t mapping_count = collect_linker_mappings(
        pid, is64, mappings, VBI_MAX_LINKER_MAPPINGS);
    u64 load_bias = 0;
    int ok = is64
        ? vbi_compute_load_bias64(image, image_sz, mappings, mapping_count,
                                  &load_bias)
        : vbi_compute_load_bias32(image, image_sz, mappings, mapping_count,
                                  &load_bias);
    free(image);
    return ok ? load_bias : 0;
}

/*
 * Find the app_process64 r-xp base in the target — used as caller_addr
 * for __loader_dlopen so the linker resolves the correct namespace.
 * The caller_addr must point inside an executable mapping.
 *
 * Returns a valid caller_addr (base + offset inside r-xp), or 0 if not found.
 */
u64 find_target_caller_addr(int pid) {
    char path[64];
    char line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }

    /*
     * The caller_addr MUST resolve to a registered soinfo (via the linker's
     * find_containing_library) so __loader_dlopen picks the caller's primary
     * namespace. app_process64 is an executable, not a .so — it may not be a
     * registered soinfo, so find_containing_library returns nullptr and the
     * linker falls back to the restrictive anonymous namespace, which rejects
     * /data paths ("library not found"). Prefer a large, always-loaded .so
     * whose r-xp segment is a real PT_LOAD; fall back to app_process64 only
     * if none is found.
     *
     * On Android 9 the bootstrap and ART libraries map from /system; there
     * the ART library resolves to the process's runtime namespace which
     * permits the payload path. On Android 10+ bionic and ART move into APEX
     * modules and map from /apex: the apex libc is a bootstrap library of the
     * DEFAULT namespace, whose ld.config permitted paths include /data — so
     * it must be probed BEFORE the apex libart (whose classloader namespace
     * does not permit /data). Legacy /system paths stay for the Android 9
     * vehicle baseline.
     */
    const char *preferred[] = {
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib/bionic/libc.so",
        "/apex/com.android.art/lib64/libart.so",
        "/apex/com.android.art/lib/libart.so",
        "/system/lib64/libart.so", "/system/lib/libart.so",
        "/system/lib64/libc.so", "/system/lib/libc.so",
        "/system/bin/app_process64", "/system/bin/app_process32"
    };
    u64 base = 0;
    for (size_t i = 0; i < sizeof(preferred) / sizeof(preferred[0]) && !base; i++) {
        if (fseek(f, 0, SEEK_SET) != 0) {
            goto done;
        }
        size_t bytes = 0;
        size_t lines = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!maps_line_within_budget(f, line, &bytes, &lines)) {
                base = 0;
                goto done;
            }
            struct vbi_map_entry entry;
            if (!vbi_parse_map_line(line, &entry)
                || !vbi_map_path_equals(&entry, preferred[i])
                || entry.perms[0] != 'r' || entry.perms[2] != 'x') {
                continue;
            }
            uint64_t span = entry.end - entry.start;
            uint64_t probe = span > 0x4000 ? entry.start + 0x4000
                                          : entry.start + span / 2;
            if (probe < entry.start || probe >= entry.end) {
                base = 0;
                goto done;
            }
            base = probe;
            break;
        }
    }
done:
    fclose(f);
    return base;
}

/* ---- runtime resolver (target I/O) ---- */

/*
 * Read the target's linker image into a flat buffer indexed by file offset.
 *
 * The Android 9 linker is mapped as several segments (r-xp at file-offset 0,
 * r--p/rw-p later) with an alignment gap between them. A single
 * process_vm_readv spanning the gap fails on the whole buffer, so we read each
 * mapping separately and place it in image[mapping_file_off], building a
 * contiguous virtual image the parser can index by p_offset. load_bias is the
 * r-xp base (LOAD #1 has p_vaddr = 0).
 *
 * Returns a malloc'd buffer of size *out_sz (caller frees), or NULL on failure.
 * On success image[file_off..file_off+size] holds each mapping's contents.
 */
static u8 *load_linker_image(int pid, int is64, size_t *out_sz) {
    char path[64];
    char line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;
    }

    /* First pass: find the max file_off+size to size the buffer. */
    size_t image_sz = 0;
    size_t mapped_bytes = 0;
    size_t linker_mappings = 0;
    size_t maps_bytes = 0;
    size_t maps_lines = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!maps_line_within_budget(f, line, &maps_bytes, &maps_lines)) {
            fclose(f);
            return NULL;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(line, &entry) || !vbi_map_is_linker(&entry, is64)) {
            continue;
        }
        size_t file_off = 0;
        size_t size = 0;
        size_t end_off = 0;
        if (!vbi_map_checked_extent(&entry, VBI_MAX_LINKER_IMAGE_BYTES,
                                    &file_off, &size, &end_off)
            || !vbi_linker_budget_add(size, &linker_mappings, &mapped_bytes)) {
            fclose(f);
            return NULL;
        }
        if (end_off > image_sz) {
            image_sz = end_off;
        }
    }
    if (!image_sz) {
        fclose(f);
        return NULL;
    }

    u8 *image = (u8 *)calloc(image_sz, 1);
    if (!image) {
        fclose(f);
        return NULL;
    }

    /* Second pass: read each mapping into image[file_off]. */
    if (fseek(f, 0, SEEK_SET) != 0) {
        free(image);
        fclose(f);
        return NULL;
    }
    maps_bytes = 0;
    maps_lines = 0;
    mapped_bytes = 0;
    linker_mappings = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!maps_line_within_budget(f, line, &maps_bytes, &maps_lines)) {
            free(image);
            fclose(f);
            return NULL;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(line, &entry) || !vbi_map_is_linker(&entry, is64)) {
            continue;
        }
        size_t file_off = 0;
        size_t size = 0;
        size_t end_off = 0;
        if (!vbi_map_checked_extent(&entry, image_sz, &file_off, &size, &end_off)
            || !vbi_linker_budget_add(size, &linker_mappings, &mapped_bytes)
            || end_off > image_sz) {
            free(image);
            fclose(f);
            return NULL;
        }
        /* Only read mappings that the target exposes as readable. The exact
         * pathname check above excludes anonymous/non-file-backed mappings;
         * file offset zero is valid for the executable linker segment. */
        if (entry.perms[0] != 'r') {
            continue;
        }
        if (target_read_mem(pid, entry.start, image + file_off, size) < 0) {
            /* Leave this slice zeroed; the parser fails closed on zeros. */
            continue;
        }
    }
    fclose(f);
    *out_sz = image_sz;
    return image;
}

static size_t collect_linker_mappings(int pid, int is64,
                                      struct vbi_load_mapping *mappings,
                                      size_t capacity) {
    if (!mappings || capacity == 0) {
        return 0;
    }
    char path[64];
    char line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    size_t count = 0;
    size_t bytes = 0;
    size_t lines = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!maps_line_within_budget(f, line, &bytes, &lines)) {
            count = 0;
            break;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(line, &entry)
            || !vbi_map_is_linker(&entry, is64)) {
            continue;
        }
        if (count >= capacity || entry.start >= entry.end) {
            count = 0;
            break;
        }
        mappings[count].start = entry.start;
        mappings[count].end = entry.end;
        mappings[count].file_offset = entry.file_offset;
        mappings[count].executable = entry.perms[2] == 'x';
        count++;
    }
    if (ferror(f)) {
        count = 0;
    }
    fclose(f);
    return count;
}

/*
 * Resolve a __loader_* symbol in the target at runtime via PT_DYNAMIC.
 * bitness selects linker64 (64) vs linker (32) and the Elf64 vs Elf32 parse.
 * Returns the absolute address, or 0 if not found / unreadable.
 *
 * The linker image is assembled mapping-by-mapping (see load_linker_image)
 * so the parser can index it by p_offset across the split mappings. The
 * load bias is derived from every PT_LOAD and its exact live file-offset
 * mapping; no segment layout is assumed.
 */
u64 resolve_loader_symbol(int pid, int bitness, const char *sym_name) {
    if ((bitness != 32 && bitness != 64) || !sym_name || !*sym_name) {
        return 0;
    }
    int is64 = (bitness == 64);
    size_t image_sz = 0;
    u8 *image = load_linker_image(pid, is64, &image_sz);
    if (!image || !image_sz) {
        free(image);
        ELFDBG("resolve %s: image load failed (sz=%zu)", sym_name, image_sz);
        return 0;
    }
    struct vbi_load_mapping mappings[VBI_MAX_LINKER_MAPPINGS];
    size_t mapping_count = collect_linker_mappings(
        pid, is64, mappings, VBI_MAX_LINKER_MAPPINGS);
    u64 load_bias = 0;
    int bias_ok = is64
        ? vbi_compute_load_bias64(image, image_sz, mappings, mapping_count,
                                  &load_bias)
        : vbi_compute_load_bias32(image, image_sz, mappings, mapping_count,
                                  &load_bias);
    if (!bias_ok) {
        free(image);
        ELFDBG("resolve %s: bias failed sz=%zu maps=%zu", sym_name, image_sz,
               mapping_count);
        return 0;
    }
    u64 result = is64 ? resolve_elf64_symbol(image, image_sz, load_bias, sym_name)
                     : resolve_elf32_symbol(image, image_sz, load_bias, sym_name);
    ELFDBG("resolve %s: sz=%zu maps=%zu bias=%#llx magic=%02x%02x%02x%02x -> %#llx",
           sym_name, image_sz, mapping_count, (unsigned long long)load_bias,
           image[0], image[1], image[2], image[3], (unsigned long long)result);
    free(image);
    return result;
}


/* Read the exact mapped libc inode through the target mount namespace. No
 * target instruction, register, or memory is changed during admission. */
int vbi_target_libc_entry_busy(int pid, int bitness, u64 pc, u64 lr) {
    if (bitness != 32 && bitness != 64) {
        return -1;
    }
    char maps_path[64], line[1024], libc_path[256] = {0};
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "re");
    if (!maps) {
        return -1;
    }
    struct vbi_load_mapping mappings[VBI_MAX_LINKER_MAPPINGS];
    size_t count = 0, bytes = 0, lines = 0;
    unsigned device_major = 0, device_minor = 0;
    unsigned long long inode = 0;
    int valid = 1;
    while (fgets(line, sizeof(line), maps)) {
        if (!maps_line_within_budget(maps, line, &bytes, &lines)) {
            valid = 0; break;
        }
        struct vbi_map_entry entry;
        if (!vbi_parse_map_line(line, &entry)) {
            continue;
        }
        const char *legacy = bitness == 64 ? "/system/lib64/libc.so" : "/system/lib/libc.so";
        const char *apex = bitness == 64 ? "/apex/com.android.runtime/lib64/bionic/libc.so"
                                      : "/apex/com.android.runtime/lib/bionic/libc.so";
        if (!vbi_map_path_equals(&entry, legacy) && !vbi_map_path_equals(&entry, apex)) {
            continue;
        }
        unsigned major_value, minor_value;
        unsigned long long inode_value;
        if (sscanf(line, "%*llx-%*llx %*s %*llx %x:%x %llu",
                   &major_value, &minor_value, &inode_value) != 3
            || !inode_value || count >= VBI_MAX_LINKER_MAPPINGS
            || entry.path_len >= sizeof(libc_path)) {
            valid = 0; break;
        }
        if (!count) {
            memcpy(libc_path, entry.path, entry.path_len);
            libc_path[entry.path_len] = 0;
            device_major = major_value; device_minor = minor_value; inode = inode_value;
        } else if (device_major != major_value || device_minor != minor_value
                   || inode != inode_value || !vbi_map_path_equals(&entry, libc_path)) {
            valid = 0; break;
        }
        mappings[count++] = (struct vbi_load_mapping){
            entry.start, entry.end, entry.file_offset, entry.perms[2] == 'x'
        };
    }
    valid = valid && !ferror(maps) && count != 0;
    fclose(maps);
    if (!valid) {
        return -1;
    }
    char path[320];
    int path_length = snprintf(path, sizeof(path), "/proc/%d/root%s", pid, libc_path);
    if (path_length <= 0 || (size_t)path_length >= sizeof(path)) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
        || (unsigned long long)status.st_ino != inode
        || major(status.st_dev) != device_major || minor(status.st_dev) != device_minor
        || status.st_size <= 0 || status.st_size > 16 * 1024 * 1024) {
        close(fd); return -1;
    }
    size_t size = (size_t)status.st_size;
    u8 *image = malloc(size);
    if (!image) {
        close(fd); return -1;
    }
    size_t read_bytes = 0;
    while (read_bytes < size) {
        ssize_t received = read(fd, image + read_bytes, size - read_bytes);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            break;
        }
        read_bytes += (size_t)received;
    }
    close(fd);
    u64 bias = 0;
    int bias_ok = read_bytes == size && (bitness == 64
        ? vbi_compute_load_bias64(image, size, mappings, count, &bias)
        : vbi_compute_load_bias32(image, size, mappings, count, &bias));
    int result = bias_ok ? vbi_elf_libc_entry_busy(image, size, bitness, bias, pc, lr) : -1;
    free(image);
    return result;
}
