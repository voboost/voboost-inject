/*
 * elf_resolve.c — runtime ELF symbol resolution in the target process.
 *
 * Resolves __loader_dlopen, __loader_dlsym, and __loader_dlerror from the
 * target's linker (linker64 for 64-bit targets, linker for 32-bit) by
 * walking PT_DYNAMIC (DT_SYMTAB / DT_STRTAB) in the target's memory. Does
 * NOT use a hardcoded offset — addresses are computed from the live
 * process at runtime (native-payload: runtime ELF symbol resolution).
 *
 * The pure parser (resolve_elf32/64_symbol) is split from target I/O so it
 * can be unit-tested on the host against a real linker image with no ptrace.
 *
 * On Android 9, linker64 is mapped as split segments: r--p (header/data)
 * and r-xp (code), both at file-offset 0. load_bias = the r-xp base (LOAD #1
 * has p_vaddr = 0), and load_bias + p_vaddr reaches PT_DYNAMIC and the
 * .dynsym/.dynstr tables. The Android 9 linker carries only DT_GNU_HASH
 * (no DT_HASH), so the symbol count is derived from DT_SYMTAB/DT_STRTAB
 * adjacency: (DT_STRTAB - DT_SYMTAB) / DT_SYMENT.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <stdint.h>

#include "injector.h"
#include "elf_parse.h"

/* ---- memory read/write helpers (operate on the target process) ---- */

typedef unsigned long long u64;
typedef uint8_t u8;

/*
 * Read N bytes from target memory at addr.
 * Uses process_vm_readv (efficient).
 */
int target_read_mem(int pid, u64 addr, void *buf, size_t len) {
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
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len) {
        return 0;
    }

    /* Fallback: PTRACE_POKEDATA word-at-a-time (arm64 word = 8 bytes). */
    size_t aligned = (len + 7) & ~7UL;
    char tmp[aligned];
    memset(tmp, 0, aligned);
    memcpy(tmp, buf, len);
    for (size_t i = 0; i < aligned; i += sizeof(long)) {
        long word;
        memcpy(&word, tmp + i, sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Verify a memory read matches expected data.
 */
int target_verify_mem(int pid, u64 addr, const void *expected, size_t len) {
    char tmp[256];
    if (len > sizeof(tmp)) {
        len = sizeof(tmp);
    }
    if (target_read_mem(pid, addr, tmp, len) < 0) {
        return -1;
    }
    return memcmp(tmp, expected, len) == 0 ? 0 : -1;
}

/* ---- linker64 base finding ---- */

/*
 * Find the r-xp base address of the target's linker in /proc/<pid>/maps.
 * For 64-bit targets this is /system/bin/linker64; for 32-bit it is
 * /system/bin/linker. On Android 9 the linker is mapped as r--p (header)
 * + r-xp (code) at file-offset 0; load_bias = the r-xp base (LOAD #1 has
 * p_vaddr = 0), and load_bias + p_vaddr reaches PT_DYNAMIC and the
 * .dynsym/.dynstr tables. We MUST use the r-xp mapping as load_bias,
 * otherwise computed addresses land in non-executable memory.
 *
 * Returns the load_bias, or 0 if not found.
 */
u64 find_linker_rxp_base(int pid, int is64) {
    char path[64];
    char line[512];
    u64 base = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    const char *needle = is64 ? "/linker64" : "/bin/linker";
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle) && strstr(line, "r-xp")) {
            sscanf(line, "%llx", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

/*
 * Deprecated 64-bit-only alias; kept for any external caller. New code
 * should call find_linker_rxp_base(pid, 1).
 */
u64 find_linker64_rxp_base(int pid) {
    return find_linker_rxp_base(pid, 1);
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
    char line[512];
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
     * (libart.so, then libc.so) whose r-xp segment is a real PT_LOAD; fall
     * back to app_process64 only if neither is found.
     */
    const char *preferred[] = { "libart.so", "libc.so", "app_process64",
                                "app_process32", "app_process" };
    u64 base = 0;
    for (size_t i = 0; i < sizeof(preferred) / sizeof(preferred[0]) && !base; i++) {
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, preferred[i]) && strstr(line, "r-xp")) {
                sscanf(line, "%llx", &base);
                /* +0x4000: well inside the text segment, past any ELF header. */
                base += 0x4000;
                break;
            }
        }
    }
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
    char line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;
    }

    const char *needle = is64 ? "/linker64" : "/bin/linker";

    /* First pass: find the max file_off+size to size the buffer. */
    size_t image_sz = 0;
    rewind(f);
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, needle)) {
            continue;
        }
        u64 start, end;
        unsigned long file_off;
        char perms[8];
        /* addr-range perms offset ... */
        if (sscanf(line, "%llx-%llx %7s %lx", &start, &end, perms, &file_off) < 4) {
            continue;
        }
        size_t size = (size_t)(end - start);
        size_t end_off = (size_t)file_off + size;
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
    rewind(f);
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, needle)) {
            continue;
        }
        u64 start, end;
        unsigned long file_off;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s %lx", &start, &end, perms, &file_off) < 4) {
            continue;
        }
        /* Skip non-file-backed mappings (file_off 0 with no path is fine; the
         * r-xp at file_off 0 IS the one we want). We only need read-capable
         * mappings; skip rw-p private (writable .data/.bss) — not needed for
         * symbol resolution. */
        if (!strchr(perms, 'r')) {
            continue;
        }
        size_t size = (size_t)(end - start);
        if (file_off + size > image_sz) {
            continue;
        }
        if (target_read_mem(pid, start, image + file_off, size) < 0) {
            /* Leave this slice zeroed; the parser fails closed on zeros. */
            continue;
        }
    }
    fclose(f);
    *out_sz = image_sz;
    return image;
}

/*
 * Resolve a __loader_* symbol in the target at runtime via PT_DYNAMIC.
 * bitness selects linker64 (64) vs linker (32) and the Elf64 vs Elf32 parse.
 * Returns the absolute address, or 0 if not found / unreadable.
 *
 * The linker image is assembled mapping-by-mapping (see load_linker_image)
 * so the parser can index it by p_offset across the r-xp/r--p gap. load_bias
 * = the r-xp base; load_bias + p_vaddr reaches every address the parser
 * touches (verified on the Android 9 device).
 */
u64 resolve_loader_symbol(int pid, int bitness, const char *sym_name) {
    int is64 = (bitness == 64);
    u64 load_bias = find_linker_rxp_base(pid, is64);
    if (!load_bias) {
        return 0;
    }

    size_t image_sz = 0;
    u8 *image = load_linker_image(pid, is64, &image_sz);
    if (!image || !image_sz) {
        free(image);
        return 0;
    }
    u64 result = is64 ? resolve_elf64_symbol(image, image_sz, load_bias, sym_name)
                     : resolve_elf32_symbol(image, image_sz, load_bias, sym_name);
    free(image);
    return result;
}
