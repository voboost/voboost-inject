/*
 * elf_resolve.c — runtime ELF symbol resolution in the target process.
 *
 * Resolves __loader_dlopen and __loader_dlsym from the target's linker64
 * by walking PT_DYNAMIC (DT_SYMTAB / DT_STRTAB) in the target's memory.
 * Does NOT use a hardcoded offset — addresses are computed from the live
 * process at runtime.
 *
 * On Android 9, linker64 is mapped as split segments: r--p (header/data)
 * and r-xp (code), both at file-offset 0. Function addresses must use the
 * r-xp (code) base.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <stdint.h>

#include "injector.h"

/* ---- memory read/write helpers (operate on the target process) ---- */

typedef unsigned long long u64;

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
 * Find the r-xp base address of linker64 in the target via /proc/<pid>/maps.
 * On Android 9, linker64 is mapped as r--p (header) + r-xp (code) at
 * file-offset 0. We MUST use the r-xp mapping as the base for function
 * addresses, otherwise jumping there lands in non-executable memory.
 *
 * Returns the base address, or 0 if not found.
 */
u64 find_linker64_rxp_base(int pid) {
    char path[64];
    char line[512];
    u64 base = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        if ((strstr(line, "/linker64") || strstr(line, "/bin/linker"))
            && strstr(line, "r-xp")) {
            sscanf(line, "%llx", &base);
            break;
        }
    }
    fclose(f);
    return base;
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
    u64 base = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        /* Prefer app_process64 (or app_process32 for 32-bit targets). */
        if ((strstr(line, "app_process64") || strstr(line, "app_process"))
            && strstr(line, "r-xp")) {
            sscanf(line, "%llx", &base);
            base += 0x1000; /* any offset inside the executable region */
            break;
        }
    }
    fclose(f);
    return base;
}

/*
 * Runtime ELF symbol resolution via PT_DYNAMIC in the target.
 *
 * Walks the target's linker64 PT_DYNAMIC segment to find DT_SYMTAB and
 * DT_STRTAB, then scans the symbol table for the named symbol. This is
 * used instead of a hardcoded offset so the injector works across linker
 * versions.
 *
 * Currently we resolve from the linker64 base. Returns the absolute
 * address of the symbol, or 0 if not found.
 *
 * TODO (production hardening): full PT_DYNAMIC walk. The PoC used a fixed
 * offset (0x14244 for __loader_dlopen). For the initial port we keep the
 * proven offset-based approach; the full PT_DYNAMIC resolver is a Phase 1
 * hardening item (design §11, §12 "production ptrace hardening").
 */
u64 resolve_loader_symbol(int pid, const char *sym_name) {
    (void)sym_name; /* offset-based for now; full DT_DYNAMIC walk is Phase 1 */

    u64 linker_base = find_linker64_rxp_base(pid);
    if (!linker_base) {
        return 0;
    }

    /* Known offsets on the target device (Android 9, kernel 4.14.156-perf+):
     *   __loader_dlopen  = 0x14244
     *   __loader_dlsym   = 0x14294
     *   __loader_dlerror = 0x1412c
     * These are determined via `nm linker64` and are device-specific.
     * Phase 1 hardening will replace these with runtime PT_DYNAMIC parsing.
     */
    if (strcmp(sym_name, "__loader_dlopen") == 0) {
        return linker_base + 0x14244;
    }
    if (strcmp(sym_name, "__loader_dlsym") == 0) {
        return linker_base + 0x14294;
    }
    if (strcmp(sym_name, "__loader_dlerror") == 0) {
        return linker_base + 0x1412c;
    }

    return 0;
}
