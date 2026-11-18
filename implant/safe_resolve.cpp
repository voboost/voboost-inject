/*
 * safe_resolve.cpp — bounded resolver for symbols in an already loaded ELF.
 *
 * ART is selected from the linker's live object list. This deliberately does
 * not open a second ART, ask RTLD_DEFAULT for a namespace-limited symbol, or
 * depend on optional .symtab sections in an OEM image.
 */

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// Defined by the implant; standalone resolver builds use the weak no-op below.
void vbi_symtab_trace(const char *stage, const char *detail, long value);

#include "bounded_elf_string.h"

namespace {

constexpr size_t kMaxProgramHeaders = 256;
constexpr size_t kMaxDynamicEntries = 4096;
constexpr size_t kMaxDynamicSymbols = 1U << 20;
constexpr size_t kMaxStringTable = 16U << 20;

struct LoadedModule {
    uintptr_t base;
    const ElfW(Phdr) *phdrs;
    size_t phnum;
};

static bool add_overflow(uintptr_t left, uintptr_t right, uintptr_t *result) {
    if (!result || left > UINTPTR_MAX - right) {
        return true;
    }
    *result = left + right;
    return false;
}

static bool range_in_module(const LoadedModule &module, uintptr_t address,
                            size_t length, bool executable_only) {
    if (!module.phdrs || module.phnum == 0 || module.phnum > kMaxProgramHeaders) {
        return false;
    }
    for (size_t i = 0; i < module.phnum; i++) {
        const ElfW(Phdr) &ph = module.phdrs[i];
        if (ph.p_type != PT_LOAD || (executable_only && !(ph.p_flags & PF_X))) {
            continue;
        }
        uintptr_t start = 0;
        if (add_overflow(module.base, static_cast<uintptr_t>(ph.p_vaddr), &start)
            || address < start || address - start > ph.p_memsz
            || length > ph.p_memsz - (address - start)) {
            continue;
        }
        return true;
    }
    return false;
}

static uintptr_t dynamic_address(const LoadedModule &module, ElfW(Addr) value) {
    uintptr_t address = 0;
    return add_overflow(module.base, static_cast<uintptr_t>(value), &address)
        ? 0
        : address;
}

static size_t dynamic_symbol_count(const LoadedModule &module,
                                   uintptr_t hash_address,
                                   uintptr_t gnu_hash_address) {
    if (hash_address != 0) {
        const uint32_t *hash = reinterpret_cast<const uint32_t *>(hash_address);
        if (!range_in_module(module, hash_address, 2 * sizeof(uint32_t), false)) {
            return 0;
        }
        uint32_t buckets = hash[0];
        uint32_t chains = hash[1];
        uintptr_t words = 0;
        if (buckets > kMaxDynamicSymbols || chains > kMaxDynamicSymbols
            || __builtin_add_overflow(static_cast<uintptr_t>(2),
                                      static_cast<uintptr_t>(buckets), &words)
            || __builtin_add_overflow(words, static_cast<uintptr_t>(chains), &words)
            || __builtin_mul_overflow(words, sizeof(uint32_t), &words)
            || !range_in_module(module, hash_address, static_cast<size_t>(words), false)) {
            return 0;
        }
        return chains;
    }

    if (gnu_hash_address == 0
        || !range_in_module(module, gnu_hash_address, 4 * sizeof(uint32_t), false)) {
        return 0;
    }
    const uint32_t *header = reinterpret_cast<const uint32_t *>(gnu_hash_address);
    uint32_t bucket_count = header[0];
    uint32_t symbol_offset = header[1];
    uint32_t bloom_count = header[2];
    if (bucket_count == 0 || bloom_count == 0 || symbol_offset > kMaxDynamicSymbols) {
        return 0;
    }
    uintptr_t buckets_address = gnu_hash_address + 16;
    uintptr_t chains_address = buckets_address
                               + static_cast<uintptr_t>(bloom_count) * sizeof(ElfW(Addr));
    if (buckets_address < gnu_hash_address
        || chains_address < buckets_address
        || !range_in_module(module, buckets_address,
                            static_cast<size_t>(bucket_count) * sizeof(uint32_t), false)) {
        return 0;
    }
    const uint32_t *buckets = reinterpret_cast<const uint32_t *>(buckets_address);
    size_t maximum = symbol_offset;
    for (uint32_t i = 0; i < bucket_count; i++) {
        uint32_t symbol = buckets[i];
        if (symbol < symbol_offset) {
            continue;
        }
        for (size_t steps = 0; steps < kMaxDynamicSymbols; steps++, symbol++) {
            uintptr_t chain_address = chains_address
                                      + static_cast<uintptr_t>(symbol - symbol_offset) * sizeof(uint32_t);
            if (chain_address < chains_address
                || !range_in_module(module, chain_address, sizeof(uint32_t), false)) {
                return 0;
            }
            uint32_t chain = *reinterpret_cast<const uint32_t *>(chain_address);
            if (symbol > maximum) {
                maximum = symbol;
            }
            if (chain & 1U) {
                break;
            }
            if (symbol == UINT32_MAX) {
                return 0;
            }
        }
    }
    return maximum + 1;
}

static void *resolve_from_loaded_module(const LoadedModule &module,
                                        const char *symbol_name) {
    uintptr_t dynamic_address_value = 0;
    size_t dynamic_size = 0;
    for (size_t i = 0; i < module.phnum; i++) {
        const ElfW(Phdr) &ph = module.phdrs[i];
        if (ph.p_type == PT_DYNAMIC) {
            dynamic_address_value = dynamic_address(module, ph.p_vaddr);
            if (!dynamic_address_value || ph.p_memsz < sizeof(ElfW(Dyn))
                || ph.p_memsz > kMaxDynamicEntries * sizeof(ElfW(Dyn))) {
                return nullptr;
            }
            dynamic_size = static_cast<size_t>(ph.p_memsz);
            break;
        }
    }
    if (!dynamic_address_value || !range_in_module(
            module, dynamic_address_value, dynamic_size, false)) {
        return nullptr;
    }

    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t hash = 0;
    uintptr_t gnu_hash = 0;
    size_t strsz = 0;
    size_t syment = 0;
    bool terminated = false;
    const ElfW(Dyn) *dynamic = reinterpret_cast<const ElfW(Dyn) *>(dynamic_address_value);
    for (size_t i = 0; i < dynamic_size / sizeof(ElfW(Dyn)); i++) {
        const ElfW(Dyn) &entry = dynamic[i];
        if (entry.d_tag == DT_NULL) {
            terminated = true;
            break;
        }
        switch (entry.d_tag) {
        case DT_SYMTAB: symtab = dynamic_address(module, entry.d_un.d_ptr); break;
        case DT_STRTAB: strtab = dynamic_address(module, entry.d_un.d_ptr); break;
        case DT_STRSZ: strsz = static_cast<size_t>(entry.d_un.d_val); break;
        case DT_SYMENT: syment = static_cast<size_t>(entry.d_un.d_val); break;
        case DT_HASH: hash = dynamic_address(module, entry.d_un.d_ptr); break;
        case DT_GNU_HASH: gnu_hash = dynamic_address(module, entry.d_un.d_ptr); break;
        default: break;
        }
    }
    if (!terminated || !symtab || !strtab || !strsz || strsz > kMaxStringTable
        || syment != sizeof(ElfW(Sym))
        || !range_in_module(module, strtab, strsz, false)) {
        return nullptr;
    }
    size_t count = dynamic_symbol_count(module, hash, gnu_hash);
    if (count == 0 || count > kMaxDynamicSymbols
        || count > SIZE_MAX / sizeof(ElfW(Sym))) {
        /* Fallback: when the GNU hash table parser returns 0, scan .dynsym
         * linearly. Validate each symbol's address individually. */
        const ElfW(Sym) *symbols = reinterpret_cast<const ElfW(Sym) *>(symtab);
        const char *strings = reinterpret_cast<const char *>(strtab);
        vbi_symtab_trace("linear-scan", symbol_name, 0);
        for (size_t i = 0; i < kMaxDynamicSymbols; i++) {
            uintptr_t sym_addr = symtab + i * sizeof(ElfW(Sym));
            if (!range_in_module(module, sym_addr, sizeof(ElfW(Sym)), false)) {
                break;
            }
            const ElfW(Sym) &symbol = symbols[i];
            if (symbol.st_shndx == SHN_UNDEF || symbol.st_name >= strsz) {
                continue;
            }
            const char *name = strings + symbol.st_name;
            size_t remaining = strsz - symbol.st_name;
            size_t name_length = strlen(symbol_name);
            if (name_length >= remaining
                || !bounded_elf_string_equals(name, strings + strsz, symbol_name)) {
                continue;
            }
            uintptr_t address = dynamic_address(module, symbol.st_value);
            if (address != 0 && range_in_module(module, address, 1, true)) {
                return reinterpret_cast<void *>(address);
            }
        }
        return nullptr;
    }
    size_t table_size = count * sizeof(ElfW(Sym));
    if (!range_in_module(module, symtab, table_size, false)) {
        return nullptr;
    }

    const ElfW(Sym) *symbols = reinterpret_cast<const ElfW(Sym) *>(symtab);
    const char *strings = reinterpret_cast<const char *>(strtab);
    for (size_t i = 0; i < count; i++) {
        const ElfW(Sym) &symbol = symbols[i];
        if (symbol.st_shndx == SHN_UNDEF || symbol.st_name >= strsz) {
            continue;
        }
        const char *name = strings + symbol.st_name;
        size_t remaining = strsz - symbol.st_name;
        size_t name_length = strlen(symbol_name);
        if (name_length >= remaining
            || !bounded_elf_string_equals(name, strings + strsz, symbol_name)) {
            continue;
        }
        uintptr_t address = dynamic_address(module, symbol.st_value);
        if (address != 0 && range_in_module(module, address, 1, true)) {
            return reinterpret_cast<void *>(address);
        }
    }
    return nullptr;
}

struct ResolveContext {
    const char *library;
    const char *symbol;
    void *result;
    size_t matches;
};

static int resolve_loaded_callback(struct dl_phdr_info *info, size_t, void *data) {
    auto *context = static_cast<ResolveContext *>(data);
    if (!info || !info->dlpi_name
        || !exact_library_basename(info->dlpi_name, context->library)) {
        return 0;
    }
    context->matches++;
    if (info->dlpi_phnum == 0 || info->dlpi_phnum > kMaxProgramHeaders) {
        return 0;
    }
    LoadedModule module{static_cast<uintptr_t>(info->dlpi_addr),
                        info->dlpi_phdr, info->dlpi_phnum};
    void *candidate = resolve_from_loaded_module(module, context->symbol);
    if (candidate) {
        if (context->result != nullptr) {
            context->result = nullptr;
        } else {
            context->result = candidate;
        }
    }
    return 0;
}

}  // namespace

void *safe_resolve_symbol(const char *libname, const char *symname) {
    if (!libname || !*libname || !symname || !*symname) {
        return nullptr;
    }
    ResolveContext context{libname, symname, nullptr, 0};
    dl_iterate_phdr(resolve_loaded_callback, &context);
    void *result = context.matches == 1 ? context.result : nullptr;
    if (result) {
        return result;
    }

    /* Fallback: dl_iterate_phdr enumerates only the caller's linker namespace.
     * When the implant runs in an isolated namespace (android_dlopen_ext) it
     * does not see libraries from the default/art namespace such as libart.so.
     * Parse /proc/self/maps to find the library load base across ALL
     * namespaces, then read its ELF program headers from memory. */
    int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (maps < 0) {
        return nullptr;
    }
    char buf[524288];
    size_t total = 0;
    while (total + 1 < sizeof(buf)) {
        ssize_t r = read(maps, buf + total, sizeof(buf) - 1 - total);
        if (r <= 0) {
            break;
        }
        total += static_cast<size_t>(r);
    }
    close(maps);
    buf[total] = '\0';
    uintptr_t base_addr = 0;
    size_t pos = 0;
    while (pos < total && base_addr == 0) {
        size_t line_end = pos;
        while (line_end < total && buf[line_end] != '\n') {
            line_end++;
        }
        buf[line_end] = '\0';
        char *line = buf + pos;
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        unsigned long offset = 0;
        unsigned int dmaj = 0, dmin = 0;
        unsigned long inode = 0;
        int path_offset = 0;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %lx %x:%x %lu %n",
                   &start, &end, perms, &offset, &dmaj, &dmin, &inode, &path_offset) >= 7
            && path_offset > 0) {
            const char *path = line + path_offset;
            while (*path == ' ') {
                path++;
            }
            if (offset == 0 && *path == '/' && exact_library_basename(path, libname)) {
                base_addr = start;
            }
        }
        pos = line_end + 1;
    }
    if (base_addr == 0) {
        return nullptr;
    }
    const ElfW(Ehdr) *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base_addr);
    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
        || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F'
        || ehdr->e_phnum == 0 || ehdr->e_phnum > kMaxProgramHeaders) {
        return nullptr;
    }
    const ElfW(Phdr) *phdrs = reinterpret_cast<const ElfW(Phdr) *>(
        base_addr + ehdr->e_phoff);
    /* base_addr is the mapping start (file offset 0), not the load bias:
     * subtract the first PT_LOAD's p_vaddr so address math matches the
     * dlpi_addr semantics of the main path. */
    ElfW(Addr) min_vaddr = 0;
    bool min_vaddr_found = false;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (!min_vaddr_found || phdrs[i].p_vaddr < min_vaddr) {
            min_vaddr = phdrs[i].p_vaddr;
            min_vaddr_found = true;
        }
    }
    if (!min_vaddr_found || min_vaddr > base_addr) {
        return nullptr;
    }
    LoadedModule module{static_cast<uintptr_t>(base_addr - min_vaddr), phdrs,
                        ehdr->e_phnum};
    return resolve_from_loaded_module(module, symname);
}

/* File-based .symtab resolver: open the library file on disk, parse its ELF
 * section headers, locate .symtab + .strtab (full symbol table, not just
 * dynamic), and resolve a symbol by exact name or prefix. Returns the runtime
 * address (load base + st_value). */
/* TEMP DEV DIAGNOSTIC: weak trace hook. The implant (implant.cpp) defines a
 * strong version writing into the agent log pipe during phase-two, so the
 * diagnostics ride the same pipe as agent logs. Remove before any production
 * build. */
__attribute__((weak)) void vbi_symtab_trace(const char *stage, const char *file,
                                            long line) {
    (void)stage; (void)file; (void)line;
}

void *safe_resolve_symbol_symtab(const char *libname, const char *symname,
                                 bool prefix_match) {
    if (!libname || !*libname || !symname || !*symname) {
        return nullptr;
    }
    vbi_symtab_trace("enter", symname, prefix_match);
    /* Find the on-disk path and load base of the library from /proc/self/maps. */
    int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (maps < 0) {
        vbi_symtab_trace("maps-open-fail", symname, __LINE__); return nullptr;
    }
    char buf[524288];
    size_t total = 0;
    uintptr_t base_addr = 0;
    char path_buf[1024] = {0};
    while (total + 1 < sizeof(buf)) {
        ssize_t r = read(maps, buf + total, sizeof(buf) - 1 - total);
        if (r <= 0) {
            break;
        }
        total += static_cast<size_t>(r);
    }
    close(maps);
    buf[total] = '\0';
    size_t pos = 0;
    while (pos < total && base_addr == 0) {
        size_t line_end = pos;
        while (line_end < total && buf[line_end] != '\n') {
            line_end++;
        }
        buf[line_end] = '\0';
        char *line = buf + pos;
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        unsigned long offset = 0;
        unsigned int dmaj = 0, dmin = 0;
        unsigned long inode = 0;
        int path_offset = 0;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %lx %x:%x %lu %n",
                   &start, &end, perms, &offset, &dmaj, &dmin, &inode, &path_offset) >= 7
            && path_offset > 0) {
            const char *path = line + path_offset;
            while (*path == ' ') {
                path++;
            }
            if (offset == 0 && *path == '/' && exact_library_basename(path, libname)) {
                base_addr = start;
                strncpy(path_buf, path, sizeof(path_buf) - 1);
            }
        }
        pos = line_end + 1;
    }
    if (base_addr == 0 || path_buf[0] == '\0') {
        vbi_symtab_trace("base-not-found", symname, (long)total);
        return nullptr;
    }
    /* The maps entry with file offset 0 is the mapping START, not the ELF
     * load bias. For libraries whose first PT_LOAD has a non-zero p_vaddr
     * (OEM libart.so: vaddr 0x25000), the linker maps the file at
     * start == bias + p_vaddr, so bias = start - p_vaddr. Compute the bias
     * from the in-memory program headers so st_value math lands on the
     * actually-mapped addresses. */
    const ElfW(Ehdr) *live_ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base_addr);
    if (live_ehdr->e_ident[0] != 0x7f || live_ehdr->e_ident[1] != 'E'
        || live_ehdr->e_ident[2] != 'L' || live_ehdr->e_ident[3] != 'F'
        || live_ehdr->e_phnum == 0 || live_ehdr->e_phnum > kMaxProgramHeaders) {
        vbi_symtab_trace("live-ehdr-invalid", path_buf, __LINE__);
        return nullptr;
    }
    const ElfW(Phdr) *live_phdrs = reinterpret_cast<const ElfW(Phdr) *>(
        base_addr + live_ehdr->e_phoff);
    ElfW(Addr) min_vaddr = 0;
    bool min_vaddr_found = false;
    for (size_t i = 0; i < live_ehdr->e_phnum; i++) {
        if (live_phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (!min_vaddr_found || live_phdrs[i].p_vaddr < min_vaddr) {
            min_vaddr = live_phdrs[i].p_vaddr;
            min_vaddr_found = true;
        }
    }
    if (!min_vaddr_found || min_vaddr > base_addr) {
        vbi_symtab_trace("bias-unavailable", path_buf, __LINE__);
        return nullptr;
    }
    uintptr_t load_bias = base_addr - static_cast<uintptr_t>(min_vaddr);
    int fd = open(path_buf, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        vbi_symtab_trace("open-fail", path_buf, errno); return nullptr;
    }
    ElfW(Ehdr) ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr)
        || ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E'
        || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F'
        || ehdr.e_shnum == 0 || ehdr.e_shoff == 0
        || ehdr.e_shentsize != sizeof(ElfW(Shdr))) {
        close(fd);
        return nullptr;
    }
    size_t shdr_size = static_cast<size_t>(ehdr.e_shentsize) * ehdr.e_shnum;
    if (shdr_size > size_t{1024} *1024U) {
        close(fd);
        return nullptr;
    }
    ElfW(Shdr) *shdrs = (ElfW(Shdr) *)malloc(shdr_size);
    if (!shdrs) {
        close(fd);
        return nullptr;
    }
    if (pread(fd, shdrs, shdr_size, ehdr.e_shoff) != (ssize_t)shdr_size) {
        free(shdrs);
        close(fd);
        return nullptr;
    }
    ElfW(Shdr) *symtab_sh = nullptr;
    ElfW(Shdr) *strtab_sh = nullptr;
    for (size_t i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_sh = &shdrs[i];
            if (symtab_sh->sh_link < ehdr.e_shnum) {
                strtab_sh = &shdrs[symtab_sh->sh_link];
            }
            break;
        }
    }
    if (!symtab_sh || !strtab_sh || symtab_sh->sh_size == 0
        || symtab_sh->sh_entsize != sizeof(ElfW(Sym))
        || symtab_sh->sh_size % sizeof(ElfW(Sym)) != 0
        || strtab_sh->sh_size == 0 || strtab_sh->sh_size > 4ULL * 1024ULL * 1024ULL) {
        vbi_symtab_trace("no-symtab", symname, __LINE__);
        free(shdrs);
        close(fd);
        return nullptr;
    }
    size_t sym_count = symtab_sh->sh_size / sizeof(ElfW(Sym));
    if (sym_count > 200000) {
        free(shdrs);
        close(fd);
        return nullptr;
    }
    ElfW(Sym) *symbols = (ElfW(Sym) *)malloc(symtab_sh->sh_size);
    if (!symbols) {
        free(shdrs);
        close(fd);
        return nullptr;
    }
    if (pread(fd, symbols, symtab_sh->sh_size, symtab_sh->sh_offset)
        != (ssize_t)symtab_sh->sh_size) {
        free(symbols);
        free(shdrs);
        close(fd);
        return nullptr;
    }
    char *strings = (char *)malloc(strtab_sh->sh_size);
    if (!strings) {
        free(symbols);
        free(shdrs);
        close(fd);
        return nullptr;
    }
    if (pread(fd, strings, strtab_sh->sh_size, strtab_sh->sh_offset)
        != (ssize_t)strtab_sh->sh_size) {
        free(strings);
        free(symbols);
        free(shdrs);
        close(fd);
        return nullptr;
    }
    const size_t string_size = static_cast<size_t>(strtab_sh->sh_size);
    free(shdrs);
    close(fd);
    size_t name_len = strlen(symname);
    void *result = nullptr;
    for (size_t i = 0; i < sym_count; i++) {
        if (symbols[i].st_name >= string_size) {
            continue;
        }
        const char *name = strings + symbols[i].st_name;
        const char *terminator = static_cast<const char *>(
            memchr(name, '\0', string_size - symbols[i].st_name));
        if (!terminator) {
            continue;
        }
        const size_t actual_length = static_cast<size_t>(terminator - name);
        bool match = prefix_match
            ? (actual_length >= name_len && memcmp(name, symname, name_len) == 0)
            : (actual_length == name_len && memcmp(name, symname, name_len) == 0);
        if (match && symbols[i].st_value != 0) {
            result = reinterpret_cast<void *>(load_bias + symbols[i].st_value);
            break;
        }
    }
    free(strings);
    free(symbols);
    /* TEMP DEV DIAGNOSTIC: surface the resolved address or the miss. */
    vbi_symtab_trace(result ? "resolved" : "not-found", symname,
                     (long)base_addr);
    return result;
}
