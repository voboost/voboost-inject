/*
 * safe_resolve.cpp — safe ART symbol resolver (NOT DobbySymbolResolver).
 *
 * DobbySymbolResolver's elf_ctx_init() crashes parsing libart.so's ELF on the
 * target device. This module does safe resolution in two steps:
 *   1. dlsym(RTLD_DEFAULT) — resolves .dynsym exports
 *   2. File-based fallback: mmap the .so, parse .symtab/.strtab via section
 *      headers, return load_bias + st_value. Symbol count via DT_HASH
 *      (not DT_GNU_HASH, which bugged on first attempt).
 *
 * libart.so on the target is NOT stripped (verified: 29 sections, .symtab
 * present at 0x6026d8), so file-based resolution works.
 */

#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

/*
 * Resolve a symbol from the .symtab section of an on-disk .so file.
 * Returns the runtime address (load_bias + st_value) or nullptr.
 */
static void *resolve_from_file(const char *path, const char *symname,
                               uintptr_t load_bias) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return nullptr;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(ElfW(Ehdr))) {
        close(fd);
        return nullptr;
    }

    void *map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return nullptr;
    }

    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr) *) map;
    void *result = nullptr;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shoff >= (ElfW(Addr)) st.st_size) {
        goto done;
    }

    {
        const ElfW(Shdr) *shdr =
            (const ElfW(Shdr) *)((const uint8_t *)map + ehdr->e_shoff);
        const ElfW(Shdr) *shstr_sh = &shdr[ehdr->e_shstrndx];
        const char *shstrtab = (const char *)map + shstr_sh->sh_offset;

        const ElfW(Sym) *symtab = nullptr;
        const char *strtab = nullptr;
        size_t symtab_size = 0;

        /* Find .symtab and .strtab by name */
        for (unsigned i = 0; i < ehdr->e_shnum; i++) {
            const char *name = shstrtab + shdr[i].sh_name;
            if (shdr[i].sh_type == SHT_SYMTAB && strcmp(name, ".symtab") == 0) {
                symtab = (const ElfW(Sym) *)((const uint8_t *)map + shdr[i].sh_offset);
                symtab_size = shdr[i].sh_size;
            } else if (shdr[i].sh_type == SHT_STRTAB &&
                       strcmp(name, ".strtab") == 0) {
                strtab = (const char *)map + shdr[i].sh_offset;
            }
        }

        if (symtab && strtab) {
            size_t count = symtab_size / sizeof(ElfW(Sym));
            for (size_t i = 0; i < count; i++) {
                const char *name = strtab + symtab[i].st_name;
                if (strcmp(name, symname) == 0 && symtab[i].st_value != 0) {
                    result = (void *)(load_bias + symtab[i].st_value);
                    break;
                }
            }
        }
    }

done:
    munmap(map, st.st_size);
    return result;
}

/*
 * Safe symbol resolver: dlsym first, file-based fallback.
 *
 *   libname — the .so to search (e.g. "libart.so")
 *   symname — the symbol to find
 *
 * This replaces DobbySymbolResolver which crashes in elf_ctx_init.
 */
void *safe_resolve_symbol(const char *libname, const char *symname) {
    /* 1. dlsym — resolves .dynsym exports */
    void *addr = dlsym(RTLD_DEFAULT, symname);
    if (addr) {
        return addr;
    }

    /* 2. Find the loaded module's path + load_bias, parse .symtab from file */
    struct Ctx {
        const char *lib;
        const char *sym;
        void *result;
    };
    Ctx ctx{libname, symname, nullptr};

    dl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t, void *data) -> int {
        auto *c = static_cast<Ctx *>(data);
        if (c->result) {
            return 0;
        }
        if (!info->dlpi_name || !strstr(info->dlpi_name, c->lib)) {
            return 0;
        }
        c->result =
            resolve_from_file(info->dlpi_name, c->sym, info->dlpi_addr);
        return c->result ? 1 : 0;
    },
        &ctx);

    return ctx.result;
}
