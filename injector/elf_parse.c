/*
 * elf_parse.c — pure ELF symbol parser (host-testable, no ptrace).
 *
 * Walks an in-memory ELF image's PT_DYNAMIC to find a symbol by name, returning
 * load_bias + st_value. Split from elf_resolve.c so the parser can be unit-
 * tested on the host against a real linker image with no device and no ptrace
 * (native-payload: runtime ELF symbol resolution).
 *
 * nsym is derived from DT_SYMTAB/DT_STRTAB adjacency
 * ((strtab - symtab) / syment) because the Android 9 linker carries only
 * DT_GNU_HASH (no DT_HASH). SHN_UNDEF entries are skipped. Fails closed
 * (returns 0) on any malformed input — never returns a bogus address.
 */

#include <string.h>
#include <stdint.h>

#include "elf_parse.h"

/*
 * Resolve a symbol in a 64-bit in-memory ELF image by walking PT_DYNAMIC.
 * image is the linker file contents (Ehdr + Phdrs + PT_DYNAMIC + SYMTAB +
 * STRTAB); load_bias is the address to add to st_value.
 */
u64 resolve_elf64_symbol(const u8 *image, size_t image_sz, u64 load_bias,
                         const char *name) {
    if (!image || !name || image_sz < sizeof(Elf64_Ehdr)) {
        return 0;
    }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        return 0;
    }
    uint64_t phoff = eh->e_phoff;
    uint16_t phnum = eh->e_phnum;
    uint16_t phent = eh->e_phentsize;
    if (phoff + (uint64_t)phnum * phent > image_sz || phent != sizeof(Elf64_Phdr)) {
        return 0;
    }

    /* Find PT_DYNAMIC. */
    uint64_t dyn_off = 0;
    uint64_t dyn_sz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(image + phoff + (uint64_t)i * phent);
        if (ph->p_type == PT_DYNAMIC) {
            dyn_off = ph->p_offset;
            dyn_sz = ph->p_filesz;
            break;
        }
    }
    if (!dyn_off || dyn_off + dyn_sz > image_sz) {
        return 0;
    }

    /* Walk DT_ entries: collect SYMTAB, STRTAB, SYMENT, STRSZ. */
    uint64_t symtab = 0, strtab = 0, syment = 0, strsz = 0;
    for (uint64_t off = dyn_off; off + sizeof(Elf64_Dyn) <= image_sz; off += sizeof(Elf64_Dyn)) {
        const Elf64_Dyn *d = (const Elf64_Dyn *)(image + off);
        if (d->d_tag == DT_NULL) {
            break;
        }
        if (d->d_tag == DT_SYMTAB) {
            symtab = d->d_un.d_ptr;
        }else if (d->d_tag == DT_STRTAB) {
            strtab = d->d_un.d_ptr;
        }else if (d->d_tag == DT_SYMENT) {
            syment = d->d_un.d_ptr;
        }else if (d->d_tag == DT_STRSZ) {
            strsz  = d->d_un.d_ptr;
        }
    }
    if (!symtab || !strtab || !syment || strtab <= symtab) {
        return 0;
    }
    uint64_t nsym = (strtab - symtab) / syment;
    if (symtab + nsym * syment > image_sz) {
        /* Adjacency broken or image truncated: bound the scan conservatively. */
        nsym = (image_sz - symtab) / syment;
    }
    uint64_t strtab_end = strsz ? (strtab + strsz) : image_sz;
    if (strtab_end > image_sz) {
        strtab_end = image_sz;
    }

    /* Linear .dynsym scan. */
    for (uint64_t i = 0; i < nsym; i++) {
        const Elf64_Sym *s = (const Elf64_Sym *)(image + symtab + i * syment);
        if (s->st_shndx == SHN_UNDEF) {
            continue;
        }
        uint32_t name_off = s->st_name;
        if (strtab + name_off >= strtab_end) {
            continue;
        }
        const char *sym = (const char *)(image + strtab + name_off);
        if (strncmp(sym, name, strtab_end - (strtab + name_off)) == 0) {
            return load_bias + s->st_value;
        }
    }
    return 0;
}

/*
 * 32-bit counterpart. Elf32_Dyn.d_un.d_ptr is Elf32_Addr (uint32_t); we widen
 * to u64 for uniform return type. load_bias is still a 64-bit value (the
 * injector is a 64-bit binary reading a 32-bit target's low memory).
 */
u64 resolve_elf32_symbol(const u8 *image, size_t image_sz, u64 load_bias,
                         const char *name) {
    if (!image || !name || image_sz < sizeof(Elf32_Ehdr)) {
        return 0;
    }
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)image;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        return 0;
    }
    uint32_t phoff = eh->e_phoff;
    uint16_t phnum = eh->e_phnum;
    uint16_t phent = eh->e_phentsize;
    if ((uint64_t)phoff + (uint64_t)phnum * phent > image_sz || phent != sizeof(Elf32_Phdr)) {
        return 0;
    }

    uint32_t dyn_off = 0;
    uint32_t dyn_sz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(image + phoff + (uint64_t)i * phent);
        if (ph->p_type == PT_DYNAMIC) {
            dyn_off = ph->p_offset;
            dyn_sz = ph->p_filesz;
            break;
        }
    }
    if (!dyn_off || (uint64_t)dyn_off + dyn_sz > image_sz) {
        return 0;
    }

    uint32_t symtab = 0, strtab = 0, syment = 0, strsz = 0;
    for (uint32_t off = dyn_off; (uint64_t)off + sizeof(Elf32_Dyn) <= image_sz; off += sizeof(Elf32_Dyn)) {
        const Elf32_Dyn *d = (const Elf32_Dyn *)(image + off);
        if (d->d_tag == DT_NULL) {
            break;
        }
        if (d->d_tag == DT_SYMTAB) {
            symtab = d->d_un.d_ptr;
        }else if (d->d_tag == DT_STRTAB) {
            strtab = d->d_un.d_ptr;
        }else if (d->d_tag == DT_SYMENT) {
            syment = d->d_un.d_ptr;
        }else if (d->d_tag == DT_STRSZ) {
            strsz  = d->d_un.d_ptr;
        }
    }
    if (!symtab || !strtab || !syment || strtab <= symtab) {
        return 0;
    }
    uint32_t nsym = (strtab - symtab) / syment;
    if ((uint64_t)symtab + (uint64_t)nsym * syment > image_sz) {
        nsym = (image_sz - symtab) / syment;
    }
    uint32_t strtab_end = strsz ? (strtab + strsz) : (uint32_t)image_sz;
    if (strtab_end > image_sz) {
        strtab_end = (uint32_t)image_sz;
    }

    for (uint32_t i = 0; i < nsym; i++) {
        const Elf32_Sym *s = (const Elf32_Sym *)(image + symtab + i * syment);
        if (s->st_shndx == SHN_UNDEF) {
            continue;
        }
        uint32_t name_off = s->st_name;
        if (strtab + name_off >= strtab_end) {
            continue;
        }
        const char *sym = (const char *)(image + strtab + name_off);
        if (strncmp(sym, name, strtab_end - (strtab + name_off)) == 0) {
            return load_bias + s->st_value;
        }
    }
    return 0;
}
