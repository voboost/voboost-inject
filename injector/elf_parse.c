/*
 * elf_parse.c — pure ELF symbol parser (host-testable, no ptrace).
 *
 * Walks an in-memory ELF image's PT_DYNAMIC to find a symbol by name, returning
 * load_bias + st_value. Split from elf_resolve.c so the parser can be unit-
 * tested on the host against a real linker image with no device and no ptrace
 * (injector-linker-reconstruction: runtime ELF symbol resolution).
 *
 * nsym is derived from DT_SYMTAB/DT_STRTAB adjacency
 * ((strtab - symtab) / syment) because the Android 9 linker carries only
 * DT_GNU_HASH (no DT_HASH). SHN_UNDEF entries are skipped. Fails closed
 * (returns 0) on any malformed input — never returns a bogus address.
 */

#include <stdint.h>
#include <string.h>

#include "elf_parse.h"

static int range_within_image(size_t image_sz, uint64_t offset,
                              uint64_t length) {
    uint64_t total = (uint64_t)image_sz;
    return offset <= total && length <= total - offset;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (!result || (right != 0 && left > UINT64_MAX / right)) {
        return 0;
    }
    *result = left * right;
    return 1;
}

static int add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (!result || left > UINT64_MAX - right) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int read_image(const u8 *image, size_t image_sz, uint64_t offset,
                      void *output, size_t output_sz) {
    if (!image || !output
        || !range_within_image(image_sz, offset, (uint64_t)output_sz)) {
        return 0;
    }
    memcpy(output, image + (size_t)offset, output_sz);
    return 1;
}

static int symbol_name_equals(const u8 *image, size_t image_sz,
                              uint64_t strtab, uint64_t strsz,
                              uint32_t name_offset, const char *name,
                              size_t name_sz) {
    if ((uint64_t)name_offset >= strsz) {
        return 0;
    }
    uint64_t symbol_offset = 0;
    if (!add_u64(strtab, name_offset, &symbol_offset)) {
        return 0;
    }
    uint64_t remaining = strsz - name_offset;
    if (!range_within_image(image_sz, symbol_offset, remaining)) {
        return 0;
    }
    const char *symbol = (const char *)(image + (size_t)symbol_offset);
    const char *terminator = (const char *)memchr(symbol, '\0', (size_t)remaining);
    if (!terminator) {
        return 0;
    }
    size_t symbol_sz = (size_t)(terminator - symbol);
    return symbol_sz == name_sz && memcmp(symbol, name, name_sz) == 0;
}

static int elf64_vaddr_to_offset(const u8 *image, size_t image_sz,
                                 uint64_t phoff, uint16_t phnum,
                                 uint64_t vaddr, uint64_t length,
                                 uint64_t *offset, int *executable) {
    if (!offset || !executable) {
        return 0;
    }
    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t index = 0;
        uint64_t ph_offset = 0;
        Elf64_Phdr ph;
        if (!multiply_u64(i, sizeof(ph), &index)
            || !add_u64(phoff, index, &ph_offset)
            || !read_image(image, image_sz, ph_offset, &ph, sizeof(ph))
            || ph.p_type != PT_LOAD) {
            continue;
        }
        if (vaddr < ph.p_vaddr || vaddr - ph.p_vaddr > ph.p_filesz
            || length > ph.p_filesz - (vaddr - ph.p_vaddr)) {
            continue;
        }
        uint64_t result = 0;
        if (!add_u64(ph.p_offset, vaddr - ph.p_vaddr, &result)
            || !range_within_image(image_sz, result, length)) {
            return 0;
        }
        *offset = result;
        *executable = (ph.p_flags & PF_X) != 0;
        return 1;
    }
    return 0;
}

static int elf32_vaddr_to_offset(const u8 *image, size_t image_sz,
                                 uint32_t phoff, uint16_t phnum,
                                 uint32_t vaddr, uint64_t length,
                                 uint64_t *offset, int *executable) {
    if (!offset || !executable) {
        return 0;
    }
    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t index = 0;
        uint64_t ph_offset = 0;
        Elf32_Phdr ph;
        if (!multiply_u64(i, sizeof(ph), &index)
            || !add_u64(phoff, index, &ph_offset)
            || !read_image(image, image_sz, ph_offset, &ph, sizeof(ph))
            || ph.p_type != PT_LOAD) {
            continue;
        }
        if (vaddr < ph.p_vaddr || vaddr - ph.p_vaddr > ph.p_filesz
            || length > ph.p_filesz - (vaddr - ph.p_vaddr)) {
            continue;
        }
        uint64_t result = 0;
        if (!add_u64(ph.p_offset, (uint64_t)(vaddr - ph.p_vaddr), &result)
            || !range_within_image(image_sz, result, length)) {
            return 0;
        }
        *offset = result;
        *executable = (ph.p_flags & PF_X) != 0;
        return 1;
    }
    return 0;
}

/*
 * Resolve a symbol in a 64-bit in-memory ELF image by walking PT_DYNAMIC.
 * image is the linker file contents (Ehdr + Phdrs + PT_DYNAMIC + SYMTAB +
 * STRTAB); load_bias is the address to add to st_value.
 */
u64 resolve_elf64_symbol(const u8 *image, size_t image_sz, u64 load_bias,
                         const char *name) {
    if (!image || !name || name[0] == '\0' || image_sz < sizeof(Elf64_Ehdr)) {
        return 0;
    }
    size_t name_sz = strlen(name);
    Elf64_Ehdr eh;
    if (!read_image(image, image_sz, 0, &eh, sizeof(eh))
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0) {
        return 0;
    }

    uint64_t phdr_bytes = 0;
    if (!multiply_u64(eh.e_phnum, sizeof(Elf64_Phdr), &phdr_bytes)
        || !range_within_image(image_sz, eh.e_phoff, phdr_bytes)) {
        return 0;
    }

    uint64_t dyn_off = 0;
    uint64_t dyn_sz = 0;
    int dyn_found = 0;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        uint64_t index_bytes = 0;
        uint64_t phdr_offset = 0;
        Elf64_Phdr ph;
        if (!multiply_u64(i, sizeof(Elf64_Phdr), &index_bytes)
            || !add_u64(eh.e_phoff, index_bytes, &phdr_offset)
            || !read_image(image, image_sz, phdr_offset, &ph, sizeof(ph))) {
            return 0;
        }
        if (ph.p_type == PT_DYNAMIC) {
            if (dyn_found) {
                return 0;
            }
            dyn_found = 1;
            dyn_off = ph.p_offset;
            dyn_sz = ph.p_filesz;
        }
    }
    if (!dyn_found || dyn_sz < sizeof(Elf64_Dyn)
        || dyn_sz % sizeof(Elf64_Dyn) != 0
        || !range_within_image(image_sz, dyn_off, dyn_sz)) {
        return 0;
    }

    uint64_t symtab_vaddr = 0;
    uint64_t strtab_vaddr = 0;
    uint64_t syment = 0;
    uint64_t strsz = 0;
    int terminated = 0;
    for (uint64_t relative = 0; relative < dyn_sz;
         relative += sizeof(Elf64_Dyn)) {
        uint64_t entry_offset = 0;
        Elf64_Dyn entry;
        if (!add_u64(dyn_off, relative, &entry_offset)
            || !read_image(image, image_sz, entry_offset, &entry,
                           sizeof(entry))) {
            return 0;
        }
        if (entry.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
        if (entry.d_tag == DT_SYMTAB) {
            symtab_vaddr = entry.d_un.d_ptr;
        } else if (entry.d_tag == DT_STRTAB) {
            strtab_vaddr = entry.d_un.d_ptr;
        } else if (entry.d_tag == DT_SYMENT) {
            syment = entry.d_un.d_val;
        } else if (entry.d_tag == DT_STRSZ) {
            strsz = entry.d_un.d_val;
        }
    }
    if (!terminated || !symtab_vaddr || !strtab_vaddr || !strsz
        || syment != sizeof(Elf64_Sym) || strtab_vaddr <= symtab_vaddr) {
        return 0;
    }

    uint64_t symtab_sz = strtab_vaddr - symtab_vaddr;
    uint64_t symtab = 0;
    uint64_t strtab = 0;
    int unused_executable = 0;
    if (symtab_sz % sizeof(Elf64_Sym) != 0
        || !elf64_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                  symtab_vaddr, symtab_sz, &symtab,
                                  &unused_executable)
        || !elf64_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                  strtab_vaddr, strsz, &strtab,
                                  &unused_executable)) {
        return 0;
    }
    uint64_t symbol_count = symtab_sz / sizeof(Elf64_Sym);
    for (uint64_t i = 0; i < symbol_count; i++) {
        uint64_t index_bytes = 0;
        uint64_t symbol_offset = 0;
        Elf64_Sym symbol;
        if (!multiply_u64(i, sizeof(Elf64_Sym), &index_bytes)
            || !add_u64(symtab, index_bytes, &symbol_offset)
            || !read_image(image, image_sz, symbol_offset, &symbol,
                           sizeof(symbol))) {
            return 0;
        }
        if (symbol.st_shndx == SHN_UNDEF
            || !symbol_name_equals(image, image_sz, strtab, strsz,
                                   symbol.st_name, name, name_sz)) {
            continue;
        }
        uint64_t symbol_file_offset = 0;
        int executable = 0;
        uint64_t address = 0;
        if (!elf64_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                   symbol.st_value, 1, &symbol_file_offset,
                                   &executable)
            || !executable || !add_u64(load_bias, symbol.st_value, &address)) {
            return 0;
        }
        return address;
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
    if (!image || !name || name[0] == '\0' || image_sz < sizeof(Elf32_Ehdr)) {
        return 0;
    }
    size_t name_sz = strlen(name);
    Elf32_Ehdr eh;
    if (!read_image(image, image_sz, 0, &eh, sizeof(eh))
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_phentsize != sizeof(Elf32_Phdr) || eh.e_phnum == 0) {
        return 0;
    }

    uint64_t phdr_bytes = 0;
    if (!multiply_u64(eh.e_phnum, sizeof(Elf32_Phdr), &phdr_bytes)
        || !range_within_image(image_sz, eh.e_phoff, phdr_bytes)) {
        return 0;
    }

    uint64_t dyn_off = 0;
    uint64_t dyn_sz = 0;
    int dyn_found = 0;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        uint64_t index_bytes = 0;
        uint64_t phdr_offset = 0;
        Elf32_Phdr ph;
        if (!multiply_u64(i, sizeof(Elf32_Phdr), &index_bytes)
            || !add_u64(eh.e_phoff, index_bytes, &phdr_offset)
            || !read_image(image, image_sz, phdr_offset, &ph, sizeof(ph))) {
            return 0;
        }
        if (ph.p_type == PT_DYNAMIC) {
            if (dyn_found) {
                return 0;
            }
            dyn_found = 1;
            dyn_off = ph.p_offset;
            dyn_sz = ph.p_filesz;
        }
    }
    if (!dyn_found || dyn_sz < sizeof(Elf32_Dyn)
        || dyn_sz % sizeof(Elf32_Dyn) != 0
        || !range_within_image(image_sz, dyn_off, dyn_sz)) {
        return 0;
    }

    uint64_t symtab_vaddr = 0;
    uint64_t strtab_vaddr = 0;
    uint64_t syment = 0;
    uint64_t strsz = 0;
    int terminated = 0;
    for (uint64_t relative = 0; relative < dyn_sz;
         relative += sizeof(Elf32_Dyn)) {
        uint64_t entry_offset = 0;
        Elf32_Dyn entry;
        if (!add_u64(dyn_off, relative, &entry_offset)
            || !read_image(image, image_sz, entry_offset, &entry,
                           sizeof(entry))) {
            return 0;
        }
        if (entry.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
        if (entry.d_tag == DT_SYMTAB) {
            symtab_vaddr = entry.d_un.d_ptr;
        } else if (entry.d_tag == DT_STRTAB) {
            strtab_vaddr = entry.d_un.d_ptr;
        } else if (entry.d_tag == DT_SYMENT) {
            syment = entry.d_un.d_val;
        } else if (entry.d_tag == DT_STRSZ) {
            strsz = entry.d_un.d_val;
        }
    }
    if (!terminated || !symtab_vaddr || !strtab_vaddr || !strsz
        || syment != sizeof(Elf32_Sym) || strtab_vaddr <= symtab_vaddr) {
        return 0;
    }

    uint64_t symtab_sz = strtab_vaddr - symtab_vaddr;
    uint64_t symtab = 0;
    uint64_t strtab = 0;
    int unused_executable = 0;
    if (symtab_sz % sizeof(Elf32_Sym) != 0
        || !elf32_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                  (uint32_t)symtab_vaddr, symtab_sz, &symtab,
                                  &unused_executable)
        || !elf32_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                  (uint32_t)strtab_vaddr, strsz, &strtab,
                                  &unused_executable)) {
        return 0;
    }
    uint64_t symbol_count = symtab_sz / sizeof(Elf32_Sym);
    for (uint64_t i = 0; i < symbol_count; i++) {
        uint64_t index_bytes = 0;
        uint64_t symbol_offset = 0;
        Elf32_Sym symbol;
        if (!multiply_u64(i, sizeof(Elf32_Sym), &index_bytes)
            || !add_u64(symtab, index_bytes, &symbol_offset)
            || !read_image(image, image_sz, symbol_offset, &symbol,
                           sizeof(symbol))) {
            return 0;
        }
        if (symbol.st_shndx == SHN_UNDEF
            || !symbol_name_equals(image, image_sz, strtab, strsz,
                                   symbol.st_name, name, name_sz)) {
            continue;
        }
        uint64_t symbol_file_offset = 0;
        int executable = 0;
        uint64_t address = 0;
        if (!elf32_vaddr_to_offset(image, image_sz, eh.e_phoff, eh.e_phnum,
                                   symbol.st_value, 1, &symbol_file_offset,
                                   &executable)
            || !executable || !add_u64(load_bias, symbol.st_value, &address)) {
            return 0;
        }
        return address;
    }
    return 0;
}

static int mapping_load_bias(uint64_t p_offset, uint64_t p_vaddr,
                             uint64_t p_filesz, uint64_t p_flags,
                             const struct vbi_load_mapping *mappings,
                             size_t mapping_count, uint64_t *bias,
                             int *found_exec) {
    const uint64_t page = UINT64_C(4096);
    uint64_t offset_page = p_offset & ~(page - 1);
    uint64_t vaddr_page = p_vaddr & ~(page - 1);
    uint64_t page_delta = p_offset - offset_page;
    if (!mappings || !mapping_count || !bias || !found_exec
        || p_filesz < page_delta || vaddr_page > p_vaddr) {
        return 0;
    }
    /* The live mapping need only cover the first mapped page of the segment:
       the kernel can split one PT_LOAD across several VMAs (e.g. r-xp + r--
     + rw-p for firmware linker64), so no single VMA spans the whole
       segment. Bias depends only on mapping->start vs p_vaddr, both
       page-aligned here. */
    uint64_t span = p_filesz + page_delta;
    uint64_t required = span < page ? span : page;
    int matched = 0;
    for (size_t i = 0; i < mapping_count; i++) {
        const struct vbi_load_mapping *mapping = &mappings[i];
        if (mapping->file_offset != offset_page
            || mapping->end < mapping->start
            || mapping->end - mapping->start < required
            || ((p_flags & PF_X) != 0 && !mapping->executable)
            || mapping->start < vaddr_page) {
            continue;
        }
        uint64_t candidate = mapping->start - vaddr_page;
        if (matched && candidate != *bias) {
            return 0;
        }
        *bias = candidate;
        matched = 1;
        if ((p_flags & PF_X) != 0) {
            *found_exec = 1;
        }
    }
    return matched;
}

int vbi_compute_load_bias64(const u8 *image, size_t image_sz,
                            const struct vbi_load_mapping *mappings,
                            size_t mapping_count, u64 *load_bias) {
    if (!image || !load_bias || image_sz < sizeof(Elf64_Ehdr)) {
        return 0;
    }
    Elf64_Ehdr eh;
    if (!read_image(image, image_sz, 0, &eh, sizeof(eh))
        || eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0) {
        return 0;
    }
    uint64_t phdr_bytes = 0;
    if (!multiply_u64(eh.e_phnum, sizeof(Elf64_Phdr), &phdr_bytes)
        || !range_within_image(image_sz, eh.e_phoff, phdr_bytes)) {
        return 0;
    }
    uint64_t bias = 0;
    int found_load = 0;
    int found_exec = 0;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        uint64_t index = 0;
        uint64_t offset = 0;
        Elf64_Phdr ph;
        if (!multiply_u64(i, sizeof(ph), &index)
            || !add_u64(eh.e_phoff, index, &offset)
            || !read_image(image, image_sz, offset, &ph, sizeof(ph))) {
            return 0;
        }
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) {
            continue;
        }
        uint64_t segment_bias = bias;
        if (!mapping_load_bias(ph.p_offset, ph.p_vaddr, ph.p_filesz,
                               ph.p_flags, mappings, mapping_count,
                               &segment_bias, &found_exec)) {
            return 0;
        }
        if (found_load && segment_bias != bias) {
            return 0;
        }
        bias = segment_bias;
        found_load = 1;
    }
    if (!found_load || !found_exec) {
        return 0;
    }
    *load_bias = bias;
    return 1;
}

int vbi_compute_load_bias32(const u8 *image, size_t image_sz,
                            const struct vbi_load_mapping *mappings,
                            size_t mapping_count, u64 *load_bias) {
    if (!image || !load_bias || image_sz < sizeof(Elf32_Ehdr)) {
        return 0;
    }
    Elf32_Ehdr eh;
    if (!read_image(image, image_sz, 0, &eh, sizeof(eh))
        || eh.e_phentsize != sizeof(Elf32_Phdr) || eh.e_phnum == 0) {
        return 0;
    }
    uint64_t phdr_bytes = 0;
    if (!multiply_u64(eh.e_phnum, sizeof(Elf32_Phdr), &phdr_bytes)
        || !range_within_image(image_sz, eh.e_phoff, phdr_bytes)) {
        return 0;
    }
    uint64_t bias = 0;
    int found_load = 0;
    int found_exec = 0;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        uint64_t index = 0;
        uint64_t offset = 0;
        Elf32_Phdr ph;
        if (!multiply_u64(i, sizeof(ph), &index)
            || !add_u64(eh.e_phoff, index, &offset)
            || !read_image(image, image_sz, offset, &ph, sizeof(ph))) {
            return 0;
        }
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) {
            continue;
        }
        uint64_t segment_bias = bias;
        if (!mapping_load_bias(ph.p_offset, ph.p_vaddr, ph.p_filesz,
                               ph.p_flags, mappings, mapping_count,
                               &segment_bias, &found_exec)) {
            return 0;
        }
        if (found_load && segment_bias != bias) {
            return 0;
        }
        bias = segment_bias;
        found_load = 1;
    }
    if (!found_load || !found_exec) {
        return 0;
    }
    *load_bias = bias;
    return 1;
}

/* File section headers are needed for hidden jemalloc symbols. They are not
 * necessarily mapped into the guest, unlike PT_DYNAMIC exported symbols. */
struct entry_section {
    uint64_t offset, size, address, flags, entry_size;
    uint32_t type, link;
};
struct entry_section64 {
    uint32_t name, type;
    uint64_t flags, address, offset, size;
    uint32_t link, info;
    uint64_t alignment, entry_size;
};
struct entry_section32 {
    uint32_t name, type, flags, address, offset, size, link, info;
    uint32_t alignment, entry_size;
};

static int entry_section_read(const u8 *image, size_t size, int bits,
                              u64 table, unsigned width, unsigned count,
                              unsigned index, struct entry_section *out) {
    if (index >= count || table > UINT64_MAX - (u64)index * width) {
        return 0;
    }
    u64 at = table + (u64)index * width;
    if (bits == 64) {
        struct entry_section64 section;
        if (width != sizeof(section)
            || !read_image(image, size, at, &section, sizeof(section))) {
            return 0;
        }
        *out = (struct entry_section){section.offset, section.size,
                                      section.address, section.flags, section.entry_size, section.type, section.link};
    } else {
        struct entry_section32 section;
        if (width != sizeof(section)
            || !read_image(image, size, at, &section, sizeof(section))) {
            return 0;
        }
        *out = (struct entry_section){section.offset, section.size,
                                      section.address, section.flags, section.entry_size, section.type, section.link};
    }
    return 1;
}

static int entry_unsafe_name(const char *name) {
    static const char *const names[] = {
        "malloc", "calloc", "realloc", "free", "aligned_alloc",
        "posix_memalign", "memalign", "valloc", "pvalloc",
        "pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock"
    };
    if (strncmp(name, "je_", 3) == 0) {
        return 1;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (strcmp(name, names[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int vbi_elf_libc_entry_busy(const u8 *image, size_t size, int bitness,
                            u64 bias, u64 pc, u64 lr) {
    u64 table;
    unsigned width, count;
    if (!image || size < EI_NIDENT || memcmp(image, ELFMAG, SELFMAG)
        || image[5] != 1 || (bitness != 32 && bitness != 64)) {
        return -1;
    }
    if (bitness == 64) {
        Elf64_Ehdr header;
        if (image[4] != 2 || !read_image(image, size, 0, &header, sizeof(header))
            || header.e_machine != 183 || header.e_type != 3) {
            return -1;
        }
        table = header.e_shoff; width = header.e_shentsize; count = header.e_shnum;
    } else {
        Elf32_Ehdr header;
        if (image[4] != 1 || !read_image(image, size, 0, &header, sizeof(header))
            || header.e_machine != 40 || header.e_type != 3) {
            return -1;
        }
        table = header.e_shoff; width = header.e_shentsize; count = header.e_shnum;
        pc &= ~1ULL; lr &= ~1ULL;
    }
    if (!count || count > 4096 || !table
        || !range_within_image(size, table, (u64)width * count)) {
        return -1;
    }
    int found_unlock = 0, busy = 0;
    size_t total_symbols = 0;
    for (unsigned i = 0; i < count; ++i) {
        struct entry_section symbols, strings;
        if (!entry_section_read(image, size, bitness, table, width, count, i, &symbols)) {
            return -1;
        }
        if (symbols.type != 2 && symbols.type != 11) {
            continue;
        }
        size_t expected = bitness == 64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
        if (symbols.entry_size != expected || symbols.size % expected
            || !range_within_image(size, symbols.offset, symbols.size)
            || !entry_section_read(image, size, bitness, table, width, count,
                                   symbols.link, &strings)
            || strings.type != 3
            || !range_within_image(size, strings.offset, strings.size)) {
            return -1;
        }
        size_t number = symbols.size / expected;
        if (number > 262144 || total_symbols > 262144 - number) {
            return -1;
        }
        total_symbols += number;
        for (size_t j = 0; j < number; ++j) {
            u64 value, length;
            uint32_t name;
            uint16_t section_index;
            unsigned info;
            u64 at = symbols.offset + j * expected;
            if (bitness == 64) {
                Elf64_Sym symbol;
                if (!read_image(image, size, at, &symbol, sizeof(symbol))) {
                    return -1;
                }
                value = symbol.st_value; length = symbol.st_size;
                name = symbol.st_name; section_index = symbol.st_shndx; info = symbol.st_info;
            } else {
                Elf32_Sym symbol;
                if (!read_image(image, size, at, &symbol, sizeof(symbol))) {
                    return -1;
                }
                value = symbol.st_value & ~1ULL; length = symbol.st_size;
                name = symbol.st_name; section_index = symbol.st_shndx; info = symbol.st_info;
            }
            if (name >= strings.size
                || !memchr(image + strings.offset + name, 0, strings.size - name)) {
                return -1;
            }
            if ((info & 15) != 2 || !section_index || !length) {
                continue;
            }
            const char *label = (const char *)image + strings.offset + name;
            if (!entry_unsafe_name(label)) {
                continue;
            }
            struct entry_section code;
            if (!entry_section_read(image, size, bitness, table, width, count,
                                    section_index, &code)
                || !(code.flags & 4) || value < code.address
                || value - code.address > code.size
                || length > code.size - (value - code.address)
                || bias > UINT64_MAX - value || bias + value > UINT64_MAX - length) {
                return -1;
            }
            u64 start = bias + value, end = start + length;
            if (strcmp(label, "pthread_mutex_unlock") == 0) {
                found_unlock = 1;
            }
            if ((pc >= start && pc < end) || (lr >= start && lr < end)) {
                busy = 1;
            }
        }
    }
    return found_unlock ? busy : -1;
}
