/*
 * elf_parse_test.c — host unit-test for the pure ELF symbol parser.
 *
 * Loads the real linker64/linker fixtures (test/fixtures/linker/) and asserts
 * resolve_elf{32,64}_symbol return the same offsets `llvm-nm` reports on the
 * device. No ptrace, no device — pure host test, silent on success.
 *
 * Build (see Makefile target test-injector):
 *   <ndk-clang> --sysroot=<ndk-sysroot> -I injector -O2 -Wall -Wextra -Werror \
 *       injector/elf_parse.c injector/elf_parse_test.c -o build/elf_parse_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_parse.h"

/* Device-verified offsets (llvm-nm --dynamic on /system/bin/linker{,64}). */
#define LINKER64_DLOPEN  0x14244ULL
#define LINKER64_DLSYM   0x14430ULL
#define LINKER64_DLERROR 0x1412cULL
#define LINKER32_DLOPEN  0x75b9ULL
#define LINKER32_DLSYM   0x76fdULL
#define LINKER32_DLERROR 0x7505ULL

/* load_bias for the test = 0, so the returned value == st_value (file offset). */
#define BIAS 0ULL

static int failures = 0;

static u64 load_file(const char *path, size_t *out_sz) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }
    u8 *buf = (u8 *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 0;
    }
    fclose(f);
    *out_sz = (size_t)sz;
    return (u64)buf;
}

static void check(u64 got, u64 want, const char *label) {
    if (got != want) {
        fprintf(stderr, "FAIL %-28s got=0x%llx want=0x%llx\n", label,
                (unsigned long long)got, (unsigned long long)want);
        failures++;
    }
}

static size_t fixture_mappings64(const u8 *image, size_t image_sz, u64 bias,
                                 struct vbi_load_mapping *out, size_t cap) {
    if (!image || image_sz < sizeof(Elf64_Ehdr) || !out) {
        return 0;
    }
    Elf64_Ehdr eh;
    memcpy(&eh, image, sizeof(eh));
    if (eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phoff > image_sz ||
        eh.e_phnum > (image_sz - eh.e_phoff) / sizeof(Elf64_Phdr)) {
        return 0;
    }
    size_t count = 0;
    for (uint16_t i = 0; i < eh.e_phnum && count < cap; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, image + eh.e_phoff + i * sizeof(ph), sizeof(ph));
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) {
            continue;
        }
        uint64_t page_offset = ph.p_offset & ~UINT64_C(0xfff);
        uint64_t page_vaddr = ph.p_vaddr & ~UINT64_C(0xfff);
        out[count].file_offset = page_offset;
        out[count].start = bias + page_vaddr;
        out[count].end = out[count].start + ph.p_filesz
                         + (ph.p_offset - page_offset);
        out[count].executable = (ph.p_flags & PF_X) != 0;
        count++;
    }
    return count;
}

static size_t fixture_mappings32(const u8 *image, size_t image_sz, u64 bias,
                                 struct vbi_load_mapping *out, size_t cap) {
    if (!image || image_sz < sizeof(Elf32_Ehdr) || !out) {
        return 0;
    }
    Elf32_Ehdr eh;
    memcpy(&eh, image, sizeof(eh));
    if (eh.e_phentsize != sizeof(Elf32_Phdr) || eh.e_phoff > image_sz ||
        eh.e_phnum > (image_sz - eh.e_phoff) / sizeof(Elf32_Phdr)) {
        return 0;
    }
    size_t count = 0;
    for (uint16_t i = 0; i < eh.e_phnum && count < cap; i++) {
        Elf32_Phdr ph;
        memcpy(&ph, image + eh.e_phoff + i * sizeof(ph), sizeof(ph));
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) {
            continue;
        }
        uint64_t page_offset = ph.p_offset & UINT32_C(~0xfff);
        uint64_t page_vaddr = ph.p_vaddr & UINT32_C(~0xfff);
        out[count].file_offset = page_offset;
        out[count].start = bias + page_vaddr;
        out[count].end = out[count].start + ph.p_filesz
                         + (ph.p_offset - page_offset);
        out[count].executable = (ph.p_flags & PF_X) != 0;
        count++;
    }
    return count;
}

static u8 *duplicate_image(const u8 *image, size_t image_sz) {
    u8 *copy = (u8 *)malloc(image_sz);
    if (copy) {
        memcpy(copy, image, image_sz);
    }
    return copy;
}

static Elf64_Phdr *dynamic_phdr64(u8 *image, size_t image_sz) {
    if (!image || image_sz < sizeof(Elf64_Ehdr)) {
        return NULL;
    }
    Elf64_Ehdr *eh = (Elf64_Ehdr *)image;
    if (eh->e_phentsize != sizeof(Elf64_Phdr) || eh->e_phoff > image_sz
        || eh->e_phnum > (image_sz - (size_t)eh->e_phoff) / sizeof(Elf64_Phdr)) {
        return NULL;
    }
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(image + (size_t)eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            return &phdrs[i];
        }
    }
    return NULL;
}

static Elf32_Phdr *dynamic_phdr32(u8 *image, size_t image_sz) {
    if (!image || image_sz < sizeof(Elf32_Ehdr)) {
        return NULL;
    }
    Elf32_Ehdr *eh = (Elf32_Ehdr *)image;
    if (eh->e_phentsize != sizeof(Elf32_Phdr) || eh->e_phoff > image_sz
        || eh->e_phnum > (image_sz - (size_t)eh->e_phoff) / sizeof(Elf32_Phdr)) {
        return NULL;
    }
    Elf32_Phdr *phdrs = (Elf32_Phdr *)(image + (size_t)eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            return &phdrs[i];
        }
    }
    return NULL;
}

static Elf64_Dyn *dynamic_tag64(u8 *image, size_t image_sz, int64_t tag) {
    Elf64_Phdr *ph = dynamic_phdr64(image, image_sz);
    if (!ph || ph->p_offset > image_sz
        || ph->p_filesz > image_sz - (size_t)ph->p_offset
        || ph->p_filesz % sizeof(Elf64_Dyn) != 0) {
        return NULL;
    }
    Elf64_Dyn *entries = (Elf64_Dyn *)(image + (size_t)ph->p_offset);
    size_t count = (size_t)ph->p_filesz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < count; i++) {
        if (entries[i].d_tag == tag) {
            return &entries[i];
        }
    }
    return NULL;
}

static Elf32_Dyn *dynamic_tag32(u8 *image, size_t image_sz, int32_t tag) {
    Elf32_Phdr *ph = dynamic_phdr32(image, image_sz);
    if (!ph || ph->p_offset > image_sz
        || ph->p_filesz > image_sz - (size_t)ph->p_offset
        || ph->p_filesz % sizeof(Elf32_Dyn) != 0) {
        return NULL;
    }
    Elf32_Dyn *entries = (Elf32_Dyn *)(image + (size_t)ph->p_offset);
    size_t count = (size_t)ph->p_filesz / sizeof(Elf32_Dyn);
    for (size_t i = 0; i < count; i++) {
        if (entries[i].d_tag == tag) {
            return &entries[i];
        }
    }
    return NULL;
}

static Elf64_Sym *symbol64(u8 *image, size_t image_sz, const char *name) {
    Elf64_Dyn *symtab_entry = dynamic_tag64(image, image_sz, DT_SYMTAB);
    Elf64_Dyn *strtab_entry = dynamic_tag64(image, image_sz, DT_STRTAB);
    Elf64_Dyn *strsz_entry = dynamic_tag64(image, image_sz, DT_STRSZ);
    if (!symtab_entry || !strtab_entry || !strsz_entry) {
        return NULL;
    }
    uint64_t symtab = symtab_entry->d_un.d_ptr;
    uint64_t strtab = strtab_entry->d_un.d_ptr;
    uint64_t strsz = strsz_entry->d_un.d_val;
    if (strtab <= symtab || symtab > image_sz || strtab > image_sz
        || strsz > image_sz - (size_t)strtab
        || (strtab - symtab) % sizeof(Elf64_Sym) != 0) {
        return NULL;
    }
    Elf64_Sym *symbols = (Elf64_Sym *)(image + (size_t)symtab);
    size_t count = (size_t)((strtab - symtab) / sizeof(Elf64_Sym));
    for (size_t i = 0; i < count; i++) {
        uint32_t name_offset = symbols[i].st_name;
        if (name_offset >= strsz) {
            continue;
        }
        const char *candidate = (const char *)(image + (size_t)strtab + name_offset);
        size_t remaining = (size_t)strsz - name_offset;
        const char *end = (const char *)memchr(candidate, '\0', remaining);
        if (end && (size_t)(end - candidate) == strlen(name)
            && memcmp(candidate, name, strlen(name)) == 0) {
            return &symbols[i];
        }
    }
    return NULL;
}

static Elf32_Sym *symbol32(u8 *image, size_t image_sz, const char *name) {
    Elf32_Dyn *symtab_entry = dynamic_tag32(image, image_sz, DT_SYMTAB);
    Elf32_Dyn *strtab_entry = dynamic_tag32(image, image_sz, DT_STRTAB);
    Elf32_Dyn *strsz_entry = dynamic_tag32(image, image_sz, DT_STRSZ);
    if (!symtab_entry || !strtab_entry || !strsz_entry) {
        return NULL;
    }
    uint32_t symtab = symtab_entry->d_un.d_ptr;
    uint32_t strtab = strtab_entry->d_un.d_ptr;
    uint32_t strsz = strsz_entry->d_un.d_val;
    if (strtab <= symtab || symtab > image_sz || strtab > image_sz
        || strsz > image_sz - (size_t)strtab
        || (strtab - symtab) % sizeof(Elf32_Sym) != 0) {
        return NULL;
    }
    Elf32_Sym *symbols = (Elf32_Sym *)(image + (size_t)symtab);
    size_t count = (strtab - symtab) / sizeof(Elf32_Sym);
    for (size_t i = 0; i < count; i++) {
        uint32_t name_offset = symbols[i].st_name;
        if (name_offset >= strsz) {
            continue;
        }
        const char *candidate = (const char *)(image + (size_t)strtab + name_offset);
        size_t remaining = (size_t)strsz - name_offset;
        const char *end = (const char *)memchr(candidate, '\0', remaining);
        if (end && (size_t)(end - candidate) == strlen(name)
            && memcmp(candidate, name, strlen(name)) == 0) {
            return &symbols[i];
        }
    }
    return NULL;
}

static void check_malformed64(const u8 *image, size_t image_sz) {
    u8 *copy = duplicate_image(image, image_sz);
    if (!copy) {
        failures++;
        return;
    }
    Elf64_Ehdr *eh = (Elf64_Ehdr *)copy;
    eh->e_phoff = UINT64_MAX - sizeof(Elf64_Phdr) + 1;
    check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
          0, "64 wrapped phdr range");
    free(copy);

    copy = duplicate_image(image, image_sz);
    eh = (Elf64_Ehdr *)copy;
    eh->e_phentsize = sizeof(Elf64_Phdr) - 1;
    check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
          0, "64 undersized phentsize");
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf64_Dyn *syment = dynamic_tag64(copy, image_sz, DT_SYMENT);
    if (!syment) {
        failures++;
    } else {
        syment->d_un.d_val = sizeof(Elf64_Sym) - 1;
        check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "64 undersized syment");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf64_Phdr *dynamic = dynamic_phdr64(copy, image_sz);
    if (!dynamic) {
        failures++;
    } else {
        dynamic->p_offset = image_sz - 1;
        dynamic->p_filesz = sizeof(Elf64_Dyn);
        check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "64 dynamic range");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    dynamic = dynamic_phdr64(copy, image_sz);
    if (!dynamic || dynamic->p_offset > image_sz
        || dynamic->p_filesz > image_sz - (size_t)dynamic->p_offset) {
        failures++;
    } else {
        Elf64_Dyn *entries = (Elf64_Dyn *)(copy + (size_t)dynamic->p_offset);
        size_t count = (size_t)dynamic->p_filesz / sizeof(Elf64_Dyn);
        for (size_t i = 0; i < count; i++) {
            if (entries[i].d_tag == DT_NULL) {
                entries[i].d_tag = 1;
            }
        }
        check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "64 dynamic lacks terminator");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf64_Dyn *strsz = dynamic_tag64(copy, image_sz, DT_STRSZ);
    if (!strsz) {
        failures++;
    } else {
        strsz->d_un.d_val = UINT64_MAX;
        check(resolve_elf64_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "64 overflowing strtab range");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf64_Sym *symbol = symbol64(copy, image_sz, "__loader_dlopen");
    if (!symbol) {
        failures++;
    } else {
        symbol->st_value = UINT64_MAX;
        check(resolve_elf64_symbol(copy, image_sz, 1, "__loader_dlopen"),
              0, "64 overflowing symbol address");
    }
    free(copy);
}

static void check_malformed32(const u8 *image, size_t image_sz) {
    u8 *copy = duplicate_image(image, image_sz);
    if (!copy) {
        failures++;
        return;
    }
    Elf32_Ehdr *eh = (Elf32_Ehdr *)copy;
    eh->e_phoff = UINT32_MAX - 1;
    eh->e_phnum = UINT16_MAX;
    check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
          0, "32 wrapped phdr range");
    free(copy);

    copy = duplicate_image(image, image_sz);
    eh = (Elf32_Ehdr *)copy;
    eh->e_phentsize = sizeof(Elf32_Phdr) - 1;
    check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
          0, "32 undersized phentsize");
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf32_Dyn *syment = dynamic_tag32(copy, image_sz, DT_SYMENT);
    if (!syment) {
        failures++;
    } else {
        syment->d_un.d_val = sizeof(Elf32_Sym) - 1;
        check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "32 undersized syment");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf32_Phdr *dynamic = dynamic_phdr32(copy, image_sz);
    if (!dynamic) {
        failures++;
    } else {
        dynamic->p_offset = (uint32_t)(image_sz - 1);
        dynamic->p_filesz = sizeof(Elf32_Dyn);
        check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "32 dynamic range");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    dynamic = dynamic_phdr32(copy, image_sz);
    if (!dynamic || dynamic->p_offset > image_sz
        || dynamic->p_filesz > image_sz - (size_t)dynamic->p_offset) {
        failures++;
    } else {
        Elf32_Dyn *entries = (Elf32_Dyn *)(copy + (size_t)dynamic->p_offset);
        size_t count = (size_t)dynamic->p_filesz / sizeof(Elf32_Dyn);
        for (size_t i = 0; i < count; i++) {
            if (entries[i].d_tag == DT_NULL) {
                entries[i].d_tag = 1;
            }
        }
        check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "32 dynamic lacks terminator");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf32_Dyn *strsz = dynamic_tag32(copy, image_sz, DT_STRSZ);
    if (!strsz) {
        failures++;
    } else {
        strsz->d_un.d_val = UINT32_MAX;
        check(resolve_elf32_symbol(copy, image_sz, BIAS, "__loader_dlopen"),
              0, "32 overflowing strtab range");
    }
    free(copy);

    copy = duplicate_image(image, image_sz);
    Elf32_Sym *symbol = symbol32(copy, image_sz, "__loader_dlopen");
    if (!symbol) {
        failures++;
    } else {
        symbol->st_value = UINT32_MAX;
        check(resolve_elf32_symbol(copy, image_sz, UINT64_MAX,
                                   "__loader_dlopen"),
              0, "32 overflowing symbol address");
    }
    free(copy);
}


struct test_section64 {
    uint32_t name, type;
    uint64_t flags, address, offset, size;
    uint32_t link, info;
    uint64_t alignment, entry_size;
};

struct test_section32 {
    uint32_t name, type, flags, address, offset, size, link, info;
    uint32_t alignment, entry_size;
};

static void check_libc_entry(void) {
    u8 image[2048] = {0};
    Elf64_Ehdr header = {0};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[4] = 2; header.e_ident[5] = 1;
    header.e_type = 3; header.e_machine = 183;
    header.e_shoff = 64; header.e_shentsize = sizeof(struct test_section64);
    header.e_shnum = 4;
    memcpy(image, &header, sizeof(header));
    struct test_section64 sections[4] = {0};
    sections[1] = (struct test_section64){.flags = 4, .address = 0x1000, .size = 0x400};
    sections[2] = (struct test_section64){.type = 11, .offset = 512,
                                          .size = 3 * sizeof(Elf64_Sym), .link = 3, .entry_size = sizeof(Elf64_Sym)};
    static const char strings[] = "\0pthread_mutex_unlock\0je_tcache_bin_flush_small\0";
    sections[3] = (struct test_section64){.type = 3, .offset = 1024, .size = sizeof(strings)};
    memcpy(image + 64, sections, sizeof(sections));
    memcpy(image + 1024, strings, sizeof(strings));
    Elf64_Sym symbols[3] = {0};
    symbols[1] = (Elf64_Sym){.st_name = 1, .st_info = 2, .st_shndx = 1,
                             .st_value = 0x1000, .st_size = 0x40};
    symbols[2] = (Elf64_Sym){.st_name = 22, .st_info = 2, .st_shndx = 1,
                             .st_value = 0x1100, .st_size = 0x40};
    memcpy(image + 512, symbols, sizeof(symbols));
    u64 bias = 0x7000000000ULL;
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1018, bias + 0x1110), 1, "libc mutex/allocator interrupted");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1018, 0), 1, "libc mutex PC alone");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  0, bias + 0x1110), 1, "libc allocator LR alone");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1040, bias + 0x1140), 0, "libc range end exclusive");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1200, 0), 0, "libc ordinary syscall allowed");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  0x1018, 0x1110), 0, "libc load bias required");
    symbols[2].st_info = 1;
    memcpy(image + 512, symbols, sizeof(symbols));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1110, 0), 0, "libc objects not code");
    sections[2].size = 2 * sizeof(Elf64_Sym);
    memcpy(image + 64, sections, sizeof(sections));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias,
                                  bias + 0x1018, 0), 1, "stripped local symbols mutex fallback");
    symbols[1].st_name = 5000;
    memcpy(image + 512, symbols, sizeof(symbols));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias, 0, 0),
          (u64)-1, "libc malformed strings deferred");
    symbols[1].st_name = 1; symbols[1].st_size = 0;
    memcpy(image + 512, symbols, sizeof(symbols));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, bias, 0, 0),
          (u64)-1, "libc missing mutex coverage deferred");
    symbols[1].st_size = 0x40;
    memcpy(image + 512, symbols, sizeof(symbols));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 64, UINT64_MAX - 8, 0, 0),
          (u64)-1, "libc address overflow deferred");
    check(vbi_elf_libc_entry_busy(image, 12, 64, bias, 0, 0),
          (u64)-1, "libc truncated deferred");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 32, bias, 0, 0),
          (u64)-1, "libc wrong ABI deferred");

    memset(image, 0, sizeof(image));
    Elf32_Ehdr header32 = {0};
    memcpy(header32.e_ident, ELFMAG, SELFMAG);
    header32.e_ident[4] = 1; header32.e_ident[5] = 1;
    header32.e_type = 3; header32.e_machine = 40;
    header32.e_shoff = 64; header32.e_shentsize = sizeof(struct test_section32);
    header32.e_shnum = 4;
    memcpy(image, &header32, sizeof(header32));
    struct test_section32 sections32[4] = {0};
    sections32[1] = (struct test_section32){.flags = 4, .address = 0x1000, .size = 0x400};
    sections32[2] = (struct test_section32){.type = 2, .offset = 512,
                                            .size = 3 * sizeof(Elf32_Sym), .link = 3, .entry_size = sizeof(Elf32_Sym)};
    sections32[3] = (struct test_section32){.type = 3, .offset = 1024, .size = sizeof(strings)};
    memcpy(image + 64, sections32, sizeof(sections32));
    memcpy(image + 1024, strings, sizeof(strings));
    Elf32_Sym symbols32[3] = {0};
    symbols32[1] = (Elf32_Sym){.st_name = 1, .st_info = 2, .st_shndx = 1,
                               .st_value = 0x1001, .st_size = 0x40};
    symbols32[2] = (Elf32_Sym){.st_name = 22, .st_info = 2, .st_shndx = 1,
                               .st_value = 0x1101, .st_size = 0x40};
    memcpy(image + 512, symbols32, sizeof(symbols32));
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 32, 0x70000000,
                                  0x70001019, 0), 1, "32 Thumb mutex PC");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 32, 0x70000000,
                                  0, 0x70001111), 1, "32 Thumb allocator LR");
    check(vbi_elf_libc_entry_busy(image, sizeof(image), 32, 0x70000000,
                                  0x70001041, 0x70001141), 0, "32 Thumb range end exclusive");
}

int main(int argc, char **argv) {
    if (argc == 2) {
        size_t size = 0;
        u64 loaded = load_file(argv[1], &size);
        const u8 *image = (const u8 *)loaded;
        check(vbi_elf_libc_entry_busy(image, size, 64, 0x77e3502000ULL,
                                      0x77e358401cULL, 0x77e35aa7ccULL), 1, "real A9 interrupted allocator");
        check(vbi_elf_libc_entry_busy(image, size, 64, 0x77e3502000ULL,
                                      0x77e356f910ULL, 0), 0, "real A9 idle ioctl allowed");
        free((void *)loaded);
        return failures ? 1 : 0;
    }

    check_libc_entry();
    struct vbi_load_mapping scratch[2];
    Elf64_Ehdr truncated64 = {0};
    truncated64.e_phoff = sizeof(truncated64);
    truncated64.e_phnum = 1;
    truncated64.e_phentsize = sizeof(Elf64_Phdr);
    check(fixture_mappings64((const u8 *)&truncated64, sizeof(truncated64),
                             0, scratch, 2), 0, "64 truncated fixture headers");
    Elf32_Ehdr truncated32 = {0};
    truncated32.e_phoff = sizeof(truncated32);
    truncated32.e_phnum = 1;
    truncated32.e_phentsize = sizeof(Elf32_Phdr);
    check(fixture_mappings32((const u8 *)&truncated32, sizeof(truncated32),
                             0, scratch, 2), 0, "32 truncated fixture headers");
    size_t sz64 = 0, sz32 = 0;
    u64 img64 = load_file("test/fixtures/linker/linker64", &sz64);
    u64 img32 = load_file("test/fixtures/linker/linker32", &sz32);
    if (!img64 || !img32) {
        fprintf(stderr, "FAIL: cannot load test/fixtures/linker/{linker64,linker32}\n");
        free((void *)img64);
        free((void *)img32);
        return 1;
    }
    const u8 *i64 = (const u8 *)img64;
    const u8 *i32 = (const u8 *)img32;

    /* 64-bit linker: three real symbols + one missing (fail-closed). */
    check(resolve_elf64_symbol(i64, sz64, BIAS, "__loader_dlopen"),
          LINKER64_DLOPEN, "64 dlopen");
    check(resolve_elf64_symbol(i64, sz64, BIAS, "__loader_dlsym"),
          LINKER64_DLSYM, "64 dlsym");
    check(resolve_elf64_symbol(i64, sz64, BIAS, "__loader_dlerror"),
          LINKER64_DLERROR, "64 dlerror");
    check(resolve_elf64_symbol(i64, sz64, BIAS, "__loader_does_not_exist"),
          0, "64 missing->0");

    /* An empty name must NOT
     * match the first symbol (would return an arbitrary address). */
    check(resolve_elf64_symbol(i64, sz64, BIAS, ""),
          0, "64 empty name->0");
    check(resolve_elf64_symbol(i64, sz64, BIAS, "a"),
          0, "64 single-char non-match->0");

    /* 32-bit linker. */
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlopen"),
          LINKER32_DLOPEN, "32 dlopen");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlsym"),
          LINKER32_DLSYM, "32 dlsym");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlerror"),
          LINKER32_DLERROR, "32 dlerror");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_does_not_exist"),
          0, "32 missing->0");
    check(resolve_elf32_symbol(i32, sz32, BIAS, ""),
          0, "32 empty name->0");

    /* load_bias is added to st_value. */
    check(resolve_elf64_symbol(i64, sz64, 0x7000000000ULL, "__loader_dlsym"),
          0x7000000000ULL + LINKER64_DLSYM, "64 dlsym+bias");

    struct vbi_load_mapping maps64[16];
    size_t maps64_count = fixture_mappings64(i64, sz64, 0x7000000000ULL,
                                             maps64, 16);
    u64 computed_bias = 0;
    check(vbi_compute_load_bias64(i64, sz64, maps64, maps64_count,
                                  &computed_bias),
          1, "64 load bias accepted");
    check(computed_bias, 0x7000000000ULL, "64 load bias");

    struct vbi_load_mapping maps32[16];
    size_t maps32_count = fixture_mappings32(i32, sz32, 0x70000000ULL,
                                             maps32, 16);
    computed_bias = 0;
    check(vbi_compute_load_bias32(i32, sz32, maps32, maps32_count,
                                  &computed_bias),
          1, "32 load bias accepted");
    check(computed_bias, 0x70000000ULL, "32 load bias");
    if (maps64_count > 0) {
        maps64[0].file_offset++;
        check(vbi_compute_load_bias64(i64, sz64, maps64, maps64_count,
                                      &computed_bias),
              0, "64 load bias rejects offset mismatch");
    }
    if (maps64_count >= 2) {
        maps64[0].file_offset--;
        /* Regression: kernel splits one PT_LOAD into several VMAs
           (r-xp + r--p + rw-p as for firmware linker64), so no single
           mapping spans the whole segment; bias must still be derived. */
        /* both mappings cover only the first page of their segment, as real
           split VMAs do (r-xp + r--p + rw-p for firmware linker64) */
        maps64[0].end = maps64[0].start + 0x1000;
        maps64[1].end = maps64[1].start + 0x1000;
        computed_bias = 0;
        check(vbi_compute_load_bias64(i64, sz64, maps64, maps64_count,
                                      &computed_bias),
              1, "64 load bias accepts split VMA");
        check(computed_bias, 0x7000000000ULL, "64 split-VMA bias");
    } else {
        check(maps64_count, 2, "64 split-VMA needs two mappings");
    }

    /* Malformed inputs fail closed. */
    check(resolve_elf64_symbol(NULL, sz64, BIAS, "__loader_dlopen"), 0, "null image");
    check(resolve_elf64_symbol(i64, 4, BIAS, "__loader_dlopen"), 0, "tiny image");
    check(resolve_elf64_symbol(i64, sz64, BIAS, NULL), 0, "null name");

    check_malformed64(i64, sz64);
    check_malformed32(i32, sz32);

    free((void *)img64);
    free((void *)img32);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    /* Silent on success (codestyle). */
    return 0;
}
