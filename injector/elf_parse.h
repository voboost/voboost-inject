/*
 * elf_parse.h — pure ELF symbol parser (host-testable, no ptrace).
 *
 * resolve_elf32/64_symbol walk an in-memory ELF image's PT_DYNAMIC to find a
 * symbol by name, returning load_bias + st_value. They have no target-I/O
 * dependency, so they can be unit-tested on the host against a real linker
 * image with no device and no ptrace (native-payload: runtime ELF symbol
 * resolution).
 *
 * ELF types are defined inline (not via <linux/elf.h>) so the parser compiles
 * with both ndk-build (Android) and a host C compiler (Apple clang) for the
 * unit-test, with no system-header differences. Only the subset of fields
 * the parser touches is included; layout matches Elf64/Elf32 exactly.
 */
#ifndef VOBOOST_INJECT_ELF_PARSE_H
#define VOBOOST_INJECT_ELF_PARSE_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned long long u64;
typedef uint8_t u8;

/* ---- minimal ELF type subset (Elf64 / Elf32, little-endian ARM targets) ---- */

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    int64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
} Elf64_Dyn;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} Elf32_Phdr;

typedef struct {
    int32_t d_tag;
    union {
        uint32_t d_val;
        uint32_t d_ptr;
    } d_un;
} Elf32_Dyn;

typedef struct {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
} Elf32_Sym;

#define EI_NIDENT 16
#define ELFMAG     "\x7f""ELF"
#define SELFMAG    4

#define PT_DYNAMIC 2

#define DT_NULL    0
#define DT_STRTAB  5
#define DT_SYMTAB  6
#define DT_STRSZ   10
#define DT_SYMENT  11

#define SHN_UNDEF  0

/* Resolve `name` in a 64-bit ELF image. Returns load_bias + st_value, or 0. */
u64 resolve_elf64_symbol(const u8 *image, size_t image_sz, u64 load_bias,
                         const char *name);

/* Resolve `name` in a 32-bit ELF image. Returns load_bias + st_value, or 0. */
u64 resolve_elf32_symbol(const u8 *image, size_t image_sz, u64 load_bias,
                         const char *name);

#endif /* VOBOOST_INJECT_ELF_PARSE_H */
