#include "bounded_elf_string.h"
#include "../injector/elf_parse.h"

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <vector>

struct Elf64_Shdr {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
};
static_assert(sizeof(Elf64_Shdr) == 64);
using Elf64_Addr = uint64_t;
#define ElfW(type) Elf64_ ## type
#define SHT_SYMTAB 2

static constexpr size_t kMaxProgramHeaders = 256;
static int maps_fd = -1;
static int fixture_open(const char *path, int flags) {
    if (std::strcmp(path, "/proc/self/maps") == 0) {
        assert(lseek(maps_fd, 0, SEEK_SET) == 0);
        return dup(maps_fd);
    }
    return open(path, flags);
}
static void vbi_symtab_trace(const char *, const char *, long) {
}
#define open fixture_open
#include "symtab_resolver_test.inc"
#undef open

struct LiveElf {
    Elf64_Ehdr header;
    Elf64_Phdr program;
};

int main() {
    char library[] = "/tmp/voboost-symtab.XXXXXX";
    char maps[] = "/tmp/voboost-symtab-maps.XXXXXX";
    int fd = mkstemp(library);
    maps_fd = mkstemp(maps);
    assert(fd >= 0 && maps_fd >= 0);
    assert(unlink(maps) == 0);
    LiveElf live{};
    std::memcpy(live.header.e_ident, "\177ELF", 4);
    live.header.e_phoff = offsetof(LiveElf, program);
    live.header.e_phnum = 1;
    live.program.p_type = PT_LOAD;
    char map_line[512];
    const uintptr_t base = reinterpret_cast<uintptr_t>(&live);
    int length = snprintf(map_line, sizeof(map_line), "%lx-%lx r-xp 00000000 00:00 1 %s\n",
                          static_cast<unsigned long>(base),
                          static_cast<unsigned long>(base + sizeof(live)), library);
    assert(length > 0 && length < static_cast<int>(sizeof(map_line)));
    assert(write(maps_fd, map_line, static_cast<size_t>(length)) == length);

    Elf64_Ehdr header{};
    std::memcpy(header.e_ident, "\177ELF", 4);
    header.e_shoff = sizeof(header);
    header.e_shnum = 3;
    header.e_shentsize = sizeof(Elf64_Shdr);
    Elf64_Shdr sections[3]{};
    Elf64_Sym symbols[4]{};
    const char strings[] = "\0target\0target_suffix\0unterminated";
    sections[1].sh_type = SHT_SYMTAB;
    sections[1].sh_offset = sizeof(header) + sizeof(sections);
    sections[1].sh_size = sizeof(symbols);
    sections[1].sh_entsize = sizeof(Elf64_Sym);
    sections[1].sh_link = 2;
    sections[2].sh_offset = sections[1].sh_offset + sizeof(symbols);
    sections[2].sh_size = sizeof(strings) - 1;
    symbols[1].st_name = 1; symbols[1].st_value = 0x100;
    symbols[2].st_name = 8; symbols[2].st_value = 0x200;
    symbols[3].st_name = 22; symbols[3].st_value = 0x300;
    const auto publish = [&] {
                             assert(ftruncate(fd, 0) == 0);
                             assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
                             assert(pwrite(fd, sections, sizeof(sections), sizeof(header)) == sizeof(sections));
                             assert(pwrite(fd, symbols, sizeof(symbols), sections[1].sh_offset) == sizeof(symbols));
                             assert(pwrite(fd, strings, sizeof(strings) - 1, sections[2].sh_offset) == sizeof(strings) - 1);
                         };
    const char *name = std::strrchr(library, '/') + 1;
    publish();
    assert(safe_resolve_symbol_symtab(name, "target", false) == reinterpret_cast<void *>(base + 0x100));
    assert(safe_resolve_symbol_symtab(name, "target_", true) == reinterpret_cast<void *>(base + 0x200));
    assert(!safe_resolve_symbol_symtab(name, "missing", false));
    assert(!safe_resolve_symbol_symtab(name, "unterminated", false));
    assert(!safe_resolve_symbol_symtab(name, "unterminated", true));
    assert(!safe_resolve_symbol_symtab(nullptr, "target", false));
    assert(!safe_resolve_symbol_symtab(name, "", false));
    symbols[1].st_name = static_cast<uint32_t>(sections[2].sh_size);
    publish();
    assert(!safe_resolve_symbol_symtab(name, "target", false));
    header.e_shentsize++;
    publish();
    assert(!safe_resolve_symbol_symtab(name, "target_", true));
    close(fd);
    close(maps_fd);
    assert(unlink(library) == 0);
}
