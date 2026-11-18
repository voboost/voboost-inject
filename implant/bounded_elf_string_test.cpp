#include "bounded_elf_string.h"

#include <cassert>

int main() {
    const char names[] = ".symtab\0.strtab\0unterminated";
    assert(bounded_elf_string_equals(names, names + sizeof(names), ".symtab"));
    assert(bounded_elf_string_equals(names + 8, names + sizeof(names), ".strtab"));
    assert(!bounded_elf_string_equals(names + 16, names + sizeof(names) - 1, "unterminated"));
    assert(!bounded_elf_string_equals(names, names + 7, ".symtab"));

    assert(exact_library_basename("/system/lib64/libart.so", "libart.so"));
    assert(exact_library_basename("libart.so", "libart.so"));
    assert(!exact_library_basename("/system/lib64/libart.so.backup", "libart.so"));
    assert(!exact_library_basename("/data/libart.so/other.so", "libart.so"));
    assert(!exact_library_basename("/system/lib64/not-libart.so", "libart.so"));
    return 0;
}
