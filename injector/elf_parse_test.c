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
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }
    rewind(f);
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

int main(void) {
    size_t sz64 = 0, sz32 = 0;
    u64 img64 = load_file("test/fixtures/linker/linker64", &sz64);
    u64 img32 = load_file("test/fixtures/linker/linker32", &sz32);
    if (!img64 || !img32) {
        fprintf(stderr, "FAIL: cannot load test/fixtures/linker/{linker64,linker32}\n");
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

    /* 32-bit linker. */
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlopen"),
          LINKER32_DLOPEN, "32 dlopen");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlsym"),
          LINKER32_DLSYM, "32 dlsym");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_dlerror"),
          LINKER32_DLERROR, "32 dlerror");
    check(resolve_elf32_symbol(i32, sz32, BIAS, "__loader_does_not_exist"),
          0, "32 missing->0");

    /* load_bias is added to st_value. */
    check(resolve_elf64_symbol(i64, sz64, 0x7000000000ULL, "__loader_dlsym"),
          0x7000000000ULL + LINKER64_DLSYM, "64 dlsym+bias");

    /* Malformed inputs fail closed. */
    check(resolve_elf64_symbol(NULL, sz64, BIAS, "__loader_dlopen"), 0, "null image");
    check(resolve_elf64_symbol(i64, 4, BIAS, "__loader_dlopen"), 0, "tiny image");
    check(resolve_elf64_symbol(i64, sz64, BIAS, NULL), 0, "null name");

    free((void *)img64);
    free((void *)img32);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    /* Silent on success (codestyle). */
    return 0;
}
