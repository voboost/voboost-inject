/* injector_internal.h — production-internal seam shared between injector.c
 * and the production host test. Nothing here is part of the injected
 * binary's public ABI; it exists so the host test can exercise fail-closed
 * branches that run before any ptrace operation (Linux gate). */
#ifndef VBI_INJECTOR_INTERNAL_H
#define VBI_INJECTOR_INTERNAL_H

#include "elf_parse.h" /* u64 */

struct vbi_scratch_layout;

struct vbi_loader_api {
    u64 create_namespace;
    u64 link_namespaces;
    u64 get_exported_namespace;
    u64 dlopen_ext;
    u64 dlopen;
    u64 dlsym;
    u64 dlerror;
};

/* Loads the payload through a bounded namespace created in the target
 * linker. Returns a target-local handle, or 0 with a phase diagnostic on
 * any fail-closed branch (never a fabricated handle). */
u64 remote_namespace_load(int pid, int bitness,
                          const struct vbi_loader_api *api,
                          const struct vbi_scratch_layout *scratch,
                          u64 caller, const char *so_path,
                          char *dlerr_out, size_t dlerr_out_sz);

#endif
