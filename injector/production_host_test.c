#define _GNU_SOURCE
#include <stdio.h>

#if defined(__linux__)
#include "injector.h"
#include "injector_internal.h"
#include "elf_parse.h"
#include "maps_parse.h"

#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int target_read_mem(int pid, unsigned long long addr, void *buf, size_t len);
int target_write_mem(int pid, unsigned long long addr, const void *buf, size_t len);
int target_verify_mem(int pid, unsigned long long addr, const void *expected, size_t len);
unsigned long long resolve_loader_symbol(int pid, int bitness, const char *symbol);

static void test_target_memory_boundaries(void) {
    char source[] = "production-memory";
    char observed[sizeof(source)] = {0};
    assert(target_read_mem(getpid(), (uintptr_t)source, observed, sizeof(source)) == 0);
    assert(memcmp(source, observed, sizeof(source)) == 0);
    assert(target_verify_mem(getpid(), (uintptr_t)source, source, sizeof(source)) == 0);
    observed[0] ^= 1;
    assert(target_verify_mem(getpid(), (uintptr_t)source, observed, sizeof(source)) != 0);

    char target[sizeof(source)] = {0};
    assert(target_write_mem(getpid(), (uintptr_t)target, source, sizeof(source)) == 0);
    assert(memcmp(source, target, sizeof(source)) == 0);
    assert(target_read_mem(getpid(), 0, NULL, sizeof(source)) != 0);
    assert(target_read_mem(getpid(), UINTPTR_MAX, observed, 2) != 0);
    assert(target_write_mem(getpid(), 0, NULL, sizeof(source)) != 0);
    assert(target_write_mem(getpid(), UINTPTR_MAX, source, 2) != 0);
    assert(target_write_mem(getpid(), (uintptr_t)target, source, 64 * 1024 + 1) != 0);
    assert(target_verify_mem(getpid(), (uintptr_t)source, source, 0) != 0);
    assert(resolve_loader_symbol(getpid(), 0, "__loader_dlopen") == 0);
    assert(resolve_loader_symbol(getpid(), 64, NULL) == 0);
}

static void test_top_level_attach_rejects_before_remote_mutation_and_detaches(void) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        for (;;) {
            pause();
        }
    }

    struct vbi_agent_pipe_fds pipes = {.record_read_fd = 41, .state_reply_fd = 42};
    char diagnostic[8] = "stale";
    int result = vbi_inject(child, "/data/voboost/libimplant-arm64-v8a.so", NULL,
                            NULL, "never-consumed", 0, (uint32_t)getuid(),
                            "u:r:system_app:s0", &pipes, diagnostic,
                            sizeof(diagnostic));
    assert(result == -7);
    assert(pipes.record_read_fd == -1 && pipes.state_reply_fd == -1);
    assert(diagnostic[0] == '\0');
    assert(kill(child, 0) == 0);
    assert(kill(child, SIGKILL) == 0);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

/* N5 fixture: a resolved loader api whose get_exported_namespace leg is
 * missing (older linker without the export, or resolve failure) must fail
 * closed BEFORE any remote call: invalid pid ensures the first ptrace
 * operation would fail the whole test; the export-unavailable branch must
 * return a null handle and the exact phase diagnostic instead. */
static void test_namespace_export_unavailable_fails_closed_before_remote_calls(void) {
    short dummy = 0;
    struct vbi_scratch_layout scratch = {
        .path = (uintptr_t)&dummy,
        .config = (uintptr_t)&dummy,
        .symbol = (uintptr_t)&dummy,
        .auxiliary = (uintptr_t)&dummy,
        .start = (uintptr_t)&dummy,
        .size = 8192,
    };
    struct vbi_loader_api api = {
        .create_namespace = 0x1000,
        .link_namespaces = 0x1008,
        .get_exported_namespace = 0, /* export leg missing — the N5 premise */
        .dlopen_ext = 0x1020,
        .dlopen = 0x1028,
        .dlsym = 0x1030,
        .dlerror = 0x1038,
    };
    char diagnostic[64] = {0};
    /* pid -1 is rejected by every ptrace entry point, so any attempted
     * remote call or remote memory write would return an error; the branch
     * under test must not attempt any of them. */
    unsigned long long handle = remote_namespace_load(
        -1, 64, &api, &scratch,
        0x2000, "/data/voboost/libimplant-arm64-v8a.so",
        diagnostic, sizeof(diagnostic));
    assert(handle == 0);
    assert(strcmp(diagnostic, "namespace-export-unavailable") == 0);
}

int main(void) {
    test_target_memory_boundaries();
    test_top_level_attach_rejects_before_remote_mutation_and_detaches();
    test_namespace_export_unavailable_fails_closed_before_remote_calls();
    return 0;
}
#else
int main(void) {
    fprintf(stderr, "SKIP: production injector host execution requires Linux\n");
    return 77;
}
#endif
