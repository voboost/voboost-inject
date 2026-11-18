#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

static int calls;
static int deny_call;
static size_t protected_size;
static int patch_mprotect(void *address, size_t size, int protection) {
    ++calls;
    protected_size = size;
    if (calls == deny_call) {
        errno = EACCES;
        return -1;
    }
    // The host verifies real read-only memory without requiring executable mappings.
    return mprotect(address, size, protection & ~PROT_EXEC);
}

// Compile the actual POSIX implementation on both Linux and macOS hosts.
#undef __APPLE__
#define __linux__ 1
#define mprotect patch_mprotect
#include DOBBY_PATCH_SOURCE
#undef mprotect

int main() {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *memory = static_cast<uint8_t *>(mmap(nullptr, page * 4, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANON, -1, 0));
    assert(memory != MAP_FAILED);
    memset(memory, 0x55, page * 4);
    assert(mprotect(memory, page * 4, PROT_READ) == 0);
    std::vector<uint8_t> bytes(page * 2 + 16, 0xAA);

    assert(mprotect(memory, page * 4, PROT_NONE) == 0);
    deny_call = 1;
    assert(DobbyCodePatch(memory + page - 8, bytes.data(), bytes.size()) == -1);
    assert(calls == 1);
    assert(mprotect(memory, page * 4, PROT_READ) == 0);
    for (size_t i = 0; i < page * 4; ++i) assert(memory[i] == 0x55);

    deny_call = 0;
    calls = 0;
    assert(DobbyCodePatch(memory + page - 8, bytes.data(), bytes.size()) == 0);
    assert(calls == 2 && protected_size == page * 4);
    assert(memcmp(memory + page - 8, bytes.data(), bytes.size()) == 0);
    assert(memory[page - 9] == 0x55 && memory[page * 3 + 8] == 0x55);

    calls = 0;
    assert(DobbyCodePatch(memory, bytes.data(), page) == 0);
    assert(calls == 2 && protected_size == page);

    calls = 0;
    assert(DobbyCodePatch(nullptr, bytes.data(), 1) == -1);
    assert(DobbyCodePatch(memory, nullptr, 1) == -1);
    assert(DobbyCodePatch(memory, bytes.data(), 0) == -1);
    assert(DobbyCodePatch(reinterpret_cast<void *>(UINTPTR_MAX - 1), bytes.data(), 4) == -1);
    assert(calls == 0);

    deny_call = 2;
    assert(DobbyCodePatch(memory, bytes.data(), 1) == -1);
    assert(calls == 2);
    assert(munmap(memory, page * 4) == 0);
}
