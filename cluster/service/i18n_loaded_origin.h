#ifndef VBC_LOADED_ORIGIN_H
#define VBC_LOADED_ORIGIN_H
#include <stddef.h>
#include <stdint.h>
/* UI-thread confined. Inputs come only from successful OEM resource calls.
 * This captures origin, not translation completeness or selected language. */
struct VbcLoadedOrigin {
    uintptr_t manager, directory;
    uint32_t kind;
    char project[128];
    uint64_t epoch;
    char source[256];
    struct Binding { uintptr_t resource; char uri[256]; } bindings[3];
    constexpr VbcLoadedOrigin():manager(0),directory(0),kind(0),project{},epoch(0),source{},bindings{} {}
    bool opened(uintptr_t manager_value, uintptr_t directory_value, const char *path, size_t length);
    bool bound(uintptr_t manager_value, uintptr_t directory_value, uintptr_t resource,
               const char *uri, size_t length);
    void removed(uintptr_t manager_value, uintptr_t directory_value);
    bool complete(uintptr_t manager_value, uintptr_t directory_value) const;
private:
    void invalidate();
};
#endif
