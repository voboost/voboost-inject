/*
 * dobby_adapter.cpp — Dobby-backed LSPlant inline-hook slots.
 *
 * Provides the inline_hooker and inline_unhooker callbacks that LSPlant::Init
 * needs, implemented as lambdas over DobbyHook / DobbyDestroy.
 *
 * No logging inside these callbacks — they may be invoked from within ART's
 * internal call paths where __android_log_print corrupts state via the
 * trampoline. Pure function-pointer plumbing.
 */

#include "dobby.h"

/*
 * Install an inline hook: target → hooker.
 * Returns the origin (original) function pointer, or nullptr on failure.
 */
extern "C" void *vbi_dobby_inline_hooker(void *target, void *hooker) {
    void *origin = nullptr;
    int rc = DobbyHook(target, hooker, &origin);
    if (rc != 0) {
        return nullptr;
    }
    return origin;
}

/*
 * Remove a previously-installed inline hook.
 * Returns true on success, false on failure.
 */
extern "C" bool vbi_dobby_inline_unhooker(void *func) {
    int rc = DobbyDestroy(func);
    return rc == 0;
}
