/*
 * lsplant.hpp — LSPlant InitInfo definition (source version).
 *
 * The Maven-published InitInfo ABI diverged (missing Allocator/Recycler),
 * so we build from source with this header. This is a minimal forward
 * declaration matching the InitInfo fields the implant wires.
 *
 * The real header is in the lsplant source tree (lsplant-src/include/lsplant.hpp).
 * This stub provides the types for compilation; the actual lsplant::Init/Hook
 * symbols are resolved via dlsym at runtime.
 */
#ifndef LSPLANT_HPP
#define LSPLANT_HPP

#include <jni.h>
#include <functional>
#include <string_view>

namespace lsplant {

struct InitInfo {
    std::function<void *(void *, void *)> inline_hooker;
    std::function<bool(void *)> inline_unhooker;
    std::function<void *(std::string_view)> art_symbol_resolver;
    std::function<void *(std::string_view)> art_symbol_prefix_resolver;
};

} // namespace lsplant

#endif // LSPLANT_HPP
