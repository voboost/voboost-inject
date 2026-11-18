#include "voboost_locale_host_v1.h"
#include "voboost_locale_object_host_v1.h"
#include <cassert>
#include <cstring>
#include <string>
#include <unistd.h>
extern "C" const VbcLocaleHostV1 *vbc_locale_host_v1();
struct ScreenReference { void *object, *owner; ~ScreenReference() {} };
static bool admitted = true, ui = true, attached = true;
static bool owner_live, object_available = true, descriptor_available = true;
static int identity = -1;
static unsigned preparations;
static std::string locale = "english";
static unsigned releases, reads, symbol_calls;
static const char *missing;
static unsigned char screen_object[32];
static int owner_object, descriptor_object;
static void *descriptor = &descriptor_object;
static ScreenReference screen() {
    assert(!owner_live); owner_live = true;
    return {attached ? screen_object : nullptr, &owner_object};
}
static void release(void *owner) { assert(owner_live && owner == &owner_object); owner_live = false; ++releases; }
static const void *read_property(const void *object, void *type) {
    assert(owner_live && object == screen_object + 8 && type == descriptor); ++reads; return &locale;
}
static const char *c_str(const void *object) {
    assert(owner_live && object == &locale); return locale.c_str();
}
extern "C" int vbc_locale_owner_identity(uint32_t owner) {
    return owner == 1 && admitted ? identity : 0;
}
extern "C" int vbc_locale_prepare_identity(uint32_t owner) {
    if (owner != 1 || !admitted) return 0;
    ++preparations; return identity;
}
static void *property_object(VbcLocaleObjectKindV1 kind, void *pinned) {
    assert(owner_live && kind == VBC_LOCALE_SCREEN_OBJECT && pinned == screen_object);
    return object_available ? screen_object + 8 : nullptr;
}
static const void *property_descriptor(VbcLocaleObjectKindV1 kind) {
    assert(owner_live && kind == VBC_LOCALE_SCREEN_OBJECT);
    return descriptor_available ? &descriptor : nullptr;
}
static int ui_ready() { return ui; }
static int prepare_current() { return vbc_locale_prepare_identity(VBC_LOCALE_GAUGE); }
static uint32_t current_owner() { return admitted && identity == 1 ? VBC_LOCALE_GAUGE : 0; }
extern "C" const VbcLocaleObjectHostV1 *vbc_locale_object_host_v1() {
    static const VbcLocaleObjectHostV1 api = {VBC_LOCALE_OBJECT_HOST_ABI_V1, sizeof(VbcLocaleObjectHostV1), property_object, property_descriptor, prepare_current, current_owner, ui_ready};
    return &api;
}
extern "C" void *vbc_host_resolve(const char *, const char *name) {
    ++symbol_calls;
    if (missing && std::strcmp(name, missing) == 0) return nullptr;
    if (std::strcmp(name, "_Z20getApplicationScreenv") == 0) return (void *)screen;
    if (std::strstr(name, "_M_releaseEv")) return (void *)release;
    if (std::strstr(name, "getFinalValueSource")) return (void *)read_property;
    if (std::strstr(name, "c_strEv")) return (void *)c_str;
    if (std::strstr(name, "LocaleProperty")) return &descriptor;
    assert(false); return nullptr;
}
int main(int argc, char **argv) {
    alarm(5);
    const auto *api = vbc_locale_host_v1();
    assert(api->abi == 1 && api->size == sizeof(*api) && api->observe && api->prepare);
    VbcLocaleObservationV1 out = {}; out.size = sizeof(out);
    if (argc > 1) {
        assert(argc == 2 && std::strcmp(argv[1], "--missing-symbol") == 0);
        identity = 1;
        missing = "_Z20getApplicationScreenv";
        assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
        assert(releases == 0 && reads == 0 && !out.capabilities);
        unsigned resolved = symbol_calls;
        assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
        assert(symbol_calls == resolved); return 0;
    }
    assert(api->observe(VBC_LOCALE_GAUGE, nullptr) == VBC_LOCALE_UNSUPPORTED);
    out.size = 1;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
    out.size = sizeof(out);
    for (auto owner : {VBC_LOCALE_POINT, VBC_LOCALE_LIGHT, VBC_LOCALE_IGNOFF})
        assert(api->observe(owner, &out) == VBC_LOCALE_UNSUPPORTED);
    assert(symbol_calls == 0);
    admitted = false;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
    assert(symbol_calls == 0); admitted = true;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_WAITING_IDENTITY);
    assert(!out.capabilities && !out.screen_identity && !out.locale[0]);
    assert(preparations == 0 && symbol_calls == 0 && reads == 0);
    assert(api->prepare(VBC_LOCALE_POINT) == VBC_LOCALE_UNSUPPORTED);
    assert(preparations == 0);
    assert(api->prepare(VBC_LOCALE_GAUGE) == VBC_LOCALE_WAITING_IDENTITY);
    assert(preparations == 1 && symbol_calls == 0 && reads == 0);
    // Only the completed background identity receipt admits subsequent UI work.
    identity = 1;
    assert(api->prepare(VBC_LOCALE_GAUGE) == VBC_LOCALE_OK);
    ui = false;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_WAITING_UI);
    assert(symbol_calls == 0); ui = true;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_OK);
    assert(std::strcmp(out.locale, "english") == 0);
    assert(out.capabilities == VBC_LOCALE_CAN_OBSERVE && out.screen_identity == (uintptr_t)screen_object);
    assert(releases == 1 && reads == 1);
    locale = "russian";
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_OK);
    assert(std::strcmp(out.locale, "russian") == 0 && releases == 2 && reads == 2);
    identity = -1;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_WAITING_IDENTITY);
    assert(!out.locale[0] && !out.capabilities && !out.screen_identity && releases == 2);
    identity = 1;
    object_available = false;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
    assert(!owner_live && releases == 3 && reads == 2 && !out.locale[0] && !out.capabilities && !out.screen_identity);
    object_available = true; descriptor_available = false;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_UNSUPPORTED);
    assert(!owner_live && releases == 4 && reads == 2 && !out.locale[0] && !out.capabilities && !out.screen_identity);
    descriptor_available = true;
    for (const char *invalid : {"", "too-long-locale-name-over-thirty-two-bytes", "ru\x01"}) {
        locale = invalid;
        assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_READBACK_FAILED);
        assert(!out.locale[0] && !out.capabilities && !out.screen_identity);
    }
    assert(releases == 7 && !owner_live);
    attached = false;
    assert(api->observe(VBC_LOCALE_GAUGE, &out) == VBC_LOCALE_WAITING_UI);
    assert(releases == 8 && !owner_live && !out.capabilities); attached = true;
    assert(symbol_calls == 5); // No per-frame dlopen references.
}
