/* Exact A11 gauge observer. All calls occur on the already observed engine UI
 * frame. GNU strings remain owned by the OEM; only c_str() copies bytes out. */
#include "voboost_locale_host_v1.h"
#include "voboost_locale_object_host_v1.h"
extern "C" const VbcLocaleObjectHostV1 *vbc_locale_object_host_v1();
extern "C" void *vbc_host_resolve(const char *, const char *);
extern "C" int vbc_host_ui_ready();
extern "C" int vbc_locale_owner_identity(uint32_t);
extern "C" int vbc_locale_prepare_identity(uint32_t);
namespace {
struct ScreenReference {
    void *object, *owner;
    ~ScreenReference() {} // OEM shared owner is released through its own ABI.
};
using Screen = ScreenReference (*)();
using Release = void (*)(void *);
using FinalValue = const void *(*)(const void *, void *);
using CStr = const char *(*)(const void *);
static Screen screen;
static Release release;
static FinalValue value;
static CStr c_str;
static void **descriptor;
static bool attempted;
static VbcLocaleResultV1 prepare(VbcLocaleOwnerV1 owner) {
    if (owner < VBC_LOCALE_GAUGE || owner > VBC_LOCALE_LIGHT) return VBC_LOCALE_UNSUPPORTED;
    int identity = vbc_locale_prepare_identity(owner);
    return identity == 1 ? VBC_LOCALE_OK : identity == 0 ? VBC_LOCALE_UNSUPPORTED : VBC_LOCALE_WAITING_IDENTITY;
}
static VbcLocaleResultV1 observe(VbcLocaleOwnerV1 owner, VbcLocaleObservationV1 *out) {
    if (!out || out->size < sizeof(*out)) return VBC_LOCALE_UNSUPPORTED;
    out->owner = owner; out->capabilities = 0; out->screen_identity = 0;
    for (unsigned i = 0; i < sizeof(out->locale); ++i) out->locale[i] = 0;
    if (owner < VBC_LOCALE_GAUGE || owner > VBC_LOCALE_LIGHT) return VBC_LOCALE_UNSUPPORTED;
    int identity = vbc_locale_owner_identity(owner);
    if (identity != 1)
        return identity == 0 ? VBC_LOCALE_UNSUPPORTED : VBC_LOCALE_WAITING_IDENTITY;
    if (!vbc_locale_object_host_v1()->ui_ready()) return VBC_LOCALE_WAITING_UI;
    // The admitted process and libraries are pinned for its lifetime. Resolve
    // once on this UI thread: repeated dlopen calls would retain new references.
    if (!attempted) {
        attempted = true;
        screen = (Screen)vbc_host_resolve(nullptr, "_Z20getApplicationScreenv");
        release = (Release)vbc_host_resolve(nullptr,
        "_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv");
        value = (FinalValue)vbc_host_resolve("/lib64/libkzcore.so",
        "_ZNK5kanzi14PropertyObject19getFinalValueSourceERNS_30AbstractPropertyTypeDescriptorE");
        c_str = (CStr)vbc_host_resolve("/usr/lib64/libstdc++.so.6",
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv");
        descriptor = (void **)vbc_host_resolve("/lib64/libkzcoreui.so",
        "_ZN5kanzi4Node14LocalePropertyB5cxx11E");
    }
    if (!screen || !release || !value || !c_str || !descriptor || !*descriptor)
        return VBC_LOCALE_UNSUPPORTED;
    ScreenReference current = screen();
    if (!current.object || !current.owner) {
        if (current.owner) release(current.owner);
        return VBC_LOCALE_WAITING_UI;
    }
    auto objects=vbc_locale_object_host_v1();
    void *property_object=objects->property_object(VBC_LOCALE_SCREEN_OBJECT,current.object);
    const void *property=objects->property_descriptor(VBC_LOCALE_SCREEN_OBJECT);
    if(!property_object||!property){release(current.owner);return VBC_LOCALE_UNSUPPORTED;}
    const void *actual = value(property_object,*static_cast<void *const *>(property));
    const char *text = actual ? c_str(actual) : nullptr;
    unsigned length = 0;
    if (text) while (length < VBC_LOCALE_NAME_BYTES && text[length]) ++length;
    bool valid = text && length && length < VBC_LOCALE_NAME_BYTES;
    if (valid) {
        for (unsigned i = 0; i < length; ++i) {
            unsigned char ch = (unsigned char)text[i];
            if (ch < 0x20 || ch > 0x7e) valid = false;
            out->locale[i] = text[i];
        }
    }
    if (valid) {
        out->screen_identity = (uint64_t)(uintptr_t)current.object;
        out->capabilities = VBC_LOCALE_CAN_OBSERVE;
    } else {
        for (unsigned i = 0; i < sizeof(out->locale); ++i) out->locale[i] = 0;
    }
    release(current.owner);
    return valid ? VBC_LOCALE_OK : VBC_LOCALE_READBACK_FAILED;
}
}
extern "C" const VbcLocaleHostV1 *vbc_locale_host_v1() {
    static const VbcLocaleHostV1 api = {VBC_LOCALE_HOST_ABI_V1, sizeof(VbcLocaleHostV1), observe, prepare};
    return &api;
}
