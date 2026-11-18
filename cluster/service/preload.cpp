/* Ordinary startup-loaded extension. Original OEM calls execute exactly once. */
#include "voboost_cluster_v2.h"
#include "voboost_font_loader_v1.h"
#include "voboost_locale_host_v1.h"
#include "voboost_pw_live_host_v1.h"
#include "voboost_pw_storage_host_v1.h"
#include "voboost_pw_oem_host_v1.h"
#include "voboost_gnu_exception_host_v1.h"
#include "system_locale_state.h"
#include "ui_frame_state.h"
#include "ui_root.h"
#include "voboost_locale_object_host_v1.h"
extern "C" const VbcLocaleObjectHostV1 *vbc_locale_object_host_v1();
extern "C" const void *vbc_resource_content_proof_v1();
extern "C" const VbcLocaleHostV1 *vbc_locale_host_v1();
extern "C" void *dlopen(const char *,int);
extern "C" void *dlsym(void *,const char *);
extern "C" int dlclose(void *);
extern "C" const char *getenv(const char *);
extern "C" long write(int,const void *,size_t);
extern "C" unsigned pthread_self(void);
struct Timespec {long seconds,nanos;};
extern "C" int clock_gettime(int,Timespec *);
extern "C" int vbc_controller_start(const char *);
extern "C" int vbc_controller_pw_lease(VbcPwLiveHostV1 *);
extern "C" const VbcPwStorageHostV1 *vbc_pw_storage_host_v1(void);
extern "C" void *vbc_pw_lookup_node_shared_boost_v1(void);
extern "C" const VbcPwOemHostV1 *vbc_pw_oem_host_v1(void);
extern "C" void *vbc_gnu_exception_resume(void);
extern "C" void vbc_controller_font_loaded(const unsigned char *,size_t,
                                           const unsigned char *,size_t,int,uint32_t);
extern "C" void vbc_controller_frame(void);
extern "C" int vbc_controller_pw_pending(void);
extern "C" int vbc_submit_ui_task(void (*)());
extern "C" int vbc_controller_data(void *,void *,void *,uint32_t);
static VbcUiRoot ui_root{};
static VbcUiFrameState ui_frame{};
static unsigned char font_lock;
static const char *font_owner;
static VbcFontTransformV1 font_transform;
static void *font_user;
static VbcFontResultV1 font_result;
static uint64_t font_faces;
static unsigned font_calls, original_calls;
static bool font_removing;
static void lock_font() {
    while (__atomic_test_and_set(&font_lock, __ATOMIC_ACQUIRE)) {
    }
}
static void unlock_font() {
    __atomic_clear(&font_lock, __ATOMIC_RELEASE);
}
static bool same_text(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    while (*a && *a == *b) {
        ++a; ++b;
    }
    return *a == *b;
}
static int install_font(const char *owner, VbcFontTransformV1 transform, void *user) {
    if (!owner || !*owner || !transform) {
        return 1;
    }
    lock_font();
    if (font_transform || font_removing) {
        unlock_font(); return 1;
    }
    font_owner = owner; font_transform = transform; font_user = user;
    unlock_font(); return 0;
}
static int install_observed_font(const char *owner, VbcFontTransformV1 transform,
                                 VbcFontResultV1 result, void *user, uint64_t *prior_faces) {
    if (!owner || !*owner || !transform || !result || !prior_faces) {
        return 1;
    }
    lock_font();
    if (font_transform || font_removing) {
        unlock_font(); return 1;
    }
    *prior_faces = font_faces + original_calls;
    font_owner = owner; font_transform = transform; font_result = result; font_user = user;
    unlock_font(); return 0;
}
static int remove_font(const char *owner) {
    lock_font();
    if (font_removing || !same_text(owner, font_owner)) {
        unlock_font(); return 1;
    }
    font_removing = true;
    font_transform = nullptr;
    unlock_font();
    while (__atomic_load_n(&font_calls, __ATOMIC_ACQUIRE)) {
    }
    lock_font();
    font_result = nullptr; font_user = nullptr; font_owner = nullptr; font_removing = false;
    unlock_font(); return 0;
}
extern "C" const VbcFontLoaderV1 *vbc_font_loader_v1() {
    static const VbcFontLoaderV1 api = {1, sizeof(VbcFontLoaderV1), install_font, remove_font, install_observed_font};
    return &api;
}
extern "C" int FT_New_Memory_Face(void *library, const unsigned char *bytes, long size, long index, void **face) {
    using Original = int (*)(void *, const unsigned char *, long, long, void **);
    static Original original = nullptr;
    const unsigned char *input = bytes; size_t length = size > 0 ? (size_t)size : 0;
    lock_font();
    if (!original) {
        original = (Original)dlsym(dlopen("/lib64/libkzcoreui.so", 2), "FT_New_Memory_Face");
    }
    if (!original || (void *)original == (void *)FT_New_Memory_Face) {
        unlock_font(); return 1;
    }
    VbcFontResultV1 result_callback = font_result;
    void *result_user = font_user;
    if (font_transform && bytes && size > 0) {
        __atomic_add_fetch(&font_calls, 1, __ATOMIC_ACQ_REL);
        size_t transformed_size = length;
        const unsigned char *transformed = font_transform(font_user, bytes, length, &transformed_size);
        if (transformed && transformed_size > 0 && transformed_size <= 0x7fffffffU) {
            input = transformed; length = transformed_size;
        }
    } else {
        result_callback = nullptr;
    }
    bool admitted = font_transform && bytes && size > 0;
    ++original_calls;
    unlock_font();
    int result = original(library, input, size > 0 ? (long)length : size, index, face);
    lock_font();
    --original_calls;
    if (result == 0 && face && *face) {
        ++font_faces;
    }
    unlock_font();
    vbc_controller_font_loaded(bytes, size > 0 ? (size_t)size : 0, input, length,
                               result, result == 0 && face && *face ? 1u : 0u);
    if (result_callback) {
        result_callback(result_user, bytes, size > 0 ? (size_t)size : 0,
                        input, length, result, result == 0 && face && *face ? 1u : 0u);
    }
    if (admitted) {
        __atomic_sub_fetch(&font_calls, 1, __ATOMIC_RELEASE);
    }
    return result;
}
extern "C" int vbc_host_ui_frame();
extern "C" int vbc_vehicle_drive_pedestrian_warning_hide_icon();
extern "C" void *vbc_host_resolve(const char *path,const char *symbol) {
    if (!path && same_text(symbol,"vbc_host_ui_frame")) {
        return (void *)vbc_host_ui_frame;
    }
    if (!path && same_text(symbol, "vehicleDrivePedestrianWarningHideIcon")) {
        return (void *)vbc_vehicle_drive_pedestrian_warning_hide_icon;
    }
    if (same_text(path, VBC_GNU_EXCEPTION_HOST_PATH)) {
        return same_text(symbol, VBC_GNU_EXCEPTION_HOST_SYMBOL)
            ? vbc_gnu_exception_resume() : nullptr;
    }
    if (same_text(path, VBC_PW_LOOKUP_HOST_PATH)) {
        return same_text(symbol, VBC_PW_LOOKUP_NODE_SHARED_BOOST)
            ? vbc_pw_lookup_node_shared_boost_v1() : nullptr;
    }
    if (same_text(path, VBC_PW_STORAGE_HOST_PATH)) {
        return same_text(symbol,"host") ? (void *)vbc_pw_storage_host_v1 : nullptr;
    }
    if (same_text(path,VBC_PW_OEM_HOST_PATH)) {
        return same_text(symbol,"host") ? (void *)vbc_pw_oem_host_v1 : nullptr;
    }
    if (same_text(path, VBC_PW_LIVE_HOST_PATH)) {
        return same_text(symbol, VBC_PW_LIVE_HOST_SYMBOL)
            ? (void *)vbc_controller_pw_lease : nullptr;
    }
    if (!path && same_text(symbol, "vbc_system_locale_host_v1")) {
        return (void *)vbc_system_locale_host_v1;
    }
    if (!path && same_text(symbol, "vbc_font_loader_v1")) {
        return (void *)vbc_font_loader_v1;
    }
    if (!path && same_text(symbol, "vbc_resource_content_proof_v1")) {
        return (void *)vbc_resource_content_proof_v1;
    }
    if (!path && same_text(symbol, "vbc_locale_object_host_v1")) {
        return (void *)vbc_locale_object_host_v1;
    }
    if (!path && same_text(symbol, "vbc_locale_host_v1")) {
        return (void *)vbc_locale_host_v1;
    }
    void *library=dlopen(path,2);
    if (!library) {
        return nullptr;
    }
    void *resolved = dlsym(library,symbol);
    if (!resolved) {
        dlclose(library);
    }
    return resolved;
}
extern "C" void vbc_preload_diagnostic(unsigned,const unsigned char *,size_t);
// Diagnostic stream only. No authenticated or bootstrap stdout payloads here.
static void vbc_emit_diagnostic(unsigned error, const char *message) {
    if (!message) {
        return;
    }
    size_t length = 0;
    while (length < 512 && message[length]) {
        ++length;
    }
    vbc_preload_diagnostic(error, (const unsigned char *)message, length);
}
extern "C" void vbc_host_log(const char *message) {
    vbc_emit_diagnostic(0, message);
}
extern "C" uint64_t vbc_host_clock() {
    Timespec time;
    if(clock_gettime(2,&time)||time.seconds<0) {
        return 0;
    }
    return (uint64_t)time.seconds*1000+(uint64_t)time.nanos/1000000;
}
extern "C" int vbc_host_ui_frame() {
    return ui_frame.ready(pthread_self())?1:0;
}
extern "C" int vbc_host_ui_ready() {
    if(!vbc_host_ui_frame()) {
        return 0;
    }
    return ui_root.ready(vbc_host_resolve)?1:0;
}
__attribute__((constructor)) static void bootstrap() {
    const char *bootfile=getenv("VOBOOST_CLUSTER_BOOTFILE");
    if(bootfile&&vbc_controller_start(bootfile)) {
        vbc_emit_diagnostic(1, "VBC startup authority rejected; OEM continues");
    }
}
#define ENGINE "/lib64/libenginecore.so.0"
#define INIT "_Z13engnCore_initP22_EngineInitInfo_StructP16_Kanzi_Cb_StructP16CEngnThemeActionNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
#define UPDATE "_Z17engnCore_onupdatev"
#define DATA "_ZN13CMcudataParse14parseGaugedataEPvS0_j"
extern "C" void vbc_engine_init(void *,void *,void *,void *) __asm__ (INIT);
extern "C" void vbc_engine_update(void) __asm__ (UPDATE);
extern "C" void vbc_gauge_data(void *,void *,uint32_t) __asm__ (DATA);
extern "C" void vbc_engine_init(void *info,void *callbacks,void *action,void *name) {
    static void *original=vbc_host_resolve(ENGINE,INIT);
    if(original&&original!=(void *)vbc_engine_init) {
        ((void (*)(void *,void *,void *,void *)) original)(info,callbacks,action,name);
    }
}
extern "C" void vbc_engine_update() {
    static void *original=vbc_host_resolve(ENGINE,UPDATE);
    if(!original||original==(void *)vbc_engine_update) {
        return;
    }
    ((void (*)(void)) original)();
    unsigned current=pthread_self();
    bool previous=ui_frame.ready(current);
    if(ui_frame.enter(current)) {
        vbc_controller_frame();
        ui_frame.leave(current,previous);
    }

}
static unsigned pw_task_pending;
static void apply_pw_on_ui() {
    static unsigned wrong_owner_reported;
    __atomic_store_n(&pw_task_pending, 0, __ATOMIC_RELEASE);
    const unsigned thread = pthread_self();
    if (!vbc_controller_pw_pending()) {
        return;
    }
    if (!ui_frame.enter_dispatched(thread)) {
        if (!__atomic_exchange_n(&wrong_owner_reported, 1, __ATOMIC_ACQ_REL)) {
            vbc_emit_diagnostic(1, "Pedestrian warning UI callback differs from its established owner");
        }
        return;
    }
    __atomic_store_n(&wrong_owner_reported, 0, __ATOMIC_RELEASE);
    vbc_controller_frame();
    ui_frame.leave(thread, false);
}

extern "C" int vbc_host_schedule_pw_frame() {
    if (__atomic_exchange_n(&pw_task_pending, 1, __ATOMIC_ACQ_REL)) {
        return 1;
    }
    const int submitted = vbc_submit_ui_task(apply_pw_on_ui);
    if (submitted != 1) {
        __atomic_store_n(&pw_task_pending, 0, __ATOMIC_RELEASE);
    }
    return submitted;
}
extern "C" void vbc_gauge_data(void *input,void *output,uint32_t size) {
    static void *original=vbc_host_resolve(ENGINE,DATA);
    if(!original||original==(void *)vbc_gauge_data) {
        return;
    }
    if(!vbc_controller_data(original,input,output,size)) {
        ((void (*)(void *,void *,uint32_t)) original)(input,output,size);
    }
}
