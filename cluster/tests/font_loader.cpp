#include "voboost_font_loader_v1.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>
extern "C" const VbcFontLoaderV1 *vbc_font_loader_v1();
extern "C" int vbc_locale_owner_identity(uint32_t) { return 0; }
extern "C" int vbc_locale_prepare_identity(uint32_t) { return 0; }
extern "C" int FT_New_Memory_Face(void *, const unsigned char *, long, long, void **);
static std::atomic<unsigned> calls{0};
static std::atomic<bool> entered{false}, release_callback{false}, removed{false};
static unsigned char corrected[4] = {4, 3, 2, 1};
static const unsigned char *last;
static int loader_result=71;
static std::atomic<bool> result_entered{false}, release_result{false};
static unsigned completions;
static int observed_result;
static uint32_t observed_face;
static int original(void *, const unsigned char *bytes, long size, long, void **face) {
    if (loader_result==0 && face) *face=(void *)1;
    assert(size == 4); last = bytes; ++calls; return loader_result;
}
extern "C" void *vbc_test_open(const char *, int) {
    return (void *)1;
}
extern "C" void *vbc_test_symbol(void *, const char *name) {
    return std::strcmp(name, "FT_New_Memory_Face") == 0 ? (void *)original : nullptr;
}
extern "C" int vbc_controller_start(const char *) {
    return 0;
}
extern "C" void vbc_controller_font_loaded(const unsigned char *,size_t,
    const unsigned char *,size_t,int,uint32_t) {}
extern "C" void vbc_controller_frame() {
}
extern "C" int vbc_vehicle_drive_pedestrian_warning_hide_icon() {
    return 0;
}
extern "C" int vbc_controller_data(void *, void *, void *, unsigned) {
    return 0;
}
static const unsigned char *transform(void *, const unsigned char *, size_t size, size_t *out) {
    assert(size == 4); entered = true;
    while (!release_callback) {
        std::this_thread::yield();
    }
    *out = 4; return corrected;
}
static void completed(void *,const unsigned char *source,size_t source_size,
                      const unsigned char *output,size_t output_size,int result,uint32_t face) {
    assert(source_size==4 && output_size==4 && source!=output && output==corrected);
    observed_result=result;observed_face=face;++completions;result_entered=true;
    while(!release_result) std::this_thread::yield();
}
int main() {
    unsigned char input[4] = {1, 2, 3, 4};
    const auto *api = vbc_font_loader_v1();
    assert(api->abi == 1 && api->size == sizeof(*api));
    assert(api->install("font-cyrillic", transform, nullptr) == 0);
    assert(api->install("foreign", transform, nullptr) != 0);
    assert(api->remove("foreign") != 0);
    std::thread callback([&] {
                         assert(FT_New_Memory_Face(nullptr, input, 4, 0, nullptr) == 71);
        });
    while (!entered) {
        std::this_thread::yield();
    }
    std::thread stop([&] {
                     assert(api->remove("font-cyrillic") == 0); removed = true;
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!removed && calls == 0);
    release_callback = true; callback.join(); stop.join();
    assert(removed && calls == 1 && last == corrected);
    assert(FT_New_Memory_Face(nullptr, input, 4, 0, nullptr) == 71);
    assert(calls == 2 && last == input);
    assert(corrected[0] == 4);
    // Successful original faces before installation force a conservative reload.
    loader_result=0; void *face=nullptr;
    assert(FT_New_Memory_Face(nullptr,input,4,0,&face)==0 && face);
    uint64_t prior=99;
    assert(api->install_observed("font-cyrillic",transform,completed,nullptr,&prior)==0);
    assert(prior==1);
    removed=false;
    std::thread completed_load([&] { void *created=nullptr; assert(FT_New_Memory_Face(nullptr,input,4,0,&created)==0 && created); });
    while(!result_entered) std::this_thread::yield();
    std::thread drain([&] { assert(api->remove("font-cyrillic")==0); removed=true; });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!removed && completions==1 && observed_result==0 && observed_face==1);
    release_result=true; completed_load.join(); drain.join();
    assert(removed);
    assert(api->install_observed("font-cyrillic",transform,completed,nullptr,&prior)==0 && prior==2);
    loader_result=17;
    assert(FT_New_Memory_Face(nullptr,input,4,0,&face)==17);
    assert(completions==2 && observed_result==17 && observed_face==0);
    assert(api->remove("font-cyrillic")==0);
    assert(api->install_observed("font-cyrillic",transform,completed,nullptr,&prior)==0 && prior==2);
    loader_result=0;
    assert(FT_New_Memory_Face(nullptr,input,4,0,nullptr)==0);
    assert(completions==3 && observed_result==0 && observed_face==0);
    assert(api->remove("font-cyrillic")==0);
    return 0;
}
