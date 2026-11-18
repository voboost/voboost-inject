#include "ui_root.h"
#include <cassert>
#include <cstring>
namespace {
int screen_object,root_object,screen_owner,root_owner;
unsigned screen_refs,root_refs,releases;
bool screen_present=true,root_present=true,is_attached=true,root_method=true;
VbcUiSharedNode screen() {
    if(!screen_present) {
        return {};
    }
    ++screen_refs; return {&screen_object,&screen_owner};
}
VbcUiSharedNode root(const void *p) {
    assert(p==&screen_object&&screen_refs==1); if(!root_present) {
        return {};
    }
    ++root_refs; return {&root_object,&root_owner};
}
bool attached(const void *p) {
    assert(p==&root_object&&screen_refs==1&&root_refs==1); return is_attached;
}
void release(void *p) {
    ++releases; if(p==&screen_owner) {
        assert(root_refs==0&&screen_refs==1); --screen_refs;
    }else {
        assert(p==&root_owner&&root_refs==1&&screen_refs==1); --root_refs;
    }
}
void *resolve(const char *,const char *name) {
    if(!std::strcmp(name,"_Z20getApplicationScreenv")) {
        return (void *)screen;
    }
    if(!std::strcmp(name,"_ZNK5kanzi6Screen7getRootEv")) {
        return root_method?(void *)root:nullptr;
    }
    if(!std::strcmp(name,"_ZNK5kanzi4Node10isAttachedEv")) {
        return (void *)attached;
    }
    if(!std::strcmp(name,"_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv")) {
        return (void *)release;
    }
    assert(false&&"readiness must not depend on a gauge-named node"); return nullptr;
}
void balanced() {
    assert(screen_refs==0&&root_refs==0);
}
}
int main() {
    VbcUiRoot probe{};
    assert(probe.ready(resolve)); assert(releases==2); balanced();
    root_present=false; assert(!probe.ready(resolve)); assert(releases==3); balanced();
    root_present=true; is_attached=false; assert(!probe.ready(resolve)); assert(releases==5); balanced();
    screen_present=false; assert(!probe.ready(resolve)); assert(releases==5); balanced();
    screen_present=true; is_attached=true; root_method=false; VbcUiRoot late{};
    assert(!late.ready(resolve)); assert(releases==5); balanced();
    root_method=true; assert(late.ready(resolve)); assert(releases==7); balanced();
}
