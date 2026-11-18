#include "i18n_loaded_origin.h"
namespace {
bool copy(char *out, const char *text, size_t n) {
    if (!text || !n || n >= 256) return false;
    for (size_t i=0;i<n;++i) if (!text[i] || static_cast<unsigned char>(text[i])<32) return false;
    for (size_t i=0;i<n;++i) out[i]=text[i];
    out[n]=0; return true;
}
bool equal(const char *a,const char *b,size_t n) {
    for(size_t i=0;i<n;++i) if(a[i]!=b[i]) return false;
    return true;
}
int locale(const char *text,size_t n) {
    if(!text || n<7 || !equal(text,"kzb://",6)) return -1;
    size_t tail=6;
    for(size_t i=6;i<n;++i) if(text[i]=='/') tail=i+1;
    const char *names[]={"english","chinese","russian"};
    const size_t lengths[]={7,7,7};
    for(int i=0;i<3;++i) if(n-tail==lengths[i] && equal(text+tail,names[i],lengths[i])) return i;
    return -1;
}
}
void VbcLoadedOrigin::invalidate() {
    manager=directory=0;kind=0;project[0]=0;source[0]=0;
    for(auto &b:bindings) { b.resource=0;b.uri[0]=0; }
    if(epoch!=UINT64_MAX) ++epoch;
}
bool VbcLoadedOrigin::opened(uintptr_t m,uintptr_t d,const char *path,size_t n) {
    invalidate();
    if(epoch==UINT64_MAX || !m || !d || !path || path[0]!='/' || !copy(source,path,n)) return false;
    manager=m;directory=d;kind=1;return true;
}
bool VbcLoadedOrigin::bound(uintptr_t m,uintptr_t d,uintptr_t resource,const char *uri,size_t n) {
    if(!m || m!=manager || !d || d!=directory || !resource || epoch==UINT64_MAX) return false;
    int index=locale(uri,n);if(index<0) return false;
    char candidate[256]; if(!copy(candidate,uri,n)) return false;
    auto &b=bindings[index];
    // Conflicting identities in one directory lifetime invalidate all receipts.
    if(b.resource && (b.resource!=resource || !equal(b.uri,candidate,n+1))) { invalidate();return false; }
    for(int i=0;i<3;++i) if(i!=index && bindings[i].resource==resource) { invalidate();return false; }
    b.resource=resource;for(size_t i=0;i<=n;++i)b.uri[i]=candidate[i];return true;
}
void VbcLoadedOrigin::removed(uintptr_t m,uintptr_t d) {
    if(m==manager && d==directory) invalidate();
}
bool VbcLoadedOrigin::complete(uintptr_t m,uintptr_t d) const {
    return m && d && m==manager && d==directory && source[0] && epoch && epoch!=UINT64_MAX &&
        bindings[0].resource && bindings[1].resource && bindings[2].resource;
}
