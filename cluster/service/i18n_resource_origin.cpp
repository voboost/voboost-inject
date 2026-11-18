#include "i18n_resource_origin.h"
extern "C" unsigned pthread_self(void);
#if defined(__APPLE__)
extern "C" void vbc_i18n_modern_dictionary_removed(uintptr_t) __attribute__((weak_import));
#else
extern "C" void vbc_i18n_modern_dictionary_removed(uintptr_t) __attribute__((weak));
#endif
extern "C" void *vbc_host_resolve(const char *,const char *);
extern "C" int vbc_host_ui_ready(void);
/* These addresses denote the actual preload exports, not the capture helpers.
 * The capture object is linked together with these exports. */
extern "C" void *vbc_origin_open_export(void *,const char *,size_t)
 __asm__("_ZN5kanzi15ResourceManager20addDirectoryFromFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_origin_bind_export(void *,const void *,const char *,size_t)
 __asm__("_ZN5kanzi8Resource6setKZBEPK18KzuBinaryDirectoryN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_origin_remove_export(void *,void *)
 __asm__("_ZN5kanzi15ResourceManager15removeDirectoryEP18KzuBinaryDirectory");

extern "C" void vbc_dictionary_add_export(void *,const void *,const char *,size_t)
 __asm__("_ZN5kanzi18ResourceDictionary3addERKNS_10ResourceIDEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_dictionary_destroy_export(void *)
 __asm__("_ZN5kanzi18ResourceDictionaryD1Ev");
namespace {
struct View { const char *data; size_t size; };
using Open=void *(*)(void *,View);
using Bind=void (*)(void *,const void *,View);
using Remove=void (*)(void *,void *);
using Name=const char *(*)(const void *);
using Directory=void *(*)(const void *,View);
static unsigned char mutex;
static void lock() {while(__atomic_test_and_set(&mutex,__ATOMIC_ACQUIRE)) {}}
static void unlock() {__atomic_clear(&mutex,__ATOMIC_RELEASE);}
static VbcLoadedOrigin origins[8];
static uint64_t capture_revision=1;
static void changed() {if(capture_revision!=UINT64_MAX)++capture_revision;}
struct Pending {
 unsigned thread; uintptr_t manager; const char *path; size_t length; VbcLoadedOrigin staged;
 Pending *previous;
 Pending(uintptr_t m,const char *p,size_t n):thread(pthread_self()),manager(m),path(p),length(n),staged(),previous(nullptr) {}
};
static Pending *pending;
struct PendingGuard {
 Pending &value;
 explicit PendingGuard(Pending &p):value(p) {
  lock();value.previous=pending;pending=&value;unlock();
 }
 ~PendingGuard() {
  lock();
  Pending **link=&pending;while(*link && *link!=&value)link=&(*link)->previous;
  if(*link)*link=value.previous;
  unlock();
 }
};
static const char *library="/lib64/libkzcoreui.so";
static const char *open_symbol="_ZN5kanzi15ResourceManager20addDirectoryFromFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE";
static const char *bind_symbol="_ZN5kanzi8Resource6setKZBEPK18KzuBinaryDirectoryN5boost17basic_string_viewIcSt11char_traitsIcEEE";
static const char *remove_symbol="_ZN5kanzi15ResourceManager15removeDirectoryEP18KzuBinaryDirectory";
static const char *name_symbol="_Z25kzuBinaryDirectoryGetNamePK18KzuBinaryDirectory";
static bool append(char *out,size_t &n,const char *text,size_t length) {
 if(!text || length>=256-n)return false;
 for(size_t i=0;i<length;++i) { if(!text[i] || (unsigned char)text[i]<32)return false;out[n++]=text[i]; }
 out[n]=0;return true;
}
}
extern "C" void *vbc_i18n_directory_from_file(void *manager,const char *data,size_t size) {
 auto original=(Open)vbc_host_resolve(library,open_symbol);
 if(!original || ((void *)original==(void *)vbc_i18n_directory_from_file || (void *)original==(void *)vbc_origin_open_export))return nullptr;
 // Exceptions propagate unchanged: no receipt is created on an OEM failure.
 Pending operation((uintptr_t)manager,data,size);PendingGuard guard(operation);
 void *directory=original(manager,{data,size});
 if(!directory)return directory;
 lock();
 VbcLoadedOrigin *slot=nullptr;
 for(auto &o:origins) if(o.manager==(uintptr_t)manager && o.directory==(uintptr_t)directory) {slot=&o;break;}
 if(!slot)for(auto &o:origins)if(!o.directory){slot=&o;break;}
 // Saturation fails closed; never evict a live resource to invent completeness.
 if(slot) {
  changed();
  slot->opened((uintptr_t)manager,(uintptr_t)directory,data,size);
  if(operation.staged.manager==(uintptr_t)manager && operation.staged.directory==(uintptr_t)directory)
   for(const auto &b:operation.staged.bindings)if(b.resource) {
    size_t n=0;while(n<sizeof(b.uri) && b.uri[n])++n;
    slot->bound(slot->manager,slot->directory,b.resource,b.uri,n);
   }
 }
 unlock();
 return directory;
}
extern "C" void vbc_i18n_resource_set_kzb(void *resource,const void *directory,const char *data,size_t size) {
 auto original=(Bind)vbc_host_resolve(library,bind_symbol);
 if(!original || ((void *)original==(void *)vbc_i18n_resource_set_kzb || (void *)original==(void *)vbc_origin_bind_export))return;
 original(resource,directory,{data,size});
 if(!resource || !directory)return;
 auto name=(Name)vbc_host_resolve(library,name_symbol);
 const char *project=name?name(directory):nullptr;
 size_t pn=0;if(project)while(pn<256 && project[pn])++pn;
 char uri[256]={};size_t n=0;
 if(!pn || pn==256 || !append(uri,n,"kzb://",6) || !append(uri,n,project,pn) ||
    !append(uri,n,"/",1) || !append(uri,n,data,size))return;
 lock();
 changed();
 for(Pending *p=pending;p;p=p->previous)if(p->thread==pthread_self()) {
  if(!p->staged.directory)p->staged.opened(p->manager,(uintptr_t)directory,p->path,p->length);
  if(p->staged.directory==(uintptr_t)directory)
   p->staged.bound(p->manager,(uintptr_t)directory,(uintptr_t)resource,uri,n);
  break;
 }
 for(auto &o:origins) if(o.directory==(uintptr_t)directory)
    o.bound(o.manager,o.directory,(uintptr_t)resource,uri,n);
 unlock();
}
extern "C" void vbc_i18n_remove_directory(void *manager,void *directory) {
 // Revoke before entering OEM code; even a throwing removal cannot leave a stale receipt.
 lock();
 changed();
 for(auto &o:origins)o.removed((uintptr_t)manager,(uintptr_t)directory);
 unlock();
 auto original=(Remove)vbc_host_resolve(library,remove_symbol);
 if(original && (void *)original!=(void *)vbc_i18n_remove_directory && (void *)original!=(void *)vbc_origin_remove_export) original(manager,directory);
}
extern "C" int vbc_i18n_resource_origin(uintptr_t manager,uintptr_t directory,VbcLoadedOrigin *out) {
 if(!out)return 0;
 *out=VbcLoadedOrigin();if(!vbc_host_ui_ready())return 0;int result=0;uint64_t revision;
 lock();
 revision=capture_revision;
 if(revision!=UINT64_MAX)for(const auto &o:origins)if(o.complete(manager,directory)){*out=o;result=1;break;}
 unlock();
 if(!result)return 0;
 // Reconfirm registration from the live manager; captured pointers alone are not liveness proof.
 bool registered=false;
 try {
  if(out->kind==1) {
   auto current=(Directory)vbc_host_resolve(library,"_ZNK5kanzi15ResourceManager12getDirectoryEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
   const char *uri=out->bindings[0].uri;size_t n=6;while(n<256 && uri[n] && uri[n]!='/')++n;
   registered=current && n>6 && n<256 && uri[n]=='/' && (uintptr_t)current((const void *)manager,{uri+6,n-6})==directory;
  } else if(out->kind==2) {
   using Kzb=void *(*)(const void *,View,size_t);
   auto current=(Kzb)vbc_host_resolve(library,"_ZNK5kanzi15ResourceManager10getKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEEm");
   size_t n=0;while(n<sizeof(out->project) && out->project[n])++n;
   if(current && n && n<sizeof(out->project))for(unsigned index=0;index<8;++index) {
    void *actual=current((const void *)manager,{out->project,n},index);if(!actual)break;
    if((uintptr_t)actual==directory){registered=true;break;}
   }
  }
 } catch(...) {registered=false;}
 if(!registered){*out=VbcLoadedOrigin();return 0;}
 lock();bool unchanged=capture_revision==revision;unlock();
 if(!unchanged){*out=VbcLoadedOrigin();return 0;}
 out->epoch=revision;return 1;
}

// Export interposition and capture in one exception-aware translation unit.
extern "C" void *vbc_origin_open_export(void *m,const char *p,size_t n) {return vbc_i18n_directory_from_file(m,p,n);}
extern "C" void vbc_origin_bind_export(void *r,const void *d,const char *p,size_t n) {vbc_i18n_resource_set_kzb(r,d,p,n);}
extern "C" void vbc_origin_remove_export(void *m,void *d) {vbc_i18n_remove_directory(m,d);}

extern "C" void vbc_dictionary_add_export(void *dictionary,const void *id,const char *value,size_t length) {
 using Add=void (*)(void *,const void *,View);
 auto original=(Add)vbc_host_resolve(library,"_ZN5kanzi18ResourceDictionary3addERKNS_10ResourceIDEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
 if(!original || (void *)original==(void *)vbc_dictionary_add_export)return;
 original(dictionary,id,{value,length});
 lock();changed();unlock();
}
extern "C" void vbc_dictionary_destroy_export(void *dictionary) {
 if(vbc_i18n_modern_dictionary_removed)vbc_i18n_modern_dictionary_removed((uintptr_t)dictionary);
 lock();changed();for(auto &o:origins)for(const auto &b:o.bindings)if(b.resource==(uintptr_t)dictionary){o.removed(o.manager,o.directory);break;}unlock();
 auto original=(void (*)(void *))vbc_host_resolve(library,"_ZN5kanzi18ResourceDictionaryD1Ev");
 if(original && (void *)original!=(void *)vbc_dictionary_destroy_export)original(dictionary);
}
extern "C" int vbc_i18n_resource_origin_at(uintptr_t manager,unsigned index,VbcLoadedOrigin *out) {
 if(!out)return 0;*out=VbcLoadedOrigin();if(index>=8 || !vbc_host_ui_ready())return 0;
 lock();uintptr_t directory=origins[index].manager==manager?origins[index].directory:0;unlock();
 return directory?vbc_i18n_resource_origin(manager,directory,out):0;
}

extern "C" void vbc_i18n_modern_forget(uintptr_t file) {
 lock();changed();for(auto &o:origins)if(o.kind==2&&o.directory==file)o.removed(o.manager,o.directory);unlock();
}
extern "C" void vbc_i18n_modern_open(uintptr_t manager,uintptr_t file,const char *path,size_t size,const char *project,size_t pn) {
 if(!project || !pn || pn>=128)return;
 for(size_t i=0;i<pn;++i)if(!project[i] || (unsigned char)project[i]<32 || project[i]=='/')return;
 lock();VbcLoadedOrigin *slot=nullptr;
 for(auto &o:origins)if(o.manager==manager && o.directory==file){slot=&o;break;}
 if(!slot)for(auto &o:origins)if(!o.directory){slot=&o;break;}
 if(slot){
  bool same=slot->kind==2&&slot->manager==manager&&slot->directory==file;
  size_t oldn=0;while(oldn<256&&slot->source[oldn])++oldn;
  same=same&&oldn==size;for(size_t i=0;same&&i<size;++i)if(slot->source[i]!=path[i])same=false;
  oldn=0;while(oldn<128&&slot->project[oldn])++oldn;same=same&&oldn==pn;
  for(size_t i=0;same&&i<pn;++i)if(slot->project[i]!=project[i])same=false;
  if(same){unlock();return;}
  changed();if(slot->opened(manager,file,path,size)){slot->kind=2;for(size_t i=0;i<pn;++i)slot->project[i]=project[i];slot->project[pn]=0;}}
 unlock();
}
extern "C" void vbc_i18n_modern_bind(uintptr_t file,uintptr_t dictionary,const char *path,size_t size) {
 lock();changed();
 for(auto &o:origins)if(o.kind==2 && o.directory==file) {
  char uri[256]={};size_t n=0;
  bool full=size>=6 && path && path[0]=='k' && path[1]=='z' && path[2]=='b' && path[3]==':' && path[4]=='/' && path[5]=='/';
  size_t pn=0;while(pn<128 && o.project[pn])++pn;
  if(full) {if(!append(uri,n,path,size))continue;}
  else if(!append(uri,n,"kzb://",6) || !append(uri,n,o.project,pn) || !append(uri,n,"/",1) || !append(uri,n,path,size))continue;
  o.bound(o.manager,o.directory,dictionary,uri,n);
 }
 unlock();
}
extern "C" void vbc_i18n_modern_remove(uintptr_t manager,const char *project,size_t size) {
 lock();changed();for(auto &o:origins)if(o.kind==2 && o.manager==manager) {
  size_t n=0;while(n<128 && o.project[n])++n;
  bool same=n==size && project;for(size_t i=0;same && i<n;++i)if(o.project[i]!=project[i])same=false;
  if(same)o.removed(o.manager,o.directory);
 }
 unlock();
}
