/* Genuine modern KZB provenance: actual successful calls and actual full URLs.
 * No object offsets, getter decoding, guessed project names or GNU construction.
 * See .work162/i18n-loaded-origin/MODERN-FULL-URL-ABI-PROOF.md. */
#include "i18n_resource_origin.h"
extern "C" unsigned pthread_self(void);
extern "C" void *vbc_host_resolve(const char *,const char *);
extern "C" int vbc_host_ui_ready(void);
namespace {
struct View {const char *data;size_t size;};
// A nontrivial destructor selects the observed AAPCS64 indirect-result ABI.
// It intentionally owns nothing: the original returned owner is forwarded.
struct Shared {void *object,*owner;~Shared(){}};
const char *lib="/lib64/libkzcoreui.so";
const char *add_name="_ZN5kanzi15ResourceManager10addKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE";
const char *ctor_name="_ZN5kanzi7KzbFileC1EPNS_6DomainESt10unique_ptrINS_4FileESt14default_deleteIS4_EE";
const char *load_name="_ZN5kanzi18ResourceDictionary11loadFromKZBEPNS_6DomainEN5boost17basic_string_viewIcSt11char_traitsIcEEERNS_7KzbFileERNS_18ReadOnlyMemoryFileERNS_15KzbMemoryParserE";
const char *url_name="_ZN5kanzi8Resource6setUrlEN5boost17basic_string_viewIcSt11char_traitsIcEEE";
const char *remove_name="_ZN5kanzi15ResourceManager13removeKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE";
struct Source {uintptr_t manager,file;char path[256];uint64_t revision;};
struct Binding {uintptr_t file,dictionary;char url[256];uint64_t revision;};
Source sources[8];Binding bindings[64];uint64_t revision=1;
unsigned char mutex;
void lock(){while(__atomic_test_and_set(&mutex,__ATOMIC_ACQUIRE)){}}
void unlock(){__atomic_clear(&mutex,__ATOMIC_RELEASE);}
bool copy(char *out,const char *in,size_t n){
 if(!in || !n || n>=256)return false;
 for(size_t i=0;i<n;++i){if(!in[i] || (unsigned char)in[i]<32)return false;out[i]=in[i];}out[n]=0;return true;
}
size_t length(const char *s){size_t n=0;while(n<256&&s[n])++n;return n;}
void invalidate(){for(auto &s:sources){if(s.file)vbc_i18n_modern_forget(s.file);s=Source();}for(auto &b:bindings)b=Binding();if(revision!=UINT64_MAX)++revision;}
struct Pending {unsigned thread;uintptr_t manager,file;unsigned constructors;uint64_t epoch;char path[256];bool committed;Pending *previous;};
Pending *pending;
struct Loading {unsigned thread;uintptr_t file;uint64_t epoch;Loading *previous;};
Loading *loading;
struct LoadingGuard {Loading item{};explicit LoadingGuard(uintptr_t file){
 item.thread=pthread_self();item.file=file;lock();
 for(const auto &s:sources)if(s.file==file)item.epoch=s.revision;
 for(Pending *p=pending;p;p=p->previous)if(p->thread==item.thread&&p->file==file){item.epoch=p->epoch;break;}
 item.previous=loading;loading=&item;unlock();}
 ~LoadingGuard(){lock();Loading **at=&loading;while(*at&&*at!=&item)at=&(*at)->previous;if(*at)*at=item.previous;unlock();}
};
struct Guard {Pending &p;explicit Guard(Pending &v):p(v){lock();p.previous=pending;pending=&p;unlock();}
 ~Guard(){lock();Pending **at=&pending;while(*at&&*at!=&p)at=&(*at)->previous;if(*at)*at=p.previous;if(!p.committed&&p.file)for(auto &b:bindings)if(b.file==p.file)b=Binding();unlock();}};
void publish(uintptr_t file,uintptr_t dictionary){
 // Only copied receipt values are used; OEM calls happen outside this mutex.
 Source source{};Binding bind{};
 lock();for(const auto &s:sources)if(s.file==file)source=s;
 for(const auto &b:bindings)if(b.file==file&&b.dictionary==dictionary)bind=b;unlock();
 if(!source.manager||!bind.url[0]||source.revision!=bind.revision)return;
 size_t n=length(bind.url);if(n<8||n>=256)return;
 const char *u=bind.url;if(u[0]!='k'||u[1]!='z'||u[2]!='b'||u[3]!=':'||u[4]!='/'||u[5]!='/')return;
 size_t end=6;while(end<n&&u[end]!='/')++end;
 if(end==6||end==n||end-6>=128)return;
 // Actual current source registration is checked independently by origin_at.
 vbc_i18n_modern_open(source.manager,file,source.path,length(source.path),u+6,end-6);
 vbc_i18n_modern_bind(file,dictionary,u,n);
}
void factory_receipt(uintptr_t file,uintptr_t dictionary){
 if(!file||!dictionary)return;lock();Binding *slot=nullptr;uint64_t epoch=0;
 for(const auto &s:sources)if(s.file==file)epoch=s.revision;
 // Synchronous factory can occur inside add before its successful receipt.
 for(Pending *p=pending;p;p=p->previous)if(p->thread==pthread_self()&&p->file==file){epoch=p->epoch;break;}
 if(!epoch){unlock();return;}
 for(auto &b:bindings)if(b.dictionary==dictionary){slot=&b;break;}
 if(!slot)for(auto &b:bindings)if(!b.dictionary){slot=&b;break;}
 if(!slot){invalidate();unlock();return;}
 if(slot->file&&slot->file!=file){invalidate();unlock();return;}
 if(slot->revision&&slot->revision!=epoch)*slot=Binding();
 slot->file=file;slot->dictionary=dictionary;slot->revision=epoch;unlock();publish(file,dictionary);
}
}
extern "C" void vbc_modern_add_export(void *,const char *,size_t) __asm__("_ZN5kanzi15ResourceManager10addKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_modern_ctor_export(void *,void *,void *) __asm__("_ZN5kanzi7KzbFileC1EPNS_6DomainESt10unique_ptrINS_4FileESt14default_deleteIS4_EE");
extern "C" Shared vbc_modern_load_export(void *,const char *,size_t,void *,void *,void *) __asm__("_ZN5kanzi18ResourceDictionary11loadFromKZBEPNS_6DomainEN5boost17basic_string_viewIcSt11char_traitsIcEEERNS_7KzbFileERNS_18ReadOnlyMemoryFileERNS_15KzbMemoryParserE");
extern "C" void vbc_modern_url_export(void *,const char *,size_t) __asm__("_ZN5kanzi8Resource6setUrlEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_modern_remove_export(void *,const char *,size_t) __asm__("_ZN5kanzi15ResourceManager13removeKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
extern "C" void vbc_modern_add_export(void *manager,const char *path,size_t n){
 using Fn=void(*)(void *,View);auto original=(Fn)vbc_host_resolve(lib,add_name);
 if(!original||(void *)original==(void *)vbc_modern_add_export)return;
 if(!vbc_host_ui_ready()){original(manager,{path,n});return;}
 Pending p{};p.thread=pthread_self();p.manager=(uintptr_t)manager;
 if(!copy(p.path,path,n)||path[0]!='/'){original(manager,{path,n});return;}
 lock();if(revision==UINT64_MAX){unlock();original(manager,{path,n});return;}p.epoch=++revision;unlock();
 Guard guard(p);original(manager,{path,n});
 if(p.constructors!=1||!p.file)return;
 lock();Source *slot=nullptr;for(auto &s:sources)if(s.file==p.file){slot=&s;break;}
 if(!slot)for(auto &s:sources)if(!s.file){slot=&s;break;}
 if(!slot||revision==UINT64_MAX){invalidate();unlock();return;}
 slot->manager=p.manager;slot->file=p.file;copy(slot->path,p.path,n);slot->revision=p.epoch;p.committed=true;
 uintptr_t ids[64]{};unsigned count=0;for(const auto &b:bindings)if(b.file==p.file)ids[count++]=b.dictionary;unlock();
 for(unsigned i=0;i<count;++i)publish(p.file,ids[i]);
}
extern "C" void vbc_modern_ctor_export(void *file,void *domain,void *moved_unique){
 using Fn=void(*)(void *,void *,void *);auto original=(Fn)vbc_host_resolve(lib,ctor_name);
 if(!original||(void *)original==(void *)vbc_modern_ctor_export)return;
 original(file,domain,moved_unique);if(!vbc_host_ui_ready())return;
 vbc_i18n_modern_forget((uintptr_t)file);
 lock();for(Pending *p=pending;p;p=p->previous)if(p->thread==pthread_self()){++p->constructors;p->file=(uintptr_t)file;break;}unlock();
}
extern "C" Shared vbc_modern_load_export(void *domain,const char *name,size_t n,void *file,void *memory,void *parser){
 using Fn=Shared(*)(void *,View,void *,void *,void *);auto original=(Fn)vbc_host_resolve(lib,load_name);
 if(!original||(void *)original==(void *)vbc_modern_load_export)return {};
 LoadingGuard guard((uintptr_t)file);
 Shared result=original(domain,{name,n},file,memory,parser);
 if(vbc_host_ui_ready())factory_receipt((uintptr_t)file,(uintptr_t)result.object);
 return result;
}
extern "C" void vbc_modern_url_export(void *resource,const char *url,size_t n){
 using Fn=void(*)(void *,View);auto original=(Fn)vbc_host_resolve(lib,url_name);
 if(!original||(void *)original==(void *)vbc_modern_url_export)return;
 original(resource,{url,n});if(!vbc_host_ui_ready()||!resource)return;
 using Cast=void *(*)(void *,const void *,const void *,long);
 auto cast=(Cast)vbc_host_resolve(nullptr,"__dynamic_cast");
 void *rtti=vbc_host_resolve(lib,"_ZTIN5kanzi8ResourceE"),*dict=vbc_host_resolve(lib,"_ZTIN5kanzi18ResourceDictionaryE");
 void *dictionary=cast&&rtti&&dict?cast(resource,rtti,dict,-1):nullptr;if(!dictionary)return;
 char text[256]{};if(!copy(text,url,n))return;
 lock();Binding *slot=nullptr;for(auto &b:bindings)if(b.dictionary==(uintptr_t)dictionary){slot=&b;break;}
 if(!slot)for(auto &b:bindings)if(!b.dictionary){slot=&b;break;}
 if(!slot){invalidate();unlock();return;}
 for(Loading *p=loading;p;p=p->previous)if(p->thread==pthread_self()){
  *slot=Binding();slot->revision=p->epoch;break;
 }
 slot->dictionary=(uintptr_t)dictionary;copy(slot->url,text,n);uintptr_t file=slot->file;unlock();
 if(file)publish(file,(uintptr_t)dictionary);
}
extern "C" void vbc_modern_remove_export(void *manager,const char *project,size_t n){
 using Fn=void(*)(void *,View);auto original=(Fn)vbc_host_resolve(lib,remove_name);
 if(!original||(void *)original==(void *)vbc_modern_remove_export)return;
 if(vbc_host_ui_ready()){lock();invalidate();unlock();vbc_i18n_modern_remove((uintptr_t)manager,project,n);}
 original(manager,{project,n});
}
extern "C" void vbc_i18n_modern_dictionary_removed(uintptr_t dictionary){
 lock();for(auto &b:bindings)if(b.dictionary==dictionary)b=Binding();unlock();
}
