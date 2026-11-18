#include "voboost_locale_object_host_v1.h"
extern "C" const VbcLocaleObjectHostV1 *vbc_locale_object_host_v1();
#include "voboost_stock_locale_host_v2.h"
#include "i18n_resource_origin.h"
#include "i18n_dictionary_coverage.h"
extern "C" void *vbc_host_resolve(const char *,const char *);
extern "C" int vbc_host_ui_ready(void);
extern "C" int vbc_locale_prepare_identity(uint32_t);
extern "C" int vbc_locale_owner_identity(uint32_t);
extern "C" uint32_t vbc_locale_current_owner(void);
extern "C" int vbc_i18n_exception_provider_ready(void);
namespace {
struct View {const char *data;size_t size;};
struct Shared {void *object,*owner;~Shared(){}};
struct BorrowedShared {void *object,*owner;};
using Screen=Shared (*)();using Release=void (*)(void *);
using Manager=void *(*)(const void *);using Acquire=Shared (*)(void *,View);
using Root=Shared (*)(void *);using Find=Shared (*)(const void *,View);
using Loaded=bool (*)(const void *);using Cast=void *(*)(const void *,const void *,const void *,ptrdiff_t);
using Final=const void *(*)(const void *,void *);using CStr=const char *(*)(const void *);
using Size=size_t (*)(const void *);using Cursor=const void *(*)(const void *);
static Screen screen;static Release release;static Manager manager;
static Acquire acquire;static Root root;static Find find;static Loaded loaded;
static Cast cast;static Final final_value;static CStr cstr;static Size string_size;static Cursor begin_urls,end_urls;
static const void *resource_type,*dictionary_type,*selector_type;static void **selected_property;
static bool initialized;
static uint64_t project_epoch,previous_screen,previous_directory,previous_manager;
static VbcDictionaryCoverage verifier;
struct Pin {void *owner;~Pin(){if(owner)release(owner);}};
struct ResourcePins {Shared values[3]={};~ResourcePins(){for(auto &r:values)if(r.owner)release(r.owner);}};
static void clear(VbcStockLocaleSnapshotV2 &out){out={};out.size=sizeof(out);}
static VbcLocaleResultV1 prepare(VbcLocaleOwnerV1 owner) {
 if(owner<VBC_LOCALE_GAUGE||owner>VBC_LOCALE_LIGHT)return VBC_LOCALE_UNSUPPORTED;
 int admission=vbc_locale_prepare_identity(owner);
 if(admission==0)return VBC_LOCALE_UNSUPPORTED;
 if(initialized)return admission==1?VBC_LOCALE_OK:VBC_LOCALE_WAITING_IDENTITY;
 const char *ui="/lib64/libkzcoreui.so",*gnu="/usr/lib64/libstdc++.so.6";
 screen=(Screen)vbc_host_resolve(nullptr,"_Z20getApplicationScreenv");
 release=(Release)vbc_host_resolve(nullptr,"_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv");
 manager=(Manager)vbc_host_resolve(ui,"_ZNK5kanzi6Object18getResourceManagerEv");
 acquire=(Acquire)vbc_host_resolve(ui,"_ZN5kanzi15ResourceManager18tryAcquireResourceEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
 root=(Root)vbc_host_resolve(ui,"_ZN5kanzi4Node25acquireResourceDictionaryEv");
 find=(Find)vbc_host_resolve(ui,"_ZNK5kanzi18ResourceDictionary14findDictionaryEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
 loaded=(Loaded)vbc_host_resolve(ui,"_ZNK5kanzi8Resource8isLoadedEv");
 cast=(Cast)vbc_host_resolve(nullptr,"__dynamic_cast");
 final_value=(Final)vbc_host_resolve("/lib64/libkzcore.so","_ZNK5kanzi14PropertyObject19getFinalValueSourceERNS_30AbstractPropertyTypeDescriptorE");
 cstr=(CStr)vbc_host_resolve(gnu,"_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv");
 string_size=(Size)vbc_host_resolve(gnu,"_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv");
 begin_urls=(Cursor)vbc_host_resolve(ui,"_ZNK5kanzi18ResourceDictionary9beginUrlsB5cxx11Ev");
 end_urls=(Cursor)vbc_host_resolve(ui,"_ZNK5kanzi18ResourceDictionary7endUrlsB5cxx11Ev");
 resource_type=vbc_host_resolve(ui,"_ZTIN5kanzi8ResourceE");dictionary_type=vbc_host_resolve(ui,"_ZTIN5kanzi18ResourceDictionaryE");
 selector_type=vbc_host_resolve(ui,"_ZTIN5kanzi26ResourceDictionarySelectorE");
 selected_property=(void **)vbc_host_resolve(ui,"_ZN5kanzi26ResourceDictionarySelector26SelectedDictionaryPropertyE");
 initialized=screen&&release&&manager&&acquire&&root&&find&&loaded&&cast&&final_value&&cstr&&string_size&&begin_urls&&end_urls&&resource_type&&dictionary_type&&selector_type&&selected_property&&*selected_property;
 return !initialized?VBC_LOCALE_UNSUPPORTED:admission==1?VBC_LOCALE_OK:VBC_LOCALE_WAITING_IDENTITY;
}
static bool scan(void *dictionary) {
 const void *node=begin_urls(dictionary),*end=end_urls(dictionary);if(end)return false;
 unsigned count=0;
 // Actual A9/A11 merge loops prove next@0, borrowed key string@8,
 // borrowed value string@0x38. No GNU object is constructed or copied here.
 while(node!=end) {
  if(++count>4096 || (reinterpret_cast<uintptr_t>(node)&7))return false;
  const void *key_object=(const unsigned char *)node+8,*value_object=(const unsigned char *)node+0x38;
  const char *key=cstr(key_object),*value=cstr(value_object);
  size_t kn=string_size(key_object),vn=string_size(value_object);
  if(!verifier.record(reinterpret_cast<uintptr_t>(dictionary),key,kn,value,vn))return false;
  const void *next=*static_cast<const void *const *>(node);if(next==node)return false;node=next;
 }
 return count!=0;
}
static bool coverage_for(uint64_t revision,void *english,void *russian,VbcDictionaryCoverage::Receipt &receipt) {
 (void)revision;
 auto en=reinterpret_cast<uintptr_t>(english),ru=reinterpret_cast<uintptr_t>(russian);
 verifier.reset();return scan(english)&&scan(russian)&&verifier.complete(en,ru,&receipt);
}
static VbcLocaleResultV1 observe(VbcStockLocaleSnapshotV2 *out) {
 if(!out || out->size<sizeof(*out))return VBC_LOCALE_UNSUPPORTED;clear(*out);
 uint32_t owner=vbc_locale_current_owner();
 int admission=owner?vbc_locale_owner_identity(owner):-1;
 if(admission!=1)return admission==0?VBC_LOCALE_UNSUPPORTED:VBC_LOCALE_WAITING_IDENTITY;
 if(vbc_i18n_exception_provider_ready()!=1)return VBC_LOCALE_WAITING_IDENTITY;
 if(!initialized)return VBC_LOCALE_UNSUPPORTED;if(!vbc_locale_object_host_v1()->ui_ready())return VBC_LOCALE_WAITING_UI;
 try {
  Shared current=screen();Pin screen_pin{current.owner};if(!current.object || !current.owner)return VBC_LOCALE_WAITING_UI;
  void *rm=manager(current.object);if(!rm)return VBC_LOCALE_READBACK_FAILED;
  Shared dictionaries=root(current.object);Pin root_pin{dictionaries.owner};if(!dictionaries.object || !dictionaries.owner)return VBC_LOCALE_READBACK_FAILED;
  Shared locales=find(dictionaries.object,{"Locales",7});Pin locales_pin{locales.owner};if(!locales.object || !locales.owner)return VBC_LOCALE_READBACK_FAILED;
  void *selector=cast(locales.object,dictionary_type,selector_type,0);if(!selector)return VBC_LOCALE_UNSUPPORTED;
  auto objects=vbc_locale_object_host_v1();
  void *object=objects->property_object(VBC_LOCALE_DICTIONARY_SELECTOR_OBJECT,selector);
  const void *property=objects->property_descriptor(VBC_LOCALE_DICTIONARY_SELECTOR_OBJECT);
  if(!object||!property)return VBC_LOCALE_READBACK_FAILED;
  auto selected=(const BorrowedShared *)final_value(object,*static_cast<void *const *>(property));

  if(!selected || !selected->object || !selected->owner)return VBC_LOCALE_READBACK_FAILED;
  void *selected_dictionary=cast(selected->object,resource_type,dictionary_type,0);if(!selected_dictionary)return VBC_LOCALE_READBACK_FAILED;
  bool found=false;VbcStockLocaleSnapshotV2 result={};result.size=sizeof(result);
  for(unsigned index=0;index<8;++index) {
   VbcLoadedOrigin origin;if(!vbc_i18n_resource_origin_at(reinterpret_cast<uintptr_t>(rm),index,&origin) || (origin.kind!=1 && origin.kind!=2))continue;
   ResourcePins pins;auto &resources=pins.values;void *types[3]={};bool valid=true,active=false;
   for(unsigned i=0;i<3;++i) {
    size_t n=0;while(n<sizeof(origin.bindings[i].uri) && origin.bindings[i].uri[n])++n;
    if(!n || n>=sizeof(origin.bindings[i].uri)){valid=false;break;}
    resources[i]=acquire(rm,{origin.bindings[i].uri,n});
    if(!resources[i].object || !resources[i].owner || !loaded(resources[i].object)){valid=false;break;}
    types[i]=cast(resources[i].object,resource_type,dictionary_type,0);
    auto captured=origin.kind==2?types[i]:resources[i].object;
    if(!types[i] || reinterpret_cast<uintptr_t>(captured)!=origin.bindings[i].resource){valid=false;break;}
    active|=types[i]==selected_dictionary;
   }
   if(valid && active) {
    VbcDictionaryCoverage::Receipt measured={};VbcLoadedOrigin fresh;
    if(coverage_for(origin.epoch,types[0],types[2],measured) && vbc_i18n_resource_origin(origin.manager,origin.directory,&fresh) && fresh.epoch==origin.epoch) {
     if(found)return VBC_LOCALE_UNSUPPORTED;
     found=true;result.owner=owner;result.origin_kind=origin.kind;result.resource_epoch=origin.epoch;
     result.screen_identity=reinterpret_cast<uintptr_t>(current.object);result.manager_identity=origin.manager;result.directory_identity=origin.directory;
     result.english_entries=measured.english;result.russian_entries=measured.russian;result.matched_entries=measured.matched;
     for(unsigned i=0;i<3;++i) {result.dictionary_identity[i]=reinterpret_cast<uintptr_t>(types[i]);for(unsigned n=0;n<256;++n)result.dictionary_uri[i][n]=origin.bindings[i].uri[n];}
    }
   }
  }
  if(!found)return VBC_LOCALE_READBACK_FAILED;
  if(result.screen_identity!=previous_screen || result.manager_identity!=previous_manager || result.directory_identity!=previous_directory) {
   if(project_epoch==UINT64_MAX)return VBC_LOCALE_UNSUPPORTED;++project_epoch;
   previous_screen=result.screen_identity;previous_manager=result.manager_identity;previous_directory=result.directory_identity;
  }
  result.project_epoch=project_epoch;*out=result;return VBC_LOCALE_OK;
 } catch(...) {clear(*out);return VBC_LOCALE_READBACK_FAILED;}
}
}
extern "C" const VbcStockLocaleHostV2 *vbc_stock_locale_host_v2() {
 static const VbcStockLocaleHostV2 api={VBC_STOCK_LOCALE_HOST_ABI_V2,sizeof(api),prepare,observe};return &api;
}
