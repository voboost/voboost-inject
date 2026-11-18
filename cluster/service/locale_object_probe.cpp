/* Structural GNU RTTI/property admission, without executable/firmware hashes.
 * Scalar-only calls into the actual loaded GNU implementation. */
#include "voboost_locale_object_host_v1.h"
#include <stddef.h>
extern "C" void *vbc_host_resolve(const char *,const char *);
extern "C" int vbc_host_ui_frame(void);
extern "C" int vbc_i18n_exception_provider_ready(void);
extern "C" int vbc_locale_owner_identity(uint32_t);
extern "C" int vbc_locale_prepare_current(void);
extern "C" uint32_t vbc_locale_current_owner(void);
namespace {
struct View {const char *data;size_t size;};
struct Shared {void *object,*owner;~Shared(){}};
using Screen=Shared(*)();using Release=void(*)(void *);
using Root=Shared(*)(void *);using Find=Shared(*)(const void *,View);
using Cast=void *(*)(const void *,const void *,const void *,ptrdiff_t);
using Upcast=bool(*)(const void *,const void *,void **);
using Attached=bool(*)(const void *);
struct Capabilities {
 Screen screen;Release release;Root root;Find find;Cast cast;Upcast upcast;Attached attached;
 const void *node_type;
 const void *screen_type,*selector_type,*dictionary_type,*property_type;
 const void *abstract_descriptor_type,*string_descriptor_type,*resource_descriptor_type;
 void **locale_slot,**selected_slot;void *locale_descriptor,*selected_descriptor;
 const void *type_tables[3];
};
Capabilities caps{};
struct Pin {
 Shared value; Release release; bool &fault;
 Pin(Shared p,Release r,bool &f):value(p),release(r),fault(f){}
 Pin(const Pin &)=delete; Pin &operator=(const Pin &)=delete;
 ~Pin() noexcept {if(value.owner)try{release(value.owner);}catch(...){fault=true;}}
};

bool aligned(const void *p){return p && (uintptr_t)p%alignof(void *)==0;}
bool typeinfo(const void *p,const Capabilities &c){
 if(!aligned(p))return false;
 const void *table=*static_cast<const void *const *>(p);
 for(const auto *known:c.type_tables)if(known && table==(const unsigned char *)known+2*sizeof(void *))return true;
 return false;
}
bool descriptors(const Capabilities &c){
 return c.locale_slot&&c.selected_slot&&c.locale_descriptor&&c.selected_descriptor&&
  *c.locale_slot==c.locale_descriptor&&*c.selected_slot==c.selected_descriptor;
}
int screen_ready() noexcept {
 if(vbc_i18n_exception_provider_ready()!=1||!vbc_locale_current_owner()||vbc_locale_owner_identity(vbc_locale_current_owner())!=1||!vbc_host_ui_frame())return 0;
 bool fault=false,attached=false;
 try {
  {Pin current(caps.screen(),caps.release,fault);
   if(!current.value.object||!current.value.owner)return 0;
   void *node=current.value.object;
   if(!caps.upcast(caps.screen_type,caps.node_type,&node)||!aligned(node)||
      (uintptr_t)node<(uintptr_t)current.value.object||(uintptr_t)node-(uintptr_t)current.value.object>4096)return 0;
   attached=caps.attached(node);
  }
 }catch(...){return 0;}
 return !fault&&attached?1:0;
}
const void *property_descriptor(VbcLocaleObjectKindV1 kind){
 if(vbc_i18n_exception_provider_ready()!=1||!vbc_locale_current_owner()||vbc_locale_owner_identity(vbc_locale_current_owner())!=1||!screen_ready()||!descriptors(caps))return nullptr;
 return kind==VBC_LOCALE_SCREEN_OBJECT?(const void *)caps.locale_slot:
  kind==VBC_LOCALE_DICTIONARY_SELECTOR_OBJECT?(const void *)caps.selected_slot:nullptr;
}
void *property_object(VbcLocaleObjectKindV1 kind,void *expected) noexcept {
 if(vbc_i18n_exception_provider_ready()!=1)return nullptr;
 bool fault=false;void *result=nullptr;
 try {
  if(!aligned(expected)||!property_descriptor(kind))return nullptr;
  {
   Pin current(caps.screen(),caps.release,fault);
   if(!current.value.object||!current.value.owner)return nullptr;
   void *object=nullptr;const void *type=nullptr;
   if(kind==VBC_LOCALE_SCREEN_OBJECT){
    if(current.value.object==expected){object=current.value.object;type=caps.screen_type;}
    result=object;
    if(!object||!caps.upcast(type,caps.property_type,&result))result=nullptr;
   }else if(kind==VBC_LOCALE_DICTIONARY_SELECTOR_OBJECT){
    Pin root(caps.root(current.value.object),caps.release,fault);
    if(root.value.object&&root.value.owner){
     Pin locales(caps.find(root.value.object,{"Locales",7}),caps.release,fault);
     if(locales.value.object&&locales.value.owner){
      void *selected=caps.cast(locales.value.object,caps.dictionary_type,caps.selector_type,0);
      if(selected==expected){object=selected;type=caps.selector_type;}
      result=object;
      if(!object||!caps.upcast(type,caps.property_type,&result))result=nullptr;
     }
    }
   }
   if(!aligned(result)||(uintptr_t)result<(uintptr_t)object||(uintptr_t)result-(uintptr_t)object>4096)result=nullptr;
  }
 }catch(...){return nullptr;}
 return fault?nullptr:result;
}
}
/* Called by the detached worker only after the genuine GNU provider is ready. */
extern "C" int vbc_locale_object_probe_prepare(void){
 if(vbc_i18n_exception_provider_ready()!=1)return 0;
 try {
 Capabilities c{};const char *ui="/lib64/libkzcoreui.so",*core="/lib64/libkzcore.so",*gnu="/usr/lib64/libstdc++.so.6";
 c.screen=(Screen)vbc_host_resolve(nullptr,"_Z20getApplicationScreenv");
 c.release=(Release)vbc_host_resolve(gnu,"_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv");
 c.root=(Root)vbc_host_resolve(ui,"_ZN5kanzi4Node25acquireResourceDictionaryEv");
 c.find=(Find)vbc_host_resolve(ui,"_ZNK5kanzi18ResourceDictionary14findDictionaryEN5boost17basic_string_viewIcSt11char_traitsIcEEE");
 c.cast=(Cast)vbc_host_resolve(gnu,"__dynamic_cast");
 c.upcast=(Upcast)vbc_host_resolve(gnu,"_ZNK10__cxxabiv117__class_type_info11__do_upcastEPKS0_PPv");
 c.attached=(Attached)vbc_host_resolve(ui,"_ZNK5kanzi4Node10isAttachedEv");
 c.node_type=vbc_host_resolve(ui,"_ZTIN5kanzi4NodeE");
 c.screen_type=vbc_host_resolve(ui,"_ZTIN5kanzi6ScreenE");
 c.selector_type=vbc_host_resolve(ui,"_ZTIN5kanzi26ResourceDictionarySelectorE");
 c.dictionary_type=vbc_host_resolve(ui,"_ZTIN5kanzi18ResourceDictionaryE");
 c.property_type=vbc_host_resolve(core,"_ZTIN5kanzi14PropertyObjectE");
 c.abstract_descriptor_type=vbc_host_resolve(core,"_ZTIN5kanzi30AbstractPropertyTypeDescriptorE");
 c.string_descriptor_type=vbc_host_resolve(ui,"_ZTIN5kanzi22PropertyTypeDescriptorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEE");
 c.resource_descriptor_type=vbc_host_resolve(ui,"_ZTIN5kanzi22PropertyTypeDescriptorISt10shared_ptrINS_8ResourceEEEE");
 c.type_tables[0]=vbc_host_resolve(gnu,"_ZTVN10__cxxabiv117__class_type_infoE");
 c.type_tables[1]=vbc_host_resolve(gnu,"_ZTVN10__cxxabiv120__si_class_type_infoE");
 c.type_tables[2]=vbc_host_resolve(gnu,"_ZTVN10__cxxabiv121__vmi_class_type_infoE");
 c.locale_slot=(void **)vbc_host_resolve(ui,"_ZN5kanzi4Node14LocalePropertyB5cxx11E");
 c.selected_slot=(void **)vbc_host_resolve(ui,"_ZN5kanzi26ResourceDictionarySelector26SelectedDictionaryPropertyE");
 if(!c.screen||!c.release||!c.root||!c.find||!c.cast||!c.upcast||!c.attached||!c.locale_slot||!c.selected_slot)return 0;
 for(const auto *table:c.type_tables)if(!aligned(table))return 0;
 const void *types[]={c.screen_type,c.selector_type,c.dictionary_type,c.property_type,c.abstract_descriptor_type,c.string_descriptor_type,c.resource_descriptor_type,c.node_type};
 for(const auto *type:types)if(!typeinfo(type,c))return 0;
 c.locale_descriptor=*c.locale_slot;c.selected_descriptor=*c.selected_slot;
 if(!aligned(c.locale_descriptor)||!aligned(c.selected_descriptor)||
  !c.cast(c.locale_descriptor,c.abstract_descriptor_type,c.string_descriptor_type,0)||
  !c.cast(c.selected_descriptor,c.abstract_descriptor_type,c.resource_descriptor_type,0))return 0;
 const char *symbols[]={"_ZNK5kanzi14PropertyObject19getFinalValueSourceERNS_30AbstractPropertyTypeDescriptorE",
 "_ZN5kanzi14PropertyObject11setPropertyINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS_12PropertyTypeIT_vEENSA_6Traits13ParameterTypeE"};
 if(!vbc_host_resolve(core,symbols[0])||!vbc_host_resolve(ui,symbols[1])||
  !vbc_host_resolve(gnu,"_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv"))return 0;
 caps=c;return 1;
 }catch(...){return 0;}
}
extern "C" const VbcLocaleObjectHostV1 *vbc_locale_object_host_v1(void){
 static const VbcLocaleObjectHostV1 api={1,sizeof(api),property_object,property_descriptor,vbc_locale_prepare_current,vbc_locale_current_owner,screen_ready};return &api;
}
