#include "i18n_dictionary_coverage.h"
namespace {
bool key_equal(const char *a,const char *b,size_t n) {for(size_t i=0;i<n;++i)if(a[i]!=b[i])return false;return a[n]==0;}
unsigned kind(char c) {
 if(c=='d'||c=='i')return 1;if(c=='u'||c=='o'||c=='x'||c=='X')return 2;
 if(c=='f'||c=='F'||c=='e'||c=='E'||c=='g'||c=='G'||c=='a'||c=='A')return 3;
 if(c=='s')return 4;if(c=='c')return 5;if(c=='p')return 6;return 0;
}
}
void VbcDictionaryCoverage::reset(){for(auto &slot:buckets)slot=0;used=0;exhausted=false;}
size_t VbcDictionaryCoverage::bucket(uintptr_t dictionary,const char *key,size_t n) {
 // Ordinary bounded key indexing, unrelated to artifact/firmware compatibility.
 uint64_t value=1469598103934665603ULL;
 for(unsigned shift=0;shift<sizeof(dictionary)*8;shift+=8){value^=(dictionary>>shift)&255;value*=1099511628211ULL;}
 for(size_t i=0;i<n;++i){value^=(unsigned char)key[i];value*=1099511628211ULL;}
 return (size_t)(value&8191);
}
bool VbcDictionaryCoverage::signature(const char *s,size_t n,Signature &out) {
 out={};unsigned next=1;
 for(size_t i=0;i<n;++i) {
  if(s[i]!='%')continue;
  if(i+1<n && s[i+1]=='%'){++i;continue;}
  size_t start=i,j=i+1;unsigned position=0;
  while(j<n && s[j]>='0' && s[j]<='9'){position=position*10+(s[j++]-'0');if(position>255)return false;}
  if(j<n && s[j]=='n')return false;
  bool explicit_position=j<n && s[j]=='$';
  if(explicit_position){++j;if(!position)return false;}
  else {
   // Qt numbered substitutions have no conversion letter.
   if(position && (j==n || (!kind(s[j]) && s[j]!='.' && s[j]!='l' && s[j]!='h' && s[j]!='L' && s[j]!='z' && s[j]!='j' && s[j]!='t'))) {
    if(position>16 || out.count==16)return false;
    out.positions[out.count]=position;out.types[out.count++]=7;i=j-1;continue;
   }
   position=next++;j=start+1;
  }
  while(j<n && (s[j]=='-'||s[j]=='+'||s[j]==' '||s[j]=='#'||s[j]=='0'))++j;
  while(j<n && s[j]>='0' && s[j]<='9')++j;
  if(j<n && s[j]=='.'){++j;while(j<n && s[j]>='0' && s[j]<='9')++j;}
  if(j<n && s[j]=='*')return false;
  unsigned length=0;
  if(j<n && s[j]=='l'){length=32;++j;if(j<n && s[j]=='l'){length=64;++j;}}
  else if(j<n && s[j]=='L'){length=96;++j;}
  else if(j<n && s[j]=='h'){++j;if(j<n && s[j]=='h')++j;}
  else if(j<n && s[j]=='z'){length=128;++j;}
  else if(j<n && s[j]=='j'){length=160;++j;}
  else if(j<n && s[j]=='t'){length=192;++j;}
  if(j<n && s[j]=='n')return false; // never accept an introduced printf write conversion
  unsigned type=j<n?kind(s[j]):0;
  if(!type){if(explicit_position)return false;continue;}
  if(position>16 || out.count==16)return false;
  out.positions[out.count]=position;out.types[out.count++]=type+length;i=j;
 }
 for(unsigned i=0;i<out.count;++i)for(unsigned j=i+1;j<out.count;++j)
  if(out.positions[j]<out.positions[i] || (out.positions[j]==out.positions[i] && out.types[j]<out.types[i])) {
   auto p=out.positions[i],t=out.types[i];out.positions[i]=out.positions[j];out.types[i]=out.types[j];out.positions[j]=p;out.types[j]=t;
  }
 return true;
}
bool VbcDictionaryCoverage::characters(const char *s,size_t n,bool &han,bool &cyrillic) {
 han=false;cyrillic=false;
 for(size_t i=0;i<n;) {
  unsigned c=(unsigned char)s[i++],value=c,remaining=0,min=0;
  if(!c)return false;
  if(c>=0xc2 && c<=0xdf){value=c&31;remaining=1;min=0x80;}
  else if(c>=0xe0 && c<=0xef){value=c&15;remaining=2;min=0x800;}
  else if(c>=0xf0 && c<=0xf4){value=c&7;remaining=3;min=0x10000;}
  else if(c>=128)return false;
  if(remaining>n-i)return false;
  for(unsigned j=0;j<remaining;++j){unsigned d=(unsigned char)s[i++];if((d&0xc0)!=0x80)return false;value=(value<<6)|(d&63);}
  if(value<min || value>0x10ffff || (value>=0xd800 && value<=0xdfff))return false;
  if((value>=0x3400 && value<=0x9fff)||(value>=0x20000 && value<=0x3134f))han=true;
  if((value>=0x400 && value<=0x52f)||(value>=0x2de0 && value<=0x2dff)||(value>=0xa640 && value<=0xa69f))cyrillic=true;
 }
 return true;
}
bool VbcDictionaryCoverage::record(uintptr_t dictionary,const char *key,size_t kn,const char *value,size_t vn) {
 if(!dictionary || !key || !kn || kn>=96 || !value || vn>16384){exhausted=true;return false;}
 for(size_t i=0;i<kn;++i)if(!key[i] || (unsigned char)key[i]<32){exhausted=true;return false;}
 Entry *entry=nullptr;size_t slot=bucket(dictionary,key,kn);
 for(unsigned probe=0;probe<8192;++probe,slot=(slot+1)&8191) {
  uint16_t index=buckets[slot];
  if(!index){if(used==4096){exhausted=true;return false;}entry=&entries[used];buckets[slot]=++used;break;}
  auto &candidate=entries[index-1];
  if(candidate.dictionary==dictionary && key_equal(candidate.key,key,kn)){entry=&candidate;break;}
 }
 if(!entry){exhausted=true;return false;}
 *entry={};entry->dictionary=dictionary;for(size_t i=0;i<kn;++i)entry->key[i]=key[i];
 bool han=false,cyr=false;entry->valid=characters(value,vn,han,cyr)&&signature(value,vn,entry->format);
 entry->nonempty=vn!=0;entry->han=han;entry->cyrillic=cyr;return entry->valid;
}
void VbcDictionaryCoverage::removed(uintptr_t dictionary) {for(unsigned i=0;i<used;++i)if(entries[i].dictionary==dictionary)entries[i]={};}
bool VbcDictionaryCoverage::complete(uintptr_t english,uintptr_t russian,Receipt *out) const {
 if(!out)return false;*out={};if(exhausted || !english || !russian || english==russian)return false;
 bool cyrillic=false;
 for(unsigned ri=0;ri<used;++ri){const auto &ru=entries[ri];if(ru.dictionary==russian){++out->russian;if(!ru.valid || ru.han)return false;cyrillic|=ru.cyrillic;}}
 for(unsigned ei=0;ei<used;++ei){const auto &en=entries[ei];if(en.dictionary!=english)continue;
  ++out->english;if(!en.valid)return false;const Entry *match=nullptr;
  size_t n=0;while(en.key[n])++n;
  size_t slot=bucket(russian,en.key,n);
  for(unsigned probe=0;probe<8192;++probe,slot=(slot+1)&8191){uint16_t index=buckets[slot];if(!index)break;const auto &ru=entries[index-1];if(ru.dictionary==russian && key_equal(ru.key,en.key,n)){match=&ru;break;}}
  if(!match || (en.nonempty && !match->nonempty) || en.format.count!=match->format.count)return false;
  for(unsigned i=0;i<en.format.count;++i)if(en.format.positions[i]!=match->format.positions[i] || en.format.types[i]!=match->format.types[i])return false;
  ++out->matched;
 }
 return out->english && cyrillic && out->matched==out->english;
}
