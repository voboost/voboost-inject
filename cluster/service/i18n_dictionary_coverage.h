#ifndef VBC_I18N_DICTIONARY_COVERAGE_H
#define VBC_I18N_DICTIONARY_COVERAGE_H
#include <stddef.h>
#include <stdint.h>
/* Captured successful OEM add calls, not a filesystem translation ledger.
 * A missing, truncated or unsupported entry cannot produce a positive receipt. */
class VbcDictionaryCoverage {
public:
 struct Receipt {uint32_t english, russian, matched;};
 constexpr VbcDictionaryCoverage():entries{},buckets{},used(0),exhausted(false) {}
 void reset();
 bool record(uintptr_t dictionary,const char *key,size_t key_size,const char *value,size_t value_size);
 void removed(uintptr_t dictionary);
 bool complete(uintptr_t english,uintptr_t russian,Receipt *out) const;
private:
 struct Signature {uint8_t count;uint8_t positions[16],types[16];};
 struct Entry {uintptr_t dictionary;char key[96];Signature format;uint8_t valid,nonempty,han,cyrillic;};
 Entry entries[4096];
 uint16_t buckets[8192];
 uint16_t used;
 static size_t bucket(uintptr_t,const char *,size_t);
 bool exhausted;
 static bool signature(const char *,size_t,Signature &);
 static bool characters(const char *,size_t,bool &,bool &);
};
#endif
