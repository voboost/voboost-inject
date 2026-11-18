#include "../service/system_locale_state.h"
#include <cassert>
#include <thread>
static int ui_ready=1;
static uint64_t clock_ms=100;
extern "C" uint64_t vbc_host_clock() { return clock_ms; }
extern "C" int vbc_host_ui_ready() { return ui_ready; }
int main() {
 auto h = vbc_system_locale_host_v1(); assert(h && h->abi == 1);
 VbcSystemLocaleObservationV1 o = {sizeof(o),3,9,9,9};
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE && !o.locale && !o.revision);
 assert(!vbc_system_locale_publish(3,0,1,1, 30100));
 assert(vbc_system_locale_publish(3,1,2,1, 30100));
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_CONFIRMED && o.locale==3 && o.endpoint_identity==2);
 clock_ms=99; assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE && !o.locale); clock_ms=100;
 ui_ready=0; assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE && !o.locale); ui_ready=1;
 assert(!vbc_system_locale_publish(1,1,2,1, 30100));
 assert(!vbc_system_locale_publish(3,2,3,1, 30100));
 assert(vbc_system_locale_publish(1,2,2,1, 30100));
 vbc_system_locale_invalidate();
 assert(!vbc_system_locale_publish(1,2,2,1, 30100));
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE && !o.lifecycle_generation);
 assert(vbc_system_locale_publish(2,1,3,2, 30100));
 assert(!vbc_system_locale_publish(3,100,2,1, 30100));
 std::thread producer([] { for(unsigned i=2;i<100000;i++) vbc_system_locale_publish(i%3+1,i,3,2, 30100); });
 for(unsigned i=0;i<100000;i++) { auto result=h->observe(&o); if(result==VBC_SYSTEM_LOCALE_CONFIRMED) {
   assert(o.endpoint_identity==3 && o.lifecycle_generation==2);
   assert(o.revision==1 ? o.locale==2 : o.locale==o.revision%3+1);
 } else assert(!o.locale && !o.revision); }
 producer.join();
 clock_ms+=30001;
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE && !o.locale);
 assert(vbc_system_locale_publish(2,99999,3,2, 30100)==0); // changed same revision rejected
 assert(!vbc_system_locale_publish(99999%3+1,99999,3,2, 30100));
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_UNAVAILABLE); // duplicate cannot refresh lease
 assert(vbc_system_locale_publish(1,100000,3,2, clock_ms+30000));
 assert(h->observe(&o)==VBC_SYSTEM_LOCALE_CONFIRMED);

}
