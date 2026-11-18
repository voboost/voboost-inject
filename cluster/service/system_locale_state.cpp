#include "system_locale_state.h"
extern "C" int vbc_host_ui_ready();
extern "C" uint64_t vbc_host_clock();
namespace {
unsigned locked;
VbcSystemLocaleObservationV1 state = {sizeof(state), 0, 0, 0, 0};
bool available;
uint64_t lease_deadline, lease_started;
constexpr uint64_t LEASE_MS = 30000;
bool acquire() { unsigned expected = 0; return __atomic_compare_exchange_n(
    &locked, &expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED); }
void release() { __atomic_store_n(&locked, 0, __ATOMIC_RELEASE); }
VbcSystemLocaleResultV1 observe(VbcSystemLocaleObservationV1 *out) {
    if (!out) return VBC_SYSTEM_LOCALE_UNSUPPORTED;
    uint32_t size = out->size;
    if (size < sizeof(*out)) return VBC_SYSTEM_LOCALE_UNSUPPORTED;
    *out = {size, 0, 0, 0, 0};
    if (!vbc_host_ui_ready() || !acquire()) return VBC_SYSTEM_LOCALE_UNAVAILABLE;
    const uint64_t now = vbc_host_clock();
    bool ready = available && now && now >= lease_started && now <= lease_deadline;
    if (ready) { *out = state; out->size = size; }
    release();
    return ready ? VBC_SYSTEM_LOCALE_CONFIRMED : VBC_SYSTEM_LOCALE_UNAVAILABLE;
}
const VbcSystemLocaleHostV1 host = {VBC_SYSTEM_LOCALE_HOST_ABI_V1, sizeof(host), observe};
}
extern "C" const VbcSystemLocaleHostV1 *vbc_system_locale_host_v1() { return &host; }
extern "C" int vbc_system_locale_publish(uint32_t locale, uint64_t revision,
                                         uint64_t endpoint, uint64_t lifecycle, uint64_t deadline) {
    if (locale < VBC_SYSTEM_LOCALE_EN || locale > VBC_SYSTEM_LOCALE_RU ||
        !revision || !endpoint || !lifecycle || !acquire()) return 0;
    bool accepted = lifecycle > state.lifecycle_generation ||
        (lifecycle == state.lifecycle_generation && endpoint == state.endpoint_identity &&
         (revision > state.revision ||
          (available && revision == state.revision && locale == state.locale)));
    const uint64_t now = vbc_host_clock();
    if (!now || deadline < now || deadline - now > LEASE_MS) accepted = false;
    if (accepted) {
        // Equal signed observations are idempotent, not fresh Binder readback:
        // transport retries must never extend a lease indefinitely.
        if (!available || lifecycle != state.lifecycle_generation || revision != state.revision) {
            lease_deadline = deadline;
            lease_started = now;
        }
        state = {sizeof(state), locale, revision, endpoint, lifecycle}; available = true;
    }
    release();
    return accepted ? 1 : 0;
}
extern "C" void vbc_system_locale_invalidate() {
    /* Controller serializes invalidation against publication; readers never wait. */
    while (!acquire()) {}
    available = false;
    release();
}
