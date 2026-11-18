#ifndef VBC_UI_FRAME_STATE_H
#define VBC_UI_FRAME_STATE_H
/* Only the published owning thread accesses active. Other threads return
 * before that non-atomic read; owner is immutable after its release CAS. */
struct VbcUiFrameState {
    unsigned owner; bool active;
    bool owns(unsigned thread) const {
        return thread && thread == __atomic_load_n(&owner, __ATOMIC_ACQUIRE);
    }
    bool ready(unsigned thread) const {
        return owns(thread) && active;
    }
    // Only a callback delivered by the OEM dispatcher may establish this owner.
    bool enter_dispatched(unsigned thread) {
        if (!thread) {
            return false;
        }
        unsigned expected = 0;
        __atomic_compare_exchange_n(&owner, &expected, thread, false,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        if (!owns(thread) || active) {
            return false;
        }
        active = true;
        return true;
    }
    bool enter(unsigned thread) {
        if(!thread) {
            return false;
        }
        unsigned expected=0;
        __atomic_compare_exchange_n(&owner,&expected,thread,false,__ATOMIC_RELEASE,__ATOMIC_RELAXED);
        if(__atomic_load_n(&owner,__ATOMIC_ACQUIRE)!=thread) {
            return false;
        }
        active=true; return true;
    }
    void leave(unsigned thread,bool previous) {
        if(__atomic_load_n(&owner,__ATOMIC_ACQUIRE)==thread) {
            active=previous;
        }
    }
};
#endif
