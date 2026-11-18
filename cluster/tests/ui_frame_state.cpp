#include "ui_frame_state.h"
#include <cassert>

int main() {
    VbcUiFrameState state{};
    assert(!state.enter_dispatched(0));
    // A callback delivered by the OEM dispatcher can precede an engine update.
    assert(state.enter_dispatched(42));
    assert(state.ready(42));
    assert(!state.enter_dispatched(42));
    assert(!state.enter_dispatched(7));
    state.leave(7, false);
    assert(state.ready(42));
    state.leave(42, false);
    assert(!state.ready(42));
    assert(state.enter_dispatched(42));
    state.leave(42, false);
    assert(!state.enter_dispatched(7));
    assert(state.enter(42));
    state.leave(42, false);
    assert(state.enter_dispatched(42));
}
