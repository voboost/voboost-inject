#include <cassert>
#include <cstring>
#include "../service/ui_dispatch.cpp"
#include "ui_frame_state.h"

namespace {
bool symbols_ready, domain_ready;
int domain, delivered;
Task pending{};
VbcUiFrameState state{};
void *get_domain() {
    return domain_ready ? &domain : nullptr;
}
void *get_dispatcher(const void *value) {
    assert(value == &domain);
    return &domain;
}
void submit(void *queue, Task *task) {
    assert(queue == &domain);
    task->manage(&pending.data, &task->data, 2);
    pending.manage = task->manage;
    pending.invoke = task->invoke;
}
void callback() {
    assert(state.enter_dispatched(42));
    ++delivered;
    state.leave(42, false);
}
}
extern "C" void *vbc_host_resolve(const char *, const char *symbol) {
    if (!symbols_ready) {
        return nullptr;
    }
    if (!std::strcmp(symbol, "_Z20getApplicationDomainv")) {
        return (void *)get_domain;
    }
    if (!std::strcmp(symbol, "_ZNK5kanzi6Domain17getTaskDispatcherEv")) {
        return (void *)get_dispatcher;
    }
    if (!std::strcmp(symbol, "_ZN5kanzi18TaskDispatcherBase6submitESt8functionIFvvEE")) {
        return (void *)submit;
    }
    return nullptr;
}
int main() {
    assert(vbc_submit_ui_task(nullptr) == 0);
    assert(vbc_submit_ui_task(callback) == -2);
    symbols_ready = true;
    assert(vbc_submit_ui_task(callback) == -3);
    domain_ready = true;
    assert(vbc_submit_ui_task(callback) == 1);
    assert(delivered == 0);
    assert(!state.ready(42));
    pending.invoke(&pending.data);
    assert(delivered == 1);
    assert(vbc_submit_ui_task(callback) == 1);
    pending.invoke(&pending.data);
    assert(delivered == 2);
}
