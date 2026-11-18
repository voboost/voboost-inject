#include <stddef.h>

extern "C" void *vbc_host_resolve(const char *, const char *);

namespace {
using Callback = void (*)();

// QNX Kanzi takes GNU std::function<void()> by invisible reference on AArch64.
// The stored callback is inline, so copy and destruction need no allocator.
struct TaskData {
    Callback callback;
    void *reserved;
};

struct Task {
    TaskData data;
    bool (*manage)(TaskData *, const TaskData *, int);
    void (*invoke)(const TaskData *);
};

static_assert(sizeof(TaskData) == 16 && sizeof(Task) == 32);
static_assert(offsetof(Task, manage) == 16 && offsetof(Task, invoke) == 24);

bool manage(TaskData *destination, const TaskData *source, int operation) {
    constexpr int clone = 2;
    if (operation == clone) {
        *destination = *source;
    }
    return false;
}

void invoke(const TaskData *data) {
    data->callback();
}

void *resolve_ready(void **slot, const char *library, const char *symbol) {
    void *value = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (!value) {
        value = vbc_host_resolve(library, symbol);
        if (value) {
            void *expected = nullptr;
            if (!__atomic_compare_exchange_n(slot, &expected, value, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                value = expected;
            }
        }
    }
    return value;
}
}

extern "C" int vbc_submit_ui_task(Callback callback) noexcept {
    using GetDomain = void *(*)();
    using GetDispatcher = void *(*)(const void *);
    using Submit = void (*)(void *, Task *);
    constexpr char library[] = "/lib64/libkzcoreui.so";
    if (!callback) {
        return 0;
    }
    static void *domain_symbol, *dispatcher_symbol, *submit_symbol;
    const auto get_domain = reinterpret_cast<GetDomain>(resolve_ready(
                                                            &domain_symbol, nullptr, "_Z20getApplicationDomainv"));
    const auto get_dispatcher = reinterpret_cast<GetDispatcher>(resolve_ready(
                                                                    &dispatcher_symbol, library, "_ZNK5kanzi6Domain17getTaskDispatcherEv"));
    const auto submit = reinterpret_cast<Submit>(resolve_ready(
                                                     &submit_symbol, library, "_ZN5kanzi18TaskDispatcherBase6submitESt8functionIFvvEE"));
    if (!get_domain || !get_dispatcher || !submit) {
        return -2;
    }

    try {
        const void *domain = get_domain();
        if (!domain) {
            return -3;
        }
        void *queue = get_dispatcher(domain);
        if (!queue) {
            return -4;
        }
        Task task{{callback, nullptr}, manage, invoke};
        submit(queue, &task);
        return 1;
    } catch (...) {
        return -1;
    }
}
