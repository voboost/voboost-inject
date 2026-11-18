#include "inline_hook_transaction_test.inc"
#include "utils/hook_helper.hpp"

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <thread>

using namespace lsplant;

using addr_t = uintptr_t;
#define PUBLIC
#define __FUNC_CALL_TRACE__() ((void)0)
#define DEBUG_LOG(...) ((void)0)
#define ERROR_LOG(...) ((void)0)
namespace features::apple {
template <class T> void arm64e_pac_strip(T &) {
}
template <class T> void arm64e_pac_strip_and_sign(T &) {
}
}
namespace features::android { inline void make_memory_readable(void *, int) {
                              }
}
static bool prepare_failed = false;
static int activation_count = 0;
static void *relocated_original = nullptr;
static std::function<void()> activate;
struct Block { addr_t addr() const {
                   return reinterpret_cast<addr_t>(relocated_original);
               }
};
struct Interceptor {
    struct Entry {
        explicit Entry(addr_t) {
        }
        addr_t fake_func_addr = 0;
        void *routing = nullptr;
        Block relocated;
    };
    Entry *installed = nullptr;
    Entry *find(addr_t) {
        return installed;
    }
    void add(Entry *entry) {
        installed = entry;
    }
};
static Interceptor gInterceptor;
struct InlineHookRouting {
    InlineHookRouting(Interceptor::Entry *, addr_t) {
    }
    int error = 0;
    void BuildRouting() {
        error = prepare_failed ? 1 : 0;
    }
    void Active() {
        ++activation_count; if (activate) {
            activate();
        }
    }
};
#include "dobby_inline_hook_test.inc"


static std::shared_mutex mutator;
static int sections = 0;
static int suspensions = 0;
static bool suspended = false;
static void (*on_resume)() noexcept = nullptr;

struct Section {
    Section(int *, int, int) {
        ++sections;
    }
    ~Section() {
        --sections;
    }
};

struct Suspend {
    Suspend(const char *, bool) {
        assert(sections == 1 && !suspended);
        mutator.lock();
        suspended = true;
        ++suspensions;
    }
    ~Suspend() {
        assert(suspended && sections == 1);
        if (on_resume) {
            on_resume();
        }
        suspended = false;
        mutator.unlock();
    }
};

static bool transaction(const std::function<bool()> &action) {
    return voboost_inline_publication::Install<Section, Suspend>(
        static_cast<int *>(nullptr), 0, 0, action);
}

static int original(int value) {
    return value + 17;
}

static constexpr auto hooker = "publication-race"_sym.hook->*[]<Backup auto backup>
                               (int value) static->int { return backup(value); };
static constexpr auto rejected = "publication-rejected"_sym.hook->*[]<Backup auto backup>
                                 (int value) static->int { return backup(value); };

struct Target { int offset; };
static int member_original(Target *self, int value) {
    return value + self->offset;
}
static constexpr auto member_backup = "publication-member"_sym.as<int (Target::*)(int)>;

int main(void) try {
    InitInfo info{};
    int calls = 0;
    std::thread caller;
    std::mutex rendezvous;
    std::condition_variable attempted_cv;
    bool attempted = false;
    std::atomic<bool> completed{false};
    std::atomic<bool> blocked{false};
    info.art_symbol_resolver = [](std::string_view) {
                                   assert(!suspended);
                                   return reinterpret_cast<void *>(original);
                               };
    info.inline_hooker = [&](void *address, void *replacement) -> void * {
                             assert(suspended && !static_cast<bool>(hooker));
                             ++calls;
                             activate = [&, replacement] {
                                            caller = std::thread([&, replacement] {
                bool acquired = mutator.try_lock_shared();
                blocked = !acquired;
                if (acquired) {
                    mutator.unlock_shared();
                }
                {
                    std::lock_guard lock(rendezvous);
                    attempted = true;
                }
                attempted_cv.notify_one();
                std::shared_lock access(mutator);
                assert(static_cast<bool>(hooker));
                assert(reinterpret_cast<int (*)(int)>(replacement)(25) == 42);
                completed = true;
            });
                                            std::unique_lock lock(rendezvous);
                                            attempted_cv.wait(lock, [&] {
                return attempted;
            });
                                            assert(blocked && !completed);
                                        };
                             relocated_original = reinterpret_cast<void *>(original);
                             void *origin = nullptr;
                             assert(DobbyHook(address, replacement, &origin) == 0);
                             return origin;
                         };
    on_resume = []() noexcept {
                    assert(static_cast<bool>(hooker));
                };
    assert(HookHandler(info, transaction)(hooker));
    caller.join();
    assert(completed && blocked && sections == 0 && !suspended);
    assert(HookHandler(info, transaction)(hooker) && calls == 1 && suspensions == 1);

    on_resume = nullptr;
    activate = {};
    void *unused_origin = nullptr;
    assert(DobbyHook(reinterpret_cast<void *>(original), reinterpret_cast<void *>(original),
                     &unused_origin) == -1 && activation_count == 1);
    gInterceptor.installed = nullptr;
    prepare_failed = true;
    assert(DobbyHook(reinterpret_cast<void *>(original), reinterpret_cast<void *>(original),
                     &unused_origin) == -1 && activation_count == 1 && !unused_origin);
    prepare_failed = false;
    assert(DobbyHook(nullptr, reinterpret_cast<void *>(original), &unused_origin) == -1);
    relocated_original = reinterpret_cast<void *>(0x1001);
    assert(DobbyHook(reinterpret_cast<void *>(original), reinterpret_cast<void *>(original),
                     &unused_origin) == 0 && unused_origin == reinterpret_cast<void *>(0x1001));
    // A resolver-only handler cannot accidentally activate a hook.
    assert(!HookHandler(info)(rejected) && calls == 1);
    info.art_symbol_resolver = [](std::string_view) -> void * {
                                   return nullptr;
                               };
    assert(!HookHandler(info, transaction)(rejected) && calls == 1 && suspensions == 1);
    info.art_symbol_resolver = [](std::string_view) {
                                   return reinterpret_cast<void *>(original);
                               };
    info.inline_hooker = [&](void *, void *) -> void * {
                             assert(suspended);
                             ++calls;
                             return nullptr;
                         };
    assert(!HookHandler(info, transaction)(rejected));
    assert(!static_cast<bool>(rejected) && sections == 0 && !suspended && suspensions == 2);

    info.inline_hooker = [](void *, void *) {
                             return reinterpret_cast<void *>(member_original);
                         };
    on_resume = []() noexcept {
                    assert(static_cast<bool>(member_backup));
                };
    assert(transaction([] {
        member_backup = reinterpret_cast<void *>(member_original);
        return static_cast<bool>(member_backup);
    }));
    Target target{17};
    assert(member_backup(&target, 25) == 42);
    constexpr auto thumb = "publication-thumb"_sym.as<void()>;
    thumb = reinterpret_cast<void *>(0x1001);
    assert(reinterpret_cast<void *>(&thumb) == reinterpret_cast<void *>(0x1001));

    on_resume = nullptr;
    info.inline_unhooker = [](void *) {
                               assert(suspended); return false;
                           };
    assert(!HookHandler(info, transaction).unhook(hooker) && static_cast<bool>(hooker));
    info.inline_unhooker = [](void *) {
                               assert(suspended); return true;
                           };
    assert(HookHandler(info, transaction).unhook(hooker) && !static_cast<bool>(hooker));
    assert(sections == 0 && !suspended);
    return 0;
}
catch (...) {
    return 1;
}

