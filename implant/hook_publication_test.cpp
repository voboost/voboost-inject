#include "lsplant_backup_publication_test.inc"

#include <cassert>
#include <stdexcept>
#include <array>
#include <string>

static void publish_before_target_activation() {
    enum Event {Publish, BackupTo, TargetActivation, PeerResume, InvokeOriginal};
    std::array<Event, 5> events{};
    size_t count = 0;
    bool published = false, backup_copied = false, target_active = false;
    int original_calls = 0;
    struct Resume {
        std::array<Event, 5> &events;
        size_t &count;
        bool &published;
        bool &backup_copied;
        bool &target_active;
        int &original_calls;
        ~Resume() noexcept {
            events[count++] = PeerResume;
            assert(published && backup_copied && target_active);
            events[count++] = InvokeOriginal;
            ++original_calls; /* callback can use genuine copied backup immediately */
        }
    };
    bool result = voboost_hook_publication::PublishThenActivate(
        [&] {
        events[count++] = Publish; published = true; return true;
    },
        [&] {
        Resume resume{events, count, published, backup_copied, target_active, original_calls};
        events[count++] = BackupTo; backup_copied = true;
        events[count++] = TargetActivation; target_active = true;
        return true;
    });
    assert(result && original_calls == 1);
    assert(count == events.size());
    assert((events == std::array<Event, 5>{Publish, BackupTo, TargetActivation, PeerResume, InvokeOriginal}));
}

static void rejected_publish_preserves_failure_without_activation() {
    bool activated = false, pending_exception = true;
    bool result = voboost_hook_publication::PublishThenActivate(
        [&] {
        return false;
    }, [&] {
        activated = true; return true;
    });
    assert(!result && !activated && pending_exception);
    try {
        voboost_hook_publication::PublishThenActivate(
            []() -> bool {
            throw std::runtime_error("publisher-failure");
        },
            [&] {
            activated = true; return true;
        });
        assert(false);
    } catch (const std::runtime_error &) {
        assert(!activated);
    }
    int publications = 0;
    result = voboost_hook_publication::PublishThenActivate(
        [&] {
        ++publications; return true;
    }, [] {
        return false;
    });
    assert(!result && publications == 1); /* activation result is not rewritten */
    try {
        voboost_hook_publication::PublishThenActivate(
            [] {
            return true;
        }, []() -> bool {
            throw std::runtime_error("activation-failure");
        });
        assert(false);
    } catch (const std::runtime_error &error) {
        assert(std::string(error.what()) == "activation-failure");
    }
}
int main() noexcept try {
    publish_before_target_activation();
    rejected_publish_preserves_failure_without_activation();
}
catch (...) {
    return 1;
}
