#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <unistd.h>

static constexpr size_t BOOTSTRAP_WORKER_FRAME_SIZE = 160;
struct BootstrapWorkerBinding {
    uint32_t pid = 0;
    uint64_t starttime = 0;
    std::array<uint8_t, 16> nonce{};
    std::array<char, 64> generation{};
    std::array<char, 64> catalog{};
    bool operator==(const BootstrapWorkerBinding &other) const {
        return pid == other.pid && starttime == other.starttime && nonce == other.nonce
               && generation == other.generation && catalog == other.catalog;
    }
};
inline bool bootstrap_worker_binding_valid(const BootstrapWorkerBinding &binding) {
    if (!binding.pid || binding.pid > INT32_MAX || !binding.starttime) {
        return false;
    }
    bool nonce_present = false;
    for (uint8_t byte : binding.nonce) {
        nonce_present |= byte != 0;
    }
    if (!nonce_present) {
        return false;
    }
    for (const auto *hash : {&binding.generation, &binding.catalog}) {
        for (char c : *hash) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
    }
    return true;
}
inline bool bootstrap_worker_decode(const uint8_t *bytes, size_t length, const char magic[4],
                                    BootstrapWorkerBinding *out) {
    if (!bytes || !out || length != BOOTSTRAP_WORKER_FRAME_SIZE || memcmp(bytes, magic, 4)) {
        return false;
    }
    BootstrapWorkerBinding binding;
    for (size_t i = 0; i < 4; ++i) {
        binding.pid |= uint32_t(bytes[4 + i]) << (i * 8);
    }
    for (size_t i = 0; i < 8; ++i) {
        binding.starttime |= uint64_t(bytes[8 + i]) << (i * 8);
    }
    memcpy(binding.nonce.data(), bytes + 16, 16);
    memcpy(binding.generation.data(), bytes + 32, 64);
    memcpy(binding.catalog.data(), bytes + 96, 64);
    if (!bootstrap_worker_binding_valid(binding)) {
        return false;
    }
    *out = binding;
    return true;
}
enum class BootstrapWorkerPhase {Staged, Running, Completed, Publishing, Ready, Deferred, Failed, Cancelled};
class BootstrapWorkerGate {
public:
explicit BootstrapWorkerGate(BootstrapWorkerBinding binding) : binding_(binding) {
}
bool commit(const BootstrapWorkerBinding &binding) {
    if (!(binding == binding_) || !bootstrap_worker_binding_valid(binding)) {
        cancel(); return false;
    }
    auto expected = BootstrapWorkerPhase::Staged;
    return phase_.compare_exchange_strong(expected, BootstrapWorkerPhase::Running);
}
template <typename Work> bool run(const BootstrapWorkerBinding &binding, Work work) {
    if (!commit(binding)) {
        return false;
    }
    work();
    return true;
}
void cancel() {
    auto phase = phase_.load();
    while (phase != BootstrapWorkerPhase::Ready && phase != BootstrapWorkerPhase::Deferred && phase != BootstrapWorkerPhase::Failed
           && phase != BootstrapWorkerPhase::Cancelled
           && !phase_.compare_exchange_weak(phase, BootstrapWorkerPhase::Cancelled)) {
    }
}
bool finish(bool ready) {
    auto expected = BootstrapWorkerPhase::Running;
    return phase_.compare_exchange_strong(expected, ready ? BootstrapWorkerPhase::Completed
                                                             : BootstrapWorkerPhase::Failed);
}
bool claim() {
    auto expected = BootstrapWorkerPhase::Completed;
    return phase_.compare_exchange_strong(expected, BootstrapWorkerPhase::Publishing);
}
bool publish(const BootstrapWorkerBinding &current) {
    if (!(current == binding_)) {
        cancel(); return false;
    }
    auto expected = BootstrapWorkerPhase::Publishing;
    return phase_.compare_exchange_strong(expected, BootstrapWorkerPhase::Ready);
}
bool defer() {
    auto expected = BootstrapWorkerPhase::Running;
    return phase_.compare_exchange_strong(expected, BootstrapWorkerPhase::Deferred);
}
BootstrapWorkerPhase phase() const {
    return phase_.load();
}
const BootstrapWorkerBinding &binding() const {
    return binding_;
}
private:
const BootstrapWorkerBinding binding_;
std::atomic<BootstrapWorkerPhase> phase_{BootstrapWorkerPhase::Staged};
};

class BootstrapWorkerChannels {
public:
int completion_fd;
int commit_fd;
BootstrapWorkerChannels(int completion, int commit)
    : completion_fd(completion), commit_fd(commit) {
}
BootstrapWorkerChannels(const BootstrapWorkerChannels &) = delete;
BootstrapWorkerChannels &operator=(const BootstrapWorkerChannels &) = delete;
~BootstrapWorkerChannels() {
    close_all();
}
void close_commit() {
    if (commit_fd >= 0) {
        close(commit_fd); commit_fd = -1;
    }
}
void close_all() {
    close_commit();
    if (completion_fd >= 0) {
        close(completion_fd); completion_fd = -1;
    }
}
};
