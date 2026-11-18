#include "include/agent_entry_seam.h"
#include "../injector/handoff_result.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#include <jni.h>
#include <cstdlib>
#include <cstdint>
#include "include/lsplant.hpp"

bool lsplant::Init(JNIEnv *, const InitInfo &) {
    std::abort();
}

bool lsplant::UnHook(JNIEnv *, jobject) {
    std::abort();
}

extern "C" jobject voboost_lsplant_hook_with_backup(
    JNIEnv *, jobject, jobject, jobject, jboolean (*)(JNIEnv *, jobject, jobject)) {
    std::abort();
}

extern "C" void voboost_lsplant_set_stage_callback(
    void (*)(const char *, uint64_t) noexcept) noexcept {
    std::abort();
}

extern "C" int implant_init(const char *cfg) noexcept;
extern "C" unsigned int implant_finish_log_handoff(int accepted) noexcept;
extern "C" int implant_log_read_fd(void);
extern "C" int implant_state_reply_write_fd(void);
extern "C" jint JNI_OnLoad(JavaVM *, void *);
extern "C" int vbi_implant_test_throw;

void *safe_resolve_symbol(const char *, const char *) {
    return nullptr;
}
void *safe_resolve_symbol_symtab(const char *, const char *, bool) {
    return nullptr;
}

extern "C" void *vbi_dobby_inline_hooker(void *, void *) {
    return nullptr;
}

extern "C" bool vbi_dobby_inline_unhooker(void *) {
    return false;
}

static void assert_closed(int fd) {
    if (fd >= 0) {
        assert(fcntl(fd, F_GETFD) == -1);
    }
}

int main(void) {
    assert(JNI_OnLoad(nullptr, nullptr) == JNI_VERSION_1_6);
    const char *invalid_modes[] = {
        nullptr, "", "@unknown", "/data/voboost/bootstrap"};
    for (const char *invalid : invalid_modes) {
        assert(implant_init(invalid) == IMPLANT_INIT_FAILED);
    }

    int record = implant_init("@pipe-bootstrap-init");
    assert(record >= 0 && implant_log_read_fd() == record);
    int reply = implant_state_reply_write_fd();
    assert(reply >= 0);
    assert(implant_finish_log_handoff(0) == VBI_HANDOFF_ACK);
    assert(implant_log_read_fd() == -1);
    assert(implant_state_reply_write_fd() == -1);
    assert_closed(record);
    assert_closed(reply);

    record = implant_init("@pipe-bootstrap-init");
    assert(record >= 0);
    reply = implant_state_reply_write_fd();
    vbi_implant_test_throw = 1;
    assert(implant_init("@pipe-bootstrap-load") == IMPLANT_INIT_FAILED);
    assert(implant_log_read_fd() == -1);
    assert(implant_state_reply_write_fd() == -1);
    assert_closed(record);
    assert_closed(reply);

    assert(implant_init("@pipe-bootstrap-abort") == IMPLANT_INIT_PIPE_OK);
    return 0;
}
#else
int main(void) {
    std::fprintf(stderr, "SKIP: production implant host execution requires Linux\n");
    return 77;
}
#endif
