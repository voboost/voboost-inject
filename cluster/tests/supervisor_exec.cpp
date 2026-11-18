#include "../service/supervisor_exec.h"
#include <cassert>
#include <cerrno>
#include <cstring>
static int calls, admitted;
static char *const *seen;
static const char *seen_path;
static char *const *seen_argv;
extern "C" int *__get_errno_ptr() { return &errno; }
extern "C" int vbc_supervisor_current(VbcSupervisorDeliveryValues *out) {
    errno = 91;
    if (!admitted) return -1;
    *out = {"/var/voboost/bin/implant.so", "/var/voboost/boot.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    return 0;
}
static int actual(const char *path, char *const argv[], char *const envp[]) {
    assert(errno == 37); ++calls; seen = envp; seen_path = path; seen_argv = argv;
    errno = 82; return -9;
}
static int other(const char *, char *const [], char *const []) { assert(false); return 0; }
int main() {
    assert(vbc_supervisor_exec_set_original(nullptr) == -1);
    assert(vbc_supervisor_exec_set_original(reinterpret_cast<void *>(vbc_supervisor_execve)) == -1);
    assert(vbc_supervisor_exec_set_original(reinterpret_cast<void *>(actual)) == 0);
    assert(vbc_supervisor_exec_set_original(reinterpret_cast<void *>(actual)) == 0);
    assert(vbc_supervisor_exec_set_original(reinterpret_cast<void *>(other)) == -1);
    char arg[] = "gauge", original[] = "A=B";
    char *argv[] = {arg, nullptr}; char *env[] = {original, nullptr};
    errno = 37;
    assert(vbc_supervisor_execve("/usr/bin/gauge", argv, env) == -9);
    assert(calls == 1 && seen == env && errno == 82 && seen_argv == argv);
    admitted = 1; errno = 37;
    assert(vbc_supervisor_execve("/usr/bin/gauge", argv, env) == -9);
    // The stack env is valid only during actual(); don't dereference it here.
    assert(calls == 2 && seen != env && errno == 82 && seen_argv == argv);
    errno = 37;
    assert(vbc_supervisor_execve("/usr/bin/other", argv, env) == -9);
    assert(calls == 3 && seen == env && errno == 82 && std::strcmp(seen_path,"/usr/bin/other") == 0);
}
