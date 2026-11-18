/* This entry is never exported as libc execve. Only an admitted supervisor slot
 * may call it, after the genuine original has been installed before fork. */
#include "supervisor_exec.h"
#include "supervisor_env.h"
extern "C" int *__get_errno_ptr(void);
using Exec = int (*)(const char *, char *const [], char *const []);
static Exec original;
extern "C" int vbc_supervisor_exec_set_original(void *value) {
    if (!value || value == reinterpret_cast<void *>(vbc_supervisor_execve)) return -1;
    Exec expected = nullptr;
    Exec desired = reinterpret_cast<Exec>(value);
    if (__atomic_compare_exchange_n(&original, &expected, desired, false,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) return 0;
    return expected == desired ? 0 : -1;
}
extern "C" int vbc_supervisor_execve(const char *path, char *const argv[], char *const envp[]) {
    Exec call = __atomic_load_n(&original, __ATOMIC_ACQUIRE);
    if (!call) return -1; // Unpublished entry: no OEM slot may point here yet.
    int *error = __get_errno_ptr();
    int before = *error;
    VbcSupervisorDeliveryValues values{};
    VbcSupervisorEnvStorage storage;
    char *const *selected = envp;
    if (vbc_supervisor_current(&values) == 0) {
        selected = vbc_supervisor_env_prepare(path, envp, values.implant,
            values.bootfile, values.stamp, &storage);
    }
    *error = before;
    return call(path, argv, selected);
}
