#ifndef VOBOOST_FAULT_RECORD_H
#define VOBOOST_FAULT_RECORD_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Image names are a fixed diagnostic vocabulary, never arbitrary map paths. */
static inline const char *vbi_fault_image(const char *path, size_t length) {
    static const char *const names[] = {
        "linker", "linker64", "libc.so", "libdl.so", "libart.so", "libnativeloader.so",
        "libandroid_runtime.so", "libwebviewchromium.so", "libimplant.so", "liblsplant.so"
    };
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        size_t size = strlen(names[index]);
        if (length > size && path[length - size - 1] == '/'
            && memcmp(path + length - size, names[index], size) == 0) {
            return names[index];
        }
    }
    return "unknown";
}

/* Keep sender-provided union data out of diagnostics. */
static inline int vbi_fault_record(char *record, size_t size, int helper, int tid,
                                   int available, int error, const siginfo_t *info) {
    int address_valid = available
                        && ((info->si_signo == SIGSEGV
                             && (info->si_code == SEGV_MAPERR || info->si_code == SEGV_ACCERR))
                            || (info->si_signo == SIGBUS
                                && (info->si_code == BUS_ADRALN || info->si_code == BUS_ADRERR
                                    || info->si_code == BUS_OBJERR))
                            || (info->si_signo == SIGILL && info->si_code >= ILL_ILLOPC
                                && info->si_code <= ILL_BADSTK)
                            || (info->si_signo == SIGFPE && info->si_code >= FPE_INTDIV
                                && info->si_code <= FPE_FLTSUB));
    int length = snprintf(record, size,
                          "[%d] callee-siginfo pid=%d available=%d error=%d signal=%d code=%d address-valid=%d address=0x%llx\n",
                          helper, tid, available, error,
                          available ? info->si_signo : 0, available ? info->si_code : 0,
                          address_valid,
                          address_valid ? (unsigned long long)(uintptr_t)info->si_addr : 0);
    return length > 0 && (size_t)length < size ? length : 0;
}

#endif
