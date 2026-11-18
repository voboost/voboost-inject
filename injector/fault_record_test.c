#define _GNU_SOURCE
#include "fault_record.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

int main(void) {
    assert(strcmp(vbi_fault_image("/system/bin/linker64", 20), "linker64") == 0);
    assert(strcmp(vbi_fault_image("/system/lib64/libc.so", 21), "libc.so") == 0);
    const char *private_path = "/data/private-user-secret.so";
    assert(strcmp(vbi_fault_image(private_path, strlen(private_path)), "unknown") == 0);
    assert(strcmp(vbi_fault_image("/system/bin/notlinker64", 23), "unknown") == 0);
    char record[256];
    siginfo_t info = {0};
    info.si_signo = SIGSEGV;
    info.si_code = SEGV_ACCERR;
    info.si_addr = (void *)(uintptr_t)0x1234;
    assert(vbi_fault_record(record, sizeof(record), 10, 20, 1, 0, &info));
    assert(strstr(record, "available=1 error=0"));
    assert(strstr(record, "address-valid=1 address=0x1234"));
    info.si_code = SI_USER;
    assert(vbi_fault_record(record, sizeof(record), 10, 20, 1, 0, &info));
    assert(strstr(record, "address-valid=0 address=0x0"));
    assert(!strstr(record, "1234"));
    assert(vbi_fault_record(record, sizeof(record), 10, 20, 0, EIO, NULL));
    assert(strstr(record, "available=0"));
    assert(strstr(record, "signal=0 code=0 address-valid=0 address=0x0"));
    assert(!vbi_fault_record(record, 8, 10, 20, 1, 0, &info));
    return 0;
}
