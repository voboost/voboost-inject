/*
 * injector.c — hybrid ptrace injector (C), the daemon's native injection rail.
 *
 * Injects a .so into a target process via ptrace + remote dlopen, then makes
 * an explicit remote-call to an entry symbol (e.g. implant_init).
 *
 * Proven mechanism (PoC, vendor-Android 9, kernel 4.14.156-perf+):
 *   - bitness detection from /proc/<pid>/exe (app_process32/app_process64)
 *     with /proc/<pid>/maps /lib64/ scan fallback
 *   - remote call via PTRACE_CONT + LR=0 trap (SINGLESTEP/hw-bp do NOT work
 *     on this kernel — AndKittyInjector rejected for that reason)
 *   - cross-bitness regsets: arm64_regs (64) / user_regs_32 (32, Thumb via CPSR.T)
 *   - __loader_dlopen (NOT libdl dlopen, which loses arguments)
 *   - caller_addr inside app_process for namespace resolution
 *   - .so path written ~8KB below SP (closer is clobbered by call frame)
 *   - explicit remote-call to init_sym (ctors don't run under ptrace-dlopen)
 *
 * See native-payload spec for the full contract.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <android/log.h>

#include "injector.h"

/* Verbose step-by-step debug logging for the injector (attach, bitness,
 * dlopen, dlsym, init, every remote_call32/64 register set). Off in
 * production — the daemon's own log file is the canonical trace; the only
 * logcat output in production is the ERROR-level dlerror string when a remote
 * dlopen fails (see vbi_inject). Flip to 1 to diagnose injection failures
 * on-device. */
#define VBI_DBG 0
#if VBI_DBG
#define DBG(fmt, ...) \
        __android_log_print(ANDROID_LOG_INFO, "voboost-injector", "DBG: " fmt, ## __VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

/* ---- internal types from regs.c ---- */

struct arm64_regs {
    unsigned long long regs[31]; /* x0..x30 */
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

/* ---- internal decls from elf_resolve.c ---- */

typedef unsigned long long u64;

int  target_read_mem(int pid, u64 addr, void *buf, size_t len);
int  target_write_mem(int pid, u64 addr, const void *buf, size_t len);
int  target_verify_mem(int pid, u64 addr, const void *expected, size_t len);
u64  find_linker64_rxp_base(int pid);
u64  find_target_caller_addr(int pid);
u64  resolve_loader_symbol(int pid, int bitness, const char *sym_name);

/* ---- bitness detection ---- */

/*
 * Detect the target process bitness at runtime.
 *
 * Checks /proc/<pid>/exe for app_process32 vs app_process64, then falls
 * back to scanning /proc/<pid>/maps for /lib64/.
 *
 * Returns: 64, 32, or 0 on failure (native-payload: bitness MUST be
 * detected per-injection, never from a static agent→bitness table).
 */
static int detect_bitness(int pid) {
    char exe_path[64];
    char buf[512];
    ssize_t n;

    /* Method 1: readlink /proc/<pid>/exe */
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    n = readlink(exe_path, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        if (strstr(buf, "app_process32") || strstr(buf, "app_process32_real")) {
            return 32;
        }
        if (strstr(buf, "app_process64") || strstr(buf, "app_process")) {
            return 64;
        }
    }

    /* Method 2: scan maps for /lib64/ (64-bit) vs absence (32-bit) */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return 0;
    }
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, "/lib64/")) {
            fclose(f);
            return 64;
        }
    }
    fclose(f);
    /* No /lib64/ found — likely 32-bit */
    return 32;
}

/* ---- 64-bit remote call ---- */

/*
 * Call a function in a 64-bit target via ptrace.
 * Sets x0..x7 for up to 8 args, LR=0 (trap on return), PC=func_addr.
 * Resumes with PTRACE_CONT; catches SIGSEGV-at-0 as the return signal.
 * Returns the x0 (return value) of the called function.
 */
static u64 remote_call64(int pid, u64 func_addr, u64 args[], int nargs) {
    struct arm64_regs regs;
    struct iovec iov = { &regs, sizeof(regs) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        return 0;
    }

    struct arm64_regs orig = regs; /* save for restore */

    /* Set arguments x0..x7 */
    for (int i = 0; i < nargs && i < 8; i++) {
        regs.regs[i] = args[i];
    }

    /* LR=0: function returns to address 0 → SIGSEGV = call completed */
    regs.regs[30] = 0;

    /* Align SP to 16 bytes (AArch64 ABI) and make room for call frame */
    regs.sp = (regs.sp & ~0xFULL) - 256;

    regs.pc = func_addr;

    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) {
        return 0;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        return 0;
    }

    int status;
    waitpid(pid, &status, 0);

    /* Read result: x0 holds the return value */
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        /* Restore on error */
        iov.iov_len = sizeof(orig);
        memcpy(&regs, &orig, sizeof(orig));
        ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
        return 0;
    }
    u64 result = regs.regs[0];

    /* Restore original registers */
    iov.iov_len = sizeof(orig);
    memcpy(&regs, &orig, sizeof(orig));
    ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);

    return result;
}

/* ---- 32-bit remote call ---- */

/*
 * ARM 32-bit user_regs (EABI).
 *   uregs[0]  = r0 (return value)
 *   uregs[13] = sp
 *   uregs[14] = lr
 *   uregs[15] = pc
 *   uregs[16] = cpsr (bit 5 = 0x20 = CPSR.T → Thumb decoding; see remote_call32)
 * NOTE: Thumb mode is NOT selected by the PC LSB under ptrace (the kernel
 * writes back an even PC). Set CPSR.T in uregs[16] when calling a Thumb
 * symbol (linker hands back LSB=1 addresses for Thumb); see remote_call32.
 */
struct user_regs_32 {
    /* 32-bit ARM regset fields are 32-bit wide. The kernel's
     * PTRACE_GETREGSET for a 32-bit ARM target returns iov_len=72
     * (18 * sizeof(uint32_t)). Using `unsigned long` here (8 bytes on a
     * 64-bit host/toolchain) makes sizeof(user_regs_32)=144, so the kernel
     * fills only the first 72 bytes and every other field reads as 0 or as a
     * misaligned concatenation of two adjacent 32-bit values (observed:
     * uregs[13]=0x269000020 was actually SP_low|SP_high of two slots). */
    uint32_t uregs[18];
};

static u64 remote_call32(int pid, u64 func_addr, u64 args[], int nargs) {
    struct user_regs_32 regs;
    struct iovec iov = { &regs, sizeof(regs) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        DBG("rc32: GETREGSET failed: %s", strerror(errno));
        return 0;
    }

    struct user_regs_32 orig = regs;
    DBG("rc32: func=0x%llx nargs=%d orig pc=0x%x sp=0x%x",
        (unsigned long long)func_addr, nargs, orig.uregs[15], orig.uregs[13]);

    /* Set arguments r0..r3 (ARM calling convention: first 4 in registers) */
    for (int i = 0; i < nargs && i < 4; i++) {
        regs.uregs[i] = (uint32_t)args[i];
    }

    /* LR=0: function returns to address 0 → SIGSEGV = call completed */
    regs.uregs[14] = 0;

    /* Align SP to 8 bytes (ARM EABI) */
    regs.uregs[13] = (regs.uregs[13] & ~0x7u) - 256;

    /* Set PC + Thumb mode. For a 32-bit ARM target under an ARM64-host kernel,
     * the PC field (uregs[15]) does NOT carry the Thumb bit in its LSB — the
     * kernel writes back the even PC and the CPU then executes ARM (A-state)
     * instructions, which SIGILLs on Thumb code. Thumb/ARM mode is selected by
     * the CPSR.T bit (bit 5 = 0x20) in uregs[16] (CPSR). The linker hands us a
     * function address with LSB=1 for Thumb symbols; we must (1) clear that LSB
     * from the PC and (2) set CPSR.T to switch to Thumb decoding. Mismatch
     * (PC odd without CPSR.T, or CPSR.T set with an even PC at a non-2byte
     * boundary) faults at the first instruction. */
    int is_thumb = (uint32_t)func_addr & 1;
    regs.uregs[15] = (uint32_t)func_addr & ~(uint32_t)1;
    if (is_thumb) {
        regs.uregs[16] |= 0x20u;  /* CPSR.T bit → Thumb decoding */
    } else {
        regs.uregs[16] &= ~0x20u;
    }

    DBG("rc32: SET pc=0x%x sp=0x%x lr=0 cpsr=0x%x (T=%d) r0=0x%x r1=0x%x r2=0x%x",
        regs.uregs[15], regs.uregs[13], regs.uregs[16], is_thumb,
        regs.uregs[0], regs.uregs[1], regs.uregs[2]);

    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) {
        DBG("rc32: SETREGSET failed: %s", strerror(errno));
        return 0;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        DBG("rc32: CONT failed: %s", strerror(errno));
        return 0;
    }

    int status;
    waitpid(pid, &status, 0);
    DBG("rc32: waited status=0x%x (WIFSTOPPED=%d sig=%d WIFSIGNALED=%d)",
        status, WIFSTOPPED(status), WSTOPSIG(status), WIFSIGNALED(status));

    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        DBG("rc32: GETREGSET(after) failed: %s", strerror(errno));
        iov.iov_len = sizeof(orig);
        memcpy(&regs, &orig, sizeof(orig));
        ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
        return 0;
    }

    u64 result = regs.uregs[0]; /* r0 = return value */
    DBG("rc32: result r0=0x%x (pc now=0x%x)", regs.uregs[0], regs.uregs[15]);

    /* Restore */
    iov.iov_len = sizeof(orig);
    memcpy(&regs, &orig, sizeof(orig));
    ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);

    return result;
}

/* ---- main injection entry ---- */

/*
 * vbi_inject — inject a .so into a target process via ptrace.
 *
 * Returns 0 on success, negative on error (see injector.h).
 */
int vbi_inject(int pid, const char *so_path, const char *init_sym) {
    DBG("vbi_inject pid=%d so_path=%s init_sym=%s", pid, so_path, init_sym);
    if (!so_path || pid <= 0) {
        DBG("invalid args");
        return -1;
    }

    /* 1. Attach to the target. */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        DBG("PTRACE_ATTACH failed: %s", strerror(errno));
        return -1; /* denied (permission or SELinux) */

    }
    int status;
    int ret = -1;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        DBG("target gone before inject");
        ret = -2; /* target gone */
        goto detach;
    }
    DBG("attached, status=0x%x", status);

    /* 2. Detect target bitness at runtime. */
    int bitness = detect_bitness(pid);
    DBG("detected bitness=%d", bitness);
    if (bitness != 32 && bitness != 64) {
        DBG("bitness detection failed");
        ret = -5; /* bitness detection failed */
        goto detach;
    }

    /* 3. Resolve __loader_dlopen in the target. */
    u64 dlopen_addr = resolve_loader_symbol(pid, bitness, "__loader_dlopen");
    DBG("__loader_dlopen @ 0x%llx", (unsigned long long)dlopen_addr);
    if (!dlopen_addr) {
        DBG("resolve __loader_dlopen FAILED");
        ret = -3; /* dlopen failed (can't even find dlopen) */
        goto detach;
    }

    /* 4. Find caller_addr inside app_process (for namespace resolution). */
    u64 caller_addr = find_target_caller_addr(pid);
    DBG("caller_addr @ 0x%llx", (unsigned long long)caller_addr);

    /* 5. Write the .so path string ~8KB below SP (safe from call frame). */
    u64 str_addr = 0;
    size_t path_len = strlen(so_path) + 1;

    if (bitness == 64) {
        struct arm64_regs regs;
        struct iovec iov = { &regs, sizeof(regs) };
        ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
        u64 sp = regs.sp & ~0xFULL;
        str_addr = sp - 8192;
    } else {
        struct user_regs_32 regs;
        memset(&regs, 0, sizeof(regs));
        struct iovec iov = { &regs, sizeof(regs) };
        int gr = ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
        DBG("32-bit GETREGSET rc=%d iov_len=%zu (sizeof user_regs_32=%zu)",
            gr, iov.iov_len, sizeof(regs));
        DBG("32-bit raw uregs[13](sp)=0x%x uregs[14](lr)=0x%x uregs[15](pc)=0x%x",
            regs.uregs[13], regs.uregs[14], regs.uregs[15]);
        /* uregs is now uint32_t[18] (matches the kernel's 72-byte regset), so
         * SP is a clean 32-bit value. Align to 8 (ARM EABI). */
        u64 sp = regs.uregs[13] & ~(u64)0x7;
        str_addr = sp - 8192;
    }
    DBG("path string @ 0x%llx (sp-based), len=%zu", (unsigned long long)str_addr, path_len);

    if (target_write_mem(pid, str_addr, so_path, path_len) < 0) {
        DBG("target_write_mem for path FAILED: %s", strerror(errno));
        ret = -3;
        goto detach;
    }
    DBG("path string written ok");

    /* 6. Call __loader_dlopen(so_path, RTLD_NOW, caller_addr). */
    u64 args[3] = { str_addr, 2 /* RTLD_NOW */, caller_addr };
    u64 handle;

    DBG("calling __loader_dlopen (bitness=%d)...", bitness);
    if (bitness == 64) {
        handle = remote_call64(pid, dlopen_addr, args, 3);
    }else {
        handle = remote_call32(pid, dlopen_addr, args, 3);
    }
    DBG("__loader_dlopen returned handle=0x%llx", (unsigned long long)handle);

    if (handle == 0) {
        /* dlopen failed — fetch + log the dlerror string for diagnostics. */
        u64 dlerror_addr = resolve_loader_symbol(pid, bitness, "__loader_dlerror");
        DBG("__loader_dlerror @ 0x%llx", (unsigned long long)dlerror_addr);
        if (dlerror_addr) {
            u64 dlerr_result;
            if (bitness == 64) {
                dlerr_result = remote_call64(pid, dlerror_addr, NULL, 0);
            } else {
                dlerr_result = remote_call32(pid, dlerror_addr, NULL, 0);
            }
            DBG("dlerror() returned 0x%llx", (unsigned long long)dlerr_result);
            if (dlerr_result != 0) {
                char dlerr_buf[256] = {0};
                int rd = target_read_mem(pid, dlerr_result, dlerr_buf, sizeof(dlerr_buf) - 1);
                DBG("target_read_mem(dlerr) = %d", rd);
                if (rd == 0) {
                    __android_log_print(ANDROID_LOG_ERROR, "voboost-injector",
                                        "remote dlopen(%s) failed: %s", so_path, dlerr_buf);
                } else {
                    __android_log_print(ANDROID_LOG_ERROR, "voboost-injector",
                                        "remote dlopen(%s) failed (dlerror unreadable @ 0x%llx)",
                                        so_path, (unsigned long long)dlerr_result);
                }
            } else {
                __android_log_print(ANDROID_LOG_ERROR, "voboost-injector",
                                    "remote dlopen(%s) failed (dlerror returned NULL)", so_path);
            }
        } else {
            DBG("resolve __loader_dlerror FAILED");
        }
        ret = -3; /* dlopen failed */
        goto detach;
    }
    DBG("dlopen succeeded, handle=0x%llx", (unsigned long long)handle);

    /* 7. Explicit remote-call to init_sym (ctors don't run under ptrace-dlopen). */
    if (init_sym) {
        u64 dlsym_addr = resolve_loader_symbol(pid, bitness, "__loader_dlsym");
        DBG("__loader_dlsym @ 0x%llx", (unsigned long long)dlsym_addr);
        if (dlsym_addr) {
            /* Write the symbol name string into target memory. */
            size_t sym_len = strlen(init_sym) + 1;
            u64 sym_str_addr = str_addr - sym_len - 16; /* below the path */
            DBG("sym '%s' @ 0x%llx, len=%zu", init_sym, (unsigned long long)sym_str_addr, sym_len);
            if (target_write_mem(pid, sym_str_addr, init_sym, sym_len) < 0) {
                DBG("target_write_mem for sym FAILED");
                ret = -4;
                goto detach;
            }

            /* dlsym(handle, init_sym, caller_addr) */
            u64 sym_args[3] = { handle, sym_str_addr, caller_addr };
            u64 init_addr;
            if (bitness == 64) {
                init_addr = remote_call64(pid, dlsym_addr, sym_args, 3);
            }else {
                init_addr = remote_call32(pid, dlsym_addr, sym_args, 3);
            }
            DBG("dlsym(handle, %s) -> init_addr=0x%llx", init_sym, (unsigned long long)init_addr);

            if (init_addr == 0) {
                DBG("init symbol not found");
                ret = -4; /* init symbol not found */
                goto detach;
            }

            /* Call init_addr(cfg). The config path is passed as x0/r0.
             * For the initial port we pass the same so_path as cfg
             * (the real config path is delivered via channel B — the
             * daemon passes it separately in injection-control). */
            u64 init_args[1] = { str_addr };
            DBG("calling init_addr(0x%llx)...", (unsigned long long)str_addr);
            if (bitness == 64) {
                remote_call64(pid, init_addr, init_args, 1);
            }else {
                remote_call32(pid, init_addr, init_args, 1);
            }
            DBG("init_addr call returned");
        } else {
            DBG("resolve __loader_dlsym FAILED");
        }
    }

    DBG("inject SUCCESS");
    ret = 0; /* success */

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret;
}
