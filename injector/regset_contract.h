#ifndef VBI_REGSET_CONTRACT_H
#define VBI_REGSET_CONTRACT_H

#include <stddef.h>

#define VBI_NT_PRSTATUS 1U
#define VBI_NT_FPREGSET 2U
#define VBI_NT_ARM_VFP 0x400U
#define VBI_NT_ARM_TLS 0x401U
#define VBI_ARM64_GPR_BYTES 272U
#define VBI_ARM64_FP_BYTES 528U
#define VBI_ARM64_TLS_BYTES 8U
#define VBI_ARM32_GPR_BYTES 72U
#define VBI_ARM32_VFP_BYTES 260U
#define VBI_ARM32_TLS_BYTES 4U

static inline int vbi_regset_length_exact(size_t actual, size_t expected) {
    return expected != 0 && actual == expected;
}

static inline size_t vbi_regset_expected_length(int bitness, unsigned int note) {
    if (bitness == 64) {
        if (note == VBI_NT_PRSTATUS) {
            return VBI_ARM64_GPR_BYTES;
        }
        if (note == VBI_NT_FPREGSET) {
            return VBI_ARM64_FP_BYTES;
        }
        if (note == VBI_NT_ARM_TLS) {
            return VBI_ARM64_TLS_BYTES;
        }
    } else if (bitness == 32) {
        if (note == VBI_NT_PRSTATUS) {
            return VBI_ARM32_GPR_BYTES;
        }
        if (note == VBI_NT_ARM_VFP) {
            return VBI_ARM32_VFP_BYTES;
        }
        if (note == VBI_NT_ARM_TLS) {
            return VBI_ARM32_TLS_BYTES;
        }
    }
    return 0;
}

#endif
