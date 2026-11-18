#ifndef VOBOOST_CALLEE_FRAMES_H
#define VOBOOST_CALLEE_FRAMES_H

#include <stddef.h>
#include <stdint.h>

#define VBI_CALLEE_FRAME_LIMIT 16U

enum vbi_callee_frame_end {
    VBI_CALLEE_END_MARKER, VBI_CALLEE_LIMIT, VBI_CALLEE_INVALID,
    VBI_CALLEE_CYCLE, VBI_CALLEE_BOUNDS, VBI_CALLEE_READ_FAILED
};
struct vbi_callee_frame_result { enum vbi_callee_frame_end reason; size_t count; };
struct vbi_callee_frame_ops {
    int (*read_pair)(void *context, uint64_t fp, uint64_t pair[2]);
    void (*emit)(void *context, size_t index, uint64_t fp, uint64_t return_address);
};

/* AArch64 saved FP/LR pairs only; neither managed frames nor a complete unwind. */
static inline struct vbi_callee_frame_result vbi_callee_frames(
    uint64_t sp, uint64_t fp, uint64_t start, uint64_t end,
    const struct vbi_callee_frame_ops *ops, void *context) {
    struct vbi_callee_frame_result result = {VBI_CALLEE_INVALID, 0};
    if (!ops || !ops->read_pair || !ops->emit || start >= end
        || sp < start || sp >= end || (sp & 15)) {
        return result;
    }
    uint64_t seen[VBI_CALLEE_FRAME_LIMIT] = {0};
    for (size_t index = 0; index < VBI_CALLEE_FRAME_LIMIT; ++index) {
        if (!fp) {
            result.reason = VBI_CALLEE_END_MARKER; return result;
        }
        for (size_t previous = 0; previous < index; ++previous) {
            if (seen[previous] == fp) {
                result.reason = VBI_CALLEE_CYCLE; return result;
            }
        }
        if (fp & 15) {
            result.reason = VBI_CALLEE_INVALID; return result;
        }
        if (fp < sp || fp < start || fp >= end || end - fp < 16) {
            result.reason = VBI_CALLEE_BOUNDS; return result;
        }
        if (index && fp <= seen[index - 1]) {
            result.reason = VBI_CALLEE_INVALID; return result;
        }
        uint64_t pair[2] = {0};
        if (ops->read_pair(context, fp, pair) != 0) {
            result.reason = VBI_CALLEE_READ_FAILED; return result;
        }
        seen[index] = fp;
        ops->emit(context, index, fp, pair[1]);
        ++result.count;
        fp = pair[0];
    }
    result.reason = VBI_CALLEE_LIMIT;
    return result;
}

static inline const char *vbi_callee_frame_reason(enum vbi_callee_frame_end reason) {
    static const char *const names[] = {"end-marker", "limit", "invalid", "cycle", "bounds", "read-failed"};
    return reason >= VBI_CALLEE_END_MARKER && reason <= VBI_CALLEE_READ_FAILED
           ? names[reason] : "invalid";
}

#endif
