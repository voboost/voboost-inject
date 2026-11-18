#ifndef VOBOOST_REGSET_RESTORE_H
#define VOBOOST_REGSET_RESTORE_H

#include "regset_contract.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

enum vbi_restore_part { VBI_RESTORE_GPR, VBI_RESTORE_FP, VBI_RESTORE_TLS, VBI_RESTORE_STACK };
enum vbi_restore_operation { VBI_RESTORE_UNAVAILABLE, VBI_RESTORE_SET,
                             VBI_RESTORE_GET, VBI_RESTORE_LENGTH,
                             VBI_RESTORE_COMPARE, VBI_RESTORE_COMPLETE };
enum vbi_restore_reason { VBI_RESTORE_NONE, VBI_RESTORE_SYSCALL,
                          VBI_RESTORE_SIZE, VBI_RESTORE_MISMATCH,
                          VBI_RESTORE_NO_SNAPSHOT };

struct vbi_restore_diag {
    enum vbi_restore_part part;
    enum vbi_restore_operation operation;
    enum vbi_restore_reason reason;
    int error;
    int errno_valid;
    size_t expected_length;
    size_t returned_length;
    size_t mismatch_count;
    size_t first_mismatch;
    int pstate_valid;
    uint64_t pstate_expected;
    uint64_t pstate_observed;
    uint64_t pstate_changed;
};
struct vbi_restore_regset {
    enum vbi_restore_part part;
    unsigned int note;
    const void *saved;
    size_t length;
};
struct vbi_restore_ops {
    long (*set)(void *context, pid_t pid, unsigned int note, const void *bytes, size_t length);
    long (*get)(void *context, pid_t pid, unsigned int note, void *bytes, size_t *length);
};

static inline const char *vbi_restore_part_name(enum vbi_restore_part part) {
    static const char *const names[] = {"gpr", "fp", "tls", "stack"};
    return part >= VBI_RESTORE_GPR && part <= VBI_RESTORE_STACK ? names[part] : "unknown";
}
static inline const char *vbi_restore_operation_name(enum vbi_restore_operation operation) {
    static const char *const names[] = {"unavailable", "set", "get", "length", "compare", "complete"};
    return operation >= VBI_RESTORE_UNAVAILABLE && operation <= VBI_RESTORE_COMPLETE
           ? names[operation] : "unknown";
}
static inline const char *vbi_restore_reason_name(enum vbi_restore_reason reason) {
    static const char *const names[] = {"none", "syscall", "length", "mismatch", "no-snapshot"};
    return reason >= VBI_RESTORE_NONE && reason <= VBI_RESTORE_NO_SNAPSHOT ? names[reason] : "unknown";
}

/* One attempt only: preserve set-all then exact get/compare order. Retry
 * policy and caller errno are unchanged; diagnostics contain no raw bytes. */
static inline int vbi_restore_regsets_once(pid_t pid, const struct vbi_restore_regset *parts,
                                           size_t count, const struct vbi_restore_ops *ops, void *context, struct vbi_restore_diag *diag) {
    *diag = (struct vbi_restore_diag){.operation = VBI_RESTORE_UNAVAILABLE,
                                      .reason = VBI_RESTORE_NO_SNAPSHOT};
    for (size_t index = 0; index < count; ++index) {
        const struct vbi_restore_regset *part = &parts[index];
        *diag = (struct vbi_restore_diag){.part = part->part, .operation = VBI_RESTORE_SET,
                                          .expected_length = part->length};
        if (ops->set(context, pid, part->note, part->saved, part->length) != 0) {
            diag->reason = VBI_RESTORE_SYSCALL;
            diag->error = errno;
            diag->errno_valid = errno != 0;
            return -1;
        }
    }
    for (size_t index = 0; index < count; ++index) {
        const struct vbi_restore_regset *part = &parts[index];
        unsigned char observed[VBI_ARM64_FP_BYTES] = {0};
        *diag = (struct vbi_restore_diag){.part = part->part, .operation = VBI_RESTORE_GET,
                                          .expected_length = part->length};
        size_t length = part->length;
        if (ops->get(context, pid, part->note, observed, &length) < 0) {
            diag->reason = VBI_RESTORE_SYSCALL;
            diag->error = errno;
            diag->errno_valid = errno != 0;
            diag->returned_length = length;
            return -1;
        }
        diag->returned_length = length;
        if (length != part->length) {
            diag->operation = VBI_RESTORE_LENGTH;
            diag->reason = VBI_RESTORE_SIZE;
            return -1;
        }
        if (memcmp(observed, part->saved, part->length) != 0) {
            diag->operation = VBI_RESTORE_COMPARE;
            diag->reason = VBI_RESTORE_MISMATCH;
            /* ARM64 NT_PRSTATUS: 31 GPRs, SP, PC, then PSTATE.
             * Diagnostics only: every byte remains subject to exact comparison. */
            if (part->part == VBI_RESTORE_GPR && part->note == VBI_NT_PRSTATUS
                && part->length == 272) {
                diag->pstate_valid = 1;
                memcpy(&diag->pstate_expected, (const unsigned char *)part->saved + 264, 8);
                memcpy(&diag->pstate_observed, observed + 264, 8);
                diag->pstate_changed = diag->pstate_expected ^ diag->pstate_observed;
            }
            const unsigned char *saved = part->saved;
            for (size_t byte = 0; byte < part->length; ++byte) {
                if (observed[byte] != saved[byte]) {
                    if (diag->mismatch_count++ == 0) {
                        diag->first_mismatch = byte;
                    }
                }
            }
            return -1;
        }
    }
    diag->operation = VBI_RESTORE_COMPLETE;
    diag->reason = VBI_RESTORE_NONE;
    return 0;
}

#endif
