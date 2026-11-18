#include "regset_restore.h"

#include <assert.h>
#include <stdio.h>

struct fixture {
    struct vbi_restore_regset parts[2];
    size_t count;
    unsigned char observed[2][VBI_ARM64_FP_BYTES];
    enum vbi_restore_part failing_part;
    enum vbi_restore_operation failing_operation;
    int length_delta;
    int calls[4];
    size_t call_count;
};
static size_t part_index(struct fixture *fixture, unsigned int note) {
    for (size_t i = 0; i < fixture->count; ++i) {
        if (fixture->parts[i].note == note) {
            return i;
        }
    }
    assert(0);
    return 0;
}
static long set(void *context, pid_t pid, unsigned int note, const void *bytes, size_t length) {
    (void)pid;
    struct fixture *fixture = context;
    size_t index = part_index(fixture, note);
    fixture->calls[fixture->call_count++] = 10 + (int)index;
    if (fixture->parts[index].part == fixture->failing_part
        && fixture->failing_operation == VBI_RESTORE_SET) {
        errno = EIO;
        return -1;
    }
    assert(length == fixture->parts[index].length);
    memcpy(fixture->observed[index], bytes, length);
    return 0;
}
static long get(void *context, pid_t pid, unsigned int note, void *bytes, size_t *length) {
    (void)pid;
    struct fixture *fixture = context;
    size_t index = part_index(fixture, note);
    fixture->calls[fixture->call_count++] = 20 + (int)index;
    int fail = fixture->parts[index].part == fixture->failing_part;
    if (fail && fixture->failing_operation == VBI_RESTORE_GET) {
        errno = ESRCH;
        return -1;
    }
    memcpy(bytes, fixture->observed[index], *length);
    if (fail && fixture->failing_operation == VBI_RESTORE_LENGTH) {
        *length = (size_t)((long)*length + fixture->length_delta);
    }
    if (fail && fixture->failing_operation == VBI_RESTORE_COMPARE) {
        size_t mismatch = fixture->parts[index].part == VBI_RESTORE_GPR && *length == 272 ? 265 : *length - 1;
        ((unsigned char *)bytes)[mismatch] ^= 1;
    }
    return 0;
}
static const struct vbi_restore_ops ops = {set, get};

static void exercise(int abi, int extended) {
    unsigned char saved[2][VBI_ARM64_FP_BYTES];
    memset(saved, 0x5a, sizeof(saved));
    struct fixture initial = {.count = extended ? 2 : 1};
    if (extended) {
        unsigned int note = abi == 64 ? VBI_NT_FPREGSET : VBI_NT_ARM_VFP;
        initial.parts[0] = (struct vbi_restore_regset){VBI_RESTORE_FP, note, saved[0],
                                                       vbi_regset_expected_length(abi, note)};
        initial.parts[1] = (struct vbi_restore_regset){VBI_RESTORE_TLS, VBI_NT_ARM_TLS, saved[1],
                                                       vbi_regset_expected_length(abi, VBI_NT_ARM_TLS)};
    } else {
        initial.parts[0] = (struct vbi_restore_regset){VBI_RESTORE_GPR, VBI_NT_PRSTATUS, saved[0],
                                                       vbi_regset_expected_length(abi, VBI_NT_PRSTATUS)};
    }
    struct fixture fixture = initial;
    fixture.failing_operation = VBI_RESTORE_COMPLETE;
    struct vbi_restore_diag diag;
    assert(vbi_restore_regsets_once(42, fixture.parts, fixture.count, &ops, &fixture, &diag) == 0);
    assert(diag.operation == VBI_RESTORE_COMPLETE && diag.reason == VBI_RESTORE_NONE);
    assert(!diag.errno_valid && diag.error == 0);
    assert(fixture.calls[0] == 10 && fixture.calls[fixture.count] == 20);
    if (extended) {
        assert(fixture.calls[1] == 11 && fixture.calls[3] == 21);
    }

    for (size_t index = 0; index < initial.count; ++index) {
        for (enum vbi_restore_operation operation = VBI_RESTORE_SET;
             operation <= VBI_RESTORE_COMPARE; ++operation) {
            for (int variant = 0; variant < (operation == VBI_RESTORE_LENGTH ? 2 : 1); ++variant) {
                fixture = initial;
                fixture.failing_part = fixture.parts[index].part;
                fixture.failing_operation = operation;
                fixture.length_delta = variant ? 1 : -1;
                errno = ERANGE; /* stale errno cannot describe a semantic mismatch */
                assert(vbi_restore_regsets_once(42, fixture.parts, fixture.count,
                                                &ops, &fixture, &diag) == -1);
                assert(diag.part == fixture.failing_part && diag.operation == operation);
                assert(diag.expected_length == fixture.parts[index].length);
                if (operation == VBI_RESTORE_SET || operation == VBI_RESTORE_GET) {
                    assert(diag.reason == VBI_RESTORE_SYSCALL && diag.errno_valid);
                    assert(diag.error == (operation == VBI_RESTORE_SET ? EIO : ESRCH));
                } else {
                    assert(!diag.errno_valid && diag.error == 0 && errno == ERANGE);
                    if (operation == VBI_RESTORE_LENGTH) {
                        assert(diag.reason == VBI_RESTORE_SIZE);
                        assert(diag.returned_length == (size_t)((long)diag.expected_length
                                                                + fixture.length_delta));
                        assert(diag.mismatch_count == 0);
                    } else {
                        assert(diag.reason == VBI_RESTORE_MISMATCH);
                        assert(diag.returned_length == diag.expected_length);
                        assert(diag.mismatch_count == 1 && diag.first_mismatch == (abi == 64 && !extended ? 265 : diag.expected_length - 1));
                        assert(diag.pstate_valid == (abi == 64 && !extended));
                        if (diag.pstate_valid) {
                            assert(diag.pstate_expected == UINT64_C(0x5a5a5a5a5a5a5a5a));
                            assert(diag.pstate_observed == UINT64_C(0x5a5a5a5a5a5a5b5a));
                            assert(diag.pstate_changed == UINT64_C(0x0000000000000100));
                        }
                    }
                }
                size_t expected_calls = operation == VBI_RESTORE_SET ? index + 1
                    : initial.count + index + 1;
                assert(fixture.call_count == expected_calls); /* no later get/compare consumed */
            }
        }
    }
}

int main(void) {
    exercise(64, 0); exercise(32, 0);
    exercise(64, 1); exercise(32, 1);
    return 0;
}
