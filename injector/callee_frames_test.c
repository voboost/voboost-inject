#include "callee_frames.h"
#include <assert.h>
#include <string.h>

struct fixture {
    uint64_t pairs[20][2];
    uint64_t emitted_fp[16];
    uint64_t emitted_return[16];
    size_t reads;
    size_t emitted;
    uint64_t fail_at;
};
static int read_pair(void *opaque, uint64_t fp, uint64_t pair[2]) {
    struct fixture *fixture = opaque;
    ++fixture->reads;
    if (fp == fixture->fail_at) {
        return -1;
    }
    assert(fp >= 0x1100 && fp < 0x1240 && (fp & 15) == 0);
    memcpy(pair, fixture->pairs[(fp - 0x1100) / 16], sizeof(uint64_t) * 2);
    return 0;
}
static void emit(void *opaque, size_t index, uint64_t fp, uint64_t return_address) {
    struct fixture *fixture = opaque;
    assert(index == fixture->emitted && index < 16);
    fixture->emitted_fp[index] = fp;
    fixture->emitted_return[index] = return_address;
    ++fixture->emitted;
}
static const struct vbi_callee_frame_ops ops = {read_pair, emit};
static struct fixture initial(void) {
    struct fixture fixture = {0};
    for (size_t index = 0; index < 20; ++index) {
        fixture.pairs[index][0] = 0x1100 + (index + 1) * 16;
        fixture.pairs[index][1] = 0x5000 + index;
    }
    return fixture;
}
int main(void) {
    struct fixture fixture = initial();
    fixture.pairs[2][0] = 0;
    struct vbi_callee_frame_result result = vbi_callee_frames(0x1000, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_END_MARKER && result.count == 3);
    assert(fixture.reads == 3 && fixture.emitted_return[2] == 0x5002);

    fixture = initial();
    fixture.pairs[1][0] = 0x1100;
    result = vbi_callee_frames(0x1000, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_CYCLE && result.count == 2 && fixture.reads == 2);

    fixture = initial();
    fixture.fail_at = 0x1120;
    result = vbi_callee_frames(0x1000, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_READ_FAILED && result.count == 2);
    assert(fixture.reads == 3 && fixture.emitted == 2);

    fixture = initial();
    result = vbi_callee_frames(0x1000, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_LIMIT && result.count == 16 && fixture.reads == 16);

    fixture = initial();
    result = vbi_callee_frames(0x1000, 0x1230, 0x1000, 0x123f, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_BOUNDS && fixture.reads == 0);
    result = vbi_callee_frames(0x1110, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_BOUNDS && fixture.reads == 0);
    result = vbi_callee_frames(0x1000, UINT64_MAX - 15, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_BOUNDS && fixture.reads == 0);
    result = vbi_callee_frames(0x1000, 0x1108, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_INVALID && fixture.reads == 0);
    result = vbi_callee_frames(0x1008, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_INVALID && fixture.reads == 0);
    result = vbi_callee_frames(0x1000, 0, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_END_MARKER && fixture.reads == 0);

    fixture = initial();
    fixture.pairs[0][0] = 0x10f0;
    result = vbi_callee_frames(0x1000, 0x1100, 0x1000, 0x1240, &ops, &fixture);
    assert(result.reason == VBI_CALLEE_INVALID && result.count == 1 && fixture.reads == 1);
    return 0;
}
