#include <assert.h>
#include "init_result.h"
#include "handoff_result.h"
#include "regset_contract.h"

int main(void) {
    assert(VBI_HANDOFF_ACK != 0);
    assert(vbi_regset_length_exact(72, 72));
    assert(!vbi_regset_length_exact(71, 72));
    assert(!vbi_regset_length_exact(73, 72));
    assert(vbi_regset_expected_length(64, VBI_NT_PRSTATUS) == 272);
    assert(vbi_regset_expected_length(64, VBI_NT_FPREGSET) == 528);
    assert(vbi_regset_expected_length(64, VBI_NT_ARM_TLS) == 8);
    assert(vbi_regset_expected_length(32, VBI_NT_PRSTATUS) == 72);
    assert(vbi_regset_expected_length(32, VBI_NT_ARM_VFP) == 260);
    assert(vbi_regset_expected_length(32, VBI_NT_ARM_TLS) == 4);
    assert(vbi_regset_expected_length(32, VBI_NT_FPREGSET) == 0);
    assert(vbi_classify_implant_init(-1004) == VBI_INIT_STAGED);
    assert(vbi_classify_implant_init(0) == VBI_INIT_INVALID_FD);
    assert(vbi_classify_implant_init(7) == VBI_INIT_FD);
    assert(vbi_classify_implant_init(-1002) == VBI_INIT_PIPE_OK);
    assert(vbi_classify_implant_init(-1003) == VBI_INIT_REBOUND);
    assert(vbi_classify_implant_init(-1) == VBI_INIT_UNKNOWN_NEGATIVE);
    assert(vbi_classify_implant_init(-77) == VBI_INIT_UNKNOWN_NEGATIVE);
    return 0;
}
