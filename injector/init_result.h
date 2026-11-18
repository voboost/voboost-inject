#ifndef VOBOOST_INIT_RESULT_H
#define VOBOOST_INIT_RESULT_H

enum vbi_implant_init_kind {
    VBI_INIT_FD,
    VBI_INIT_PIPE_OK,
    VBI_INIT_DEFERRED,
    VBI_INIT_FAILED,
    VBI_INIT_REBOUND,
    VBI_INIT_STAGED,
    VBI_INIT_UNKNOWN_NEGATIVE,
    VBI_INIT_INVALID_FD,
};

static inline enum vbi_implant_init_kind vbi_classify_implant_init(int value) {
    if (value == 0) {
        return VBI_INIT_INVALID_FD;
    }
    if (value > 0) {
        return VBI_INIT_FD;
    }
    if (value == -1000) {
        return VBI_INIT_DEFERRED;
    }
    if (value == -1001) {
        return VBI_INIT_FAILED;
    }
    if (value == -1002) {
        return VBI_INIT_PIPE_OK;
    }
    if (value == -1004) {
        return VBI_INIT_STAGED;
    }
    if (value == -1003) {
        return VBI_INIT_REBOUND;
    }
    return VBI_INIT_UNKNOWN_NEGATIVE;
}

#endif
