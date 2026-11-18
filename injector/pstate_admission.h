#ifndef VOBOOST_PSTATE_ADMISSION_H
#define VOBOOST_PSTATE_ADMISSION_H

#include <stdint.h>

/* Old Android kernels clear BTYPE in SETREGSET even when GETREGSET reports
 * it. Defer at a natural stop instead of changing the saved execution state.
 * This conservative gate also applies on kernels that support BTYPE. */
static inline int vbi_pstate_admissible(uint64_t pstate) {
    return (pstate & UINT64_C(0xc00)) == 0;
}

#endif
