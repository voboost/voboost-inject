#include "diagnostic_time.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    errno = EACCES;
    uint64_t first = vbi_diagnostic_millis();
    assert(errno == EACCES);
    assert(first > 0);
    uint64_t second = vbi_diagnostic_millis();
    assert(second >= first);
    assert(vbi_diagnostic_elapsed(100, 107) == 7);
    assert(vbi_diagnostic_elapsed(0, 107) == 0);
    assert(vbi_diagnostic_elapsed(107, 100) == 0);
    puts("diagnostic time checks passed");
    return 0;
}
