// Host checks for the resident downlink watcher's apply-acknowledgement
// contract (downlink_watch_apply.h): the pure decision extracted from
// downlink_watch_main. Red vs. the pre-fix behaviour: last_pushed was set
// before the Java call and its boolean answer/exception were ignored.
#include "downlink_watch_apply.h"

#include <cassert>
#include <cstdio>
#include <string>

static int failures = 0;

static void check(bool condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "downlink_watch_apply_test: FAILED: %s\n", what);
        failures++;
    }
}

int main() noexcept try {
    // A true answer without exception acknowledges the document.
    check(DownlinkWatchApply::acknowledged(false, false) == false,
          "applyDesiredSnapshot false must NOT acknowledge");
    check(DownlinkWatchApply::acknowledged(true, false) == true,
          "applyDesiredSnapshot true acknowledges only without exception");
    check(DownlinkWatchApply::acknowledged(true, true) == false,
          "thrown exception must NOT acknowledge even with a true answer");
    check(DownlinkWatchApply::acknowledged(false, true) == false,
          "false answer with exception must NOT acknowledge");

    // Empty never needs an attempt (the framer/snapshots have no document).
    check(DownlinkWatchApply::needs_attempt("", "") == false,
          "empty document needs no attempt");
    check(DownlinkWatchApply::needs_attempt("{}", "") == true,
          "fresh document needs an attempt");
    check(DownlinkWatchApply::needs_attempt("{}", "{}") == false,
          "already-pushed document needs no attempt");

    // Retry regression: an unacknowledged document must stay attemptable —
    // the pre-fix code committed last_pushed before the Java call, so this
    // needs_attempt would have returned false after a failing apply.
    std::string last_pushed;
    std::string document = "{\"generation\":9}";
    check(DownlinkWatchApply::needs_attempt(document, last_pushed),
          "fresh generation is attemptable");
    bool accepted = DownlinkWatchApply::acknowledged(false /*java false*/, false);
    if (accepted) {
        last_pushed = document; // only the acknowledged commit
    }
    check(DownlinkWatchApply::needs_attempt(document, last_pushed),
          "applyDesiredSnapshot=false must leave the same document retryable");

    if (failures == 0) {
        printf("downlink_watch_apply_test: all checks passed\n");
        return 0;
    }
    return 1;
}
catch (...) {
    return 1;
}
