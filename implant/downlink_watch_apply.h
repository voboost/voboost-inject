#pragma once

#include <string>

// Pure apply-acknowledgement decision for the resident downlink watcher.
// Extracted from downlink_watch_main so the transport/apply acknowledgement
// contract is testable on the host: a document counts as applied only when
// the Java upcall answered true without throwing. Otherwise the same
// document must be retried on the next wakeup (never silently dropped).
class DownlinkWatchApply {
public:
// Returns true when the apply attempt acknowledged the document and the
// watcher may commit it as last_pushed. A false answer or an exception
// leaves the previous push state untouched so the same document retries.
static bool acknowledged(bool java_accepted, bool java_threw) {
    return java_accepted && !java_threw;
}

// The watcher may skip the upcall when this document was already
// acknowledged as the last push.
static bool needs_attempt(const std::string &document,
                          const std::string &last_pushed) {
    return !document.empty() && document != last_pushed;
}
};
