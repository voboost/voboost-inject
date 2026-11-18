#include "cache_quiescence_ack.h"
#include <cassert>
#include <string>
int main() {
    assert(CacheQuiescenceAck::may_apply(1, 1, "{}"));
    assert(!CacheQuiescenceAck::may_apply(1, 2, "{}"));
    assert(!CacheQuiescenceAck::may_apply(1, 1, ""));
    assert(!CacheQuiescenceAck::may_apply(1, 1, std::string(1025, 'a')));
    assert(CacheQuiescenceAck::may_ack(true, false, 1, 1, "{}", "{}"));
    assert(!CacheQuiescenceAck::may_ack(false, false, 1, 1, "{}", "{}"));
    assert(!CacheQuiescenceAck::may_ack(true, true, 1, 1, "{}", "{}"));
    assert(!CacheQuiescenceAck::may_ack(true, false, 1, 2, "{}", "{}"));
    assert(!CacheQuiescenceAck::may_ack(true, false, 1, 1, "{}", "{\"newer\":true}"));
}
