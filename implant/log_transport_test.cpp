#include "log_transport.h"
#include "sigpipe_safe_write.h"
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>

struct Sink {
    bool blocked = false;
    int error = EAGAIN;
    unsigned int attempts = 0;
    std::vector<std::string> records;
    bool operator()(const char *bytes, size_t size) {
        ++attempts;
        if (blocked) {
            errno = error;
            return false;
        }
        records.emplace_back(bytes, size);
        return true;
    }
};

static void submit(LogTransport &transport, Sink &sink, int level, const char *record) {
    transport.submit(level, 123, record, strlen(record),
                     [&](const char *bytes, size_t size) {
        return sink(bytes, size);
    });
}

int main() {
    {
        LogTransport transport;
        Sink sink;
        submit(transport, sink, 2, "L|10|launcher-apps|2|golden\n");
        assert(sink.records == std::vector<std::string>{"L|10|launcher-apps|2|golden\n"});
    }
    {
        LogTransport transport;
        Sink sink;
        sink.blocked = true;
        submit(transport, sink, 2, "info\n");
        submit(transport, sink, 1, "error\n");
        submit(transport, sink, 3, "debug\n");
        sink.blocked = false;
        submit(transport, sink, 3, "next-debug\n");
        assert(sink.records.size() == 4);
        assert(sink.records[0] == "error\n");
        assert(sink.records[1] == "info\n");
        assert(sink.records[2] ==
               "L|123|implant|1|log.transport.dropped error=0 info=0 debug=1\n");
        assert(sink.records[3] == "next-debug\n");
    }
    {
        LogTransport transport;
        Sink sink;
        sink.blocked = true;
        for (unsigned int i = 0; i < 10; ++i) {
            submit(transport, sink, 1, "error\n");
            submit(transport, sink, 2, "info\n");
        }
        submit(transport, sink, 3, "debug\n");
        sink.blocked = false;
        unsigned int before = sink.attempts;
        submit(transport, sink, 3, "debug\n");
        assert(sink.attempts - before == 4); // critical records precede receipts
        for (size_t i = 0; i < sink.records.size(); ++i) {
            assert(sink.records[i] == "error\n");
        }
        // The new debug was dropped because critical records remain queued.
        submit(transport, sink, 3, "debug\n");
        assert(sink.records.size() == 8);
        submit(transport, sink, 3, "debug\n");
        submit(transport, sink, 3, "debug\n");
        assert(sink.records[16] ==
               "L|123|implant|1|log.transport.dropped error=2 info=2 debug=4\n");
    }
    {
        for (int error : {EPIPE, EINTR, EAGAIN}) {
            LogTransport transport;
            Sink sink;
            sink.blocked = true;
            sink.error = error;
            submit(transport, sink, 1, "critical\n");
            assert(sink.attempts == 1); // no transport spin/retry loop
            sink.blocked = false;
            submit(transport, sink, 2, "info\n");
            assert(sink.records == std::vector<std::string>({"critical\n", "info\n"}));
        }
    }
    {
        LogTransport transport;
        Sink sink;
        sink.blocked = true;
        submit(transport, sink, 3, "lost\n");
        submit(transport, sink, 3, "lost-again\n");
        sink.blocked = false;
        submit(transport, sink, 2, "info\n");
        assert(sink.records[1] ==
               "L|123|implant|1|log.transport.dropped error=0 info=0 debug=2\n");
        sink.records.clear();
        submit(transport, sink, 2, "next\n");
        assert(sink.records == std::vector<std::string>{"next\n"});
    }
    {
        // Real kernel backpressure, independent of the injected test writer.
        int fds[2];
        assert(pipe(fds) == 0);
        assert(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
        assert(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
        char fill[4096]{};
        while (write(fds[1], fill, sizeof(fill)) > 0) {
        }
        // Fill the final partial page too (Darwin permits partial large writes).
        while (write(fds[1], fill, 1) > 0) {
        }
        assert(errno == EAGAIN);
        LogTransport transport;
        auto writer = [&](const char *bytes, size_t size) {
                          return sigpipe_safe_write(fds[1], bytes, size) == static_cast<ssize_t>(size);
                      };
        transport.submit(1, 123, "critical\n", 9, writer);
        transport.submit(3, 123, "debug\n", 6, writer);
        while (read(fds[0], fill, sizeof(fill)) > 0) {
        }
        transport.submit(2, 123, "info\n", 5, writer);
        std::string recovered;
        ssize_t count;
        while ((count = read(fds[0], fill, sizeof(fill))) > 0) {
            recovered.append(fill, static_cast<size_t>(count));
        }
        assert(recovered ==
               "critical\ninfo\n"
               "L|123|implant|1|log.transport.dropped error=0 info=0 debug=1\n");
        close(fds[0]);
        transport.submit(1, 123, "epipe\n", 6, writer); // SIGPIPE stays process-local-safe
        close(fds[1]);
    }
    {
        LogTransport transport;
        std::string critical(4096, 'x');
        bool blocked = true;
        unsigned int short_writes = 0;
        auto writer = [&](const char *, size_t size) {
                          if (size >= 4096 && blocked) {
                              return false;
                          }
                          if (size < 4096) {
                              ++short_writes;
                          }
                          return true;
                      };
        transport.submit(1, 123, critical.data(), critical.size(), writer);
        for (unsigned int i = 0; i < 100; ++i) {
            transport.submit(3, 123, "debug\n", 6, writer);
        }
        assert(short_writes == 0); // receipts cannot consume critical headroom
        blocked = false;
        transport.submit(3, 123, "debug\n", 6, writer);
        assert(short_writes == 2); // receipt plus current DEBUG, after critical
    }
    {
        LogTransport transport;
        Sink sink;
        sink.blocked = true;
        submit(transport, sink, 1, "old-error\n");
        submit(transport, sink, 2, "old-info\n");
        transport.abandon_pending();
        sink.blocked = false;
        submit(transport, sink, 2, "new-info\n");
        assert(sink.records == std::vector<std::string>({
            "new-info\n",
            "L|123|implant|1|log.transport.dropped error=1 info=1 debug=0\n"}));
    }
    return 0;
}
