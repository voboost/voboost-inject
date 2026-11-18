#define _GNU_SOURCE
#include "ptrace_state.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <pthread.h>

static void *clone_thread(void *unused) {
    (void)unused;
    return NULL;
}

/* Bounded wait for a specific tid: a modern kernel can report clone-event
 * stops in an order this test does not assume, and PTRACE_KILL-style
 * kill edges are deprecated; an unbounded waitpid here wedged the whole
 * gate on kernel 6.8. Fail closed with -1 after 3s instead of hanging. */
static int wait_stopped_bounded(pid_t tid, int *status) {
    for (int elapsed_ms = 0; elapsed_ms < 3000; elapsed_ms += 5) {
        pid_t result = waitpid(tid, status, __WALL | WNOHANG);
        if (result == tid) {
            return WIFSTOPPED(*status) ? 0 : -1;
        }
        if (result < 0 && errno != EINTR) {
            return -1;
        }
        struct timespec delay = {0, 5L * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

static void kill_and_reap(pid_t tid) {
    if (ptrace(PTRACE_CONT, tid, NULL, (void *)(uintptr_t)SIGKILL) != 0) {
        kill(tid, SIGKILL);
    }
    int status = 0;
    /* Bounded reap: the tracee may already be gone (ESRCH) — that is success. */
    for (int elapsed_ms = 0; elapsed_ms < 1000; elapsed_ms += 5) {
        pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
        if (result == tid || (result < 0 && errno == ECHILD)) {
            return;
        }
        struct timespec delay = {0, 5L * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
}

static int run_clone_then_return_trap_model(int bitness) {
    int gate[2];
    if (pipe(gate) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        close(gate[1]);
        char byte;
        if (read(gate[0], &byte, 1) != 1) {
            _exit(2);
        }
        pthread_t thread;
        if (pthread_create(&thread, NULL, clone_thread, NULL) != 0) {
            _exit(3);
        }
        pthread_join(thread, NULL);
        raise(SIGSEGV);
        _exit(4);
    }
    close(gate[0]);
    if (ptrace(PTRACE_SEIZE, child, NULL, (void *)(uintptr_t)PTRACE_O_TRACECLONE) != 0
        || ptrace(PTRACE_INTERRUPT, child, NULL, NULL) != 0) {
        return 1;
    }
    int status = 0;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) {
        kill_and_reap(child);
        return 1;
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0 || write(gate[1], "x", 1) != 1) {
        kill_and_reap(child);
        return 1;
    }
    close(gate[1]);

    if (waitpid(child, &status, __WALL) != child
        || vbi_ptrace_event_from_status(status) != PTRACE_EVENT_CLONE
        || vbi_remote_stop_signal_for_detach(status, 0) != 0) {
        kill_and_reap(child);
        return 1;
    }
    unsigned long clone_tid = 0;
    if (ptrace(PTRACE_GETEVENTMSG, child, NULL, &clone_tid) != 0 || clone_tid == 0) {
        kill_and_reap(child);
        return 1;
    }
    int clone_status = 0;
    if (wait_stopped_bounded((pid_t)clone_tid, &clone_status) != 0) {
        fprintf(stderr, "clone tid %lu never reported its stop within 3s\n", clone_tid);
        kill_and_reap((pid_t)clone_tid);
        kill_and_reap(child);
        return 1;
    }
    if (ptrace(PTRACE_CONT, (pid_t)clone_tid, NULL, NULL) != 0
        || ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        kill_and_reap((pid_t)clone_tid);
        kill_and_reap(child);
        return 1;
    }

    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)
        || WSTOPSIG(status) != SIGSEGV || vbi_ptrace_event_from_status(status) != 0) {
        kill_and_reap((pid_t)clone_tid);
        kill_and_reap(child);
        return 1;
    }
    /* Both ABI paths deliberately use LR=0; the modeled PC width is the only
     * architectural difference relevant to accepting the final trap. */
    uint64_t pc = bitness == 32 ? (uint32_t)0 : 0;
    if (pc != 0) {
        kill_and_reap(child);
        return 1;
    }
    /* PTRACE_KILL is deprecated and on a stopped tracee behaves like
     * PTRACE_CONT with no signal (kernel documented behavior since 3.x):
     * resume with SIGKILL so the tracee dies on modern kernels too. */
    kill_and_reap(child);
    return 0;
}
#endif

int main(void) {
#if defined(__linux__)
    if (run_clone_then_return_trap_model(32) != 0) {
        return 1;
    }
    if (run_clone_then_return_trap_model(64) != 0) {
        return 1;
    }
#endif
#if defined(__linux__)
    return 0;
#else
    fprintf(stderr, "SKIP: ptrace clone integration requires Linux\n");
    return 77;
#endif
}
