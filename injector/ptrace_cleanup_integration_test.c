#define _GNU_SOURCE
#include <stdio.h>

#if defined(__linux__)
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
                             fprintf(stderr, "check failed at line %d: %s (errno=%d)\n", \
                                     __LINE__, #expr, errno); return 1; \
                         } } while (0)

struct process_ids {
    pid_t controller;
    pid_t helper;
    pid_t tracee;
};

static int wait_stopped_bounded(pid_t child, int *status) {
    for (int elapsed_ms = 0; elapsed_ms < 3000; elapsed_ms += 5) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) {
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

static int helper_main(pid_t controller, pid_t tracee, int ready_fd, int result_fd,
                       int seam) {
#if defined(__x86_64__)
    int status = 0;
    if (ptrace(PTRACE_ATTACH, tracee, NULL, NULL) != 0
        || wait_stopped_bounded(tracee, &status) != 0) {
        return 10;
    }
    struct user_regs_struct original;
    struct user_regs_struct temporary;
    if (ptrace(PTRACE_GETREGS, tracee, NULL, &original) != 0) {
        return 11;
    }
    temporary = original;
    if (seam == 64) {
        temporary.rip = 0;
        temporary.rsp -= 256U;
        temporary.rax ^= 0x55aaU;
    } else {
        temporary.rip = 0;
        temporary.rsp -= 256U;
        temporary.rbx ^= 0xaa55U;
    }
    if (ptrace(PTRACE_SETREGS, tracee, NULL, &temporary) != 0) {
        return 12;
    }
    if (ptrace(PTRACE_CONT, tracee, NULL, NULL) != 0
        || wait_stopped_bounded(tracee, &status) != 0
        || WSTOPSIG(status) != SIGSEGV) {
        return 18;
    }
    char ready = 'R';
    if (write(ready_fd, &ready, 1) != 1) {
        return 13;
    }
    while (getppid() == controller) {
        struct timespec delay = {0, 5L * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
    if (ptrace(PTRACE_SETREGS, tracee, NULL, &original) != 0) {
        return 14;
    }
    struct user_regs_struct restored;
    if (ptrace(PTRACE_GETREGS, tracee, NULL, &restored) != 0
        || memcmp(&restored, &original, sizeof(original)) != 0) {
        return 15;
    }
    if (ptrace(PTRACE_DETACH, tracee, NULL, NULL) != 0) {
        return 16;
    }
    char result = 'D';
    if (write(result_fd, &result, 1) != 1) {
        return 17;
    }
#else
    (void)controller;
    (void)tracee;
    (void)ready_fd;
    (void)result_fd;
    (void)seam;
#endif
    return 0;
}

static int exercise_parent_death_seam(int seam) {
#if defined(__x86_64__)
    int ids_pipe[2];
    int ready_pipe[2];
    int result_pipe[2];
    CHECK(pipe(ids_pipe) == 0);
    CHECK(pipe(ready_pipe) == 0);
    CHECK(pipe(result_pipe) == 0);
    pid_t controller = fork();
    CHECK(controller >= 0);
    if (controller == 0) {
        close(ids_pipe[0]);
        close(ready_pipe[0]);
        close(result_pipe[0]);
        int tracee_ready[2];
        if (pipe(tracee_ready) != 0) {
            _exit(19);
        }
        pid_t tracee = fork();
        if (tracee == 0) {
            close(tracee_ready[0]);
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
            char ready = 'T';
            if (write(tracee_ready[1], &ready, 1) != 1) {
                _exit(18);
            }
            for (;;) {
                pause();
            }
        }
        if (tracee < 0) {
            _exit(20);
        }
        close(tracee_ready[1]);
        char tracee_signal = 0;
        if (read(tracee_ready[0], &tracee_signal, 1) != 1 || tracee_signal != 'T') {
            _exit(23);
        }
        close(tracee_ready[0]);
        pid_t helper = fork();
        if (helper == 0) {
            close(ids_pipe[1]);
            _exit(helper_main(getppid(), tracee, ready_pipe[1], result_pipe[1], seam));
        }
        if (helper < 0) {
            _exit(21);
        }
        struct process_ids ids = { getpid(), helper, tracee };
        if (write(ids_pipe[1], &ids, sizeof(ids)) != sizeof(ids)) {
            _exit(22);
        }
        for (;;) {
            pause();
        }
    }
    close(ids_pipe[1]);
    close(ready_pipe[1]);
    close(result_pipe[1]);
    struct process_ids ids;
    CHECK(read(ids_pipe[0], &ids, sizeof(ids)) == sizeof(ids));
    char value = 0;
    CHECK(read(ready_pipe[0], &value, 1) == 1 && value == 'R');
    CHECK(kill(ids.controller, SIGKILL) == 0);
    int status = 0;
    CHECK(waitpid(ids.controller, &status, 0) == ids.controller);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    CHECK(read(result_pipe[0], &value, 1) == 1 && value == 'D');
    CHECK(kill(ids.tracee, 0) == 0);
    CHECK(kill(ids.tracee, SIGKILL) == 0);
#else
    (void)seam;
#endif
    return 0;
}

int main(void) {
    CHECK(exercise_parent_death_seam(64) == 0);
    CHECK(exercise_parent_death_seam(32) == 0);
    return 0;
}
#else
int main(void) {
    fprintf(stderr, "SKIP: ptrace parent-death integration requires Linux\n");
    return 77;
}
#endif
