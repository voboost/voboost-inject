#define EMBEDDED_PUBKEY_HEX                                                   \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0
#define main voboost_selinux_embedded_main
#include "../../selinux/voboost-selinux.c"
#undef main

#include <assert.h>
#include <sys/wait.h>

int main(void) {
    int blocked_stderr[2];
    assert(pipe(blocked_stderr) == 0);
    int flags = fcntl(blocked_stderr[1], F_GETFL, 0);
    assert(flags >= 0);
    assert(fcntl(blocked_stderr[1], F_SETFL, flags | O_NONBLOCK) == 0);
    char fill[4096] = {0};
    while (write(blocked_stderr[1], fill, sizeof(fill)) > 0) {
    }
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    assert(fcntl(blocked_stderr[1], F_SETFL, flags) == 0);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(dup2(blocked_stderr[1], STDERR_FILENO) == STDERR_FILENO);
        close(blocked_stderr[0]);
        close(blocked_stderr[1]);
        flockfile(stderr);
        assert(install_alarm_watchdog(1) == 0);
        for (;;) {
            pause();
        }
        _exit(99);
    }
    close(blocked_stderr[1]);

    int status = 0;
    for (int attempt = 0; attempt < 1000; attempt++) {
        pid_t result = waitpid(child, &status, WNOHANG);
        assert(result >= 0);
        if (result == child) {
            assert(WIFEXITED(status));
            assert(WEXITSTATUS(status) == 7);
            close(blocked_stderr[0]);
            return 0;
        }
        usleep(1000);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    close(blocked_stderr[0]);
    assert(!"watchdog handler did not terminate within one second");
}
