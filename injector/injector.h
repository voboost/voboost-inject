/*
 * injector.h — C-ABI contract for the ptrace injector.
 *
 * The daemon's sole extern "C" seam to the native layer. The daemon calls
 * vbi_inject(pid, so_path, init_sym, bootstrap_arg, pipe_fds, dlerr_out,
 * dlerr_out_sz) to inject a .so into a target process via ptrace. The injector
 * handles bitness detection, remote dlopen, and the explicit implant_init
 * remote-call (see injector-remote-execution spec).
 *
 * Return codes (consumed by daemon safety logic):
 * -12  — executed native loader timed out; CPU restoration and detach
 *         succeeded but loader unwind is unverified. No further remote
 *         calls (including cleanup/rebind) in this exact process lifetime.
 * -11  — register baseline deferred: no target memory/register changes were
 *         made in this invocation; bounded natural-stop attempts exhausted.
 *         Retryable on the same PID only after prior bootstrap cleanup.
 *   0  — success: .so loaded and init_sym called
 *  -1  — denied (ptrace ATTACH failed — permission or SELinux) [fatal: do not
 *         retry the same pid without a policy/permission change]
 *  -2  — target gone (process exited during injection) [retryable: the pid
 *         is dead; re-inject on the next live pid of this process]
 *  -3  — target linker load failed [fatal for this pid: a loader-level
 *         failure; retry on a fresh pid]. The optional dlerr_out begins with
 *         a stable phase such as namespace-api-unavailable,
 *         namespace-create-failed, namespace-link-failed or
 *         payload-load-failed.
 *  -4  — init failed (init_sym could not be resolved or called, OR the
 *         implant reported a hard agent-init failure via IMPLANT_INIT_FAILED)
 *         [fatal for this pid: the re-entry guard is set; do not retry this pid]
 *  -5  — bitness detection failed [fatal: target maps unreadable]
 *  -7  — identity mismatch: the stopped target's TGID/starttime, UID,
 *         SELinux context, argv[0] or executable differs from signed identity
 *  -8  — unsafe cleanup: the injector could not prove a stopped tracee,
 *         restore its saved registers, or detach cleanly. It never detaches a
 *         running tracee carrying the temporary remote-call frame.
 *  -6  — agent pending: the native payload loaded and implant_init ran, but
 *         the agent could not initialize yet because the host Application was
 *         not bound (early boot). Retryable on the SAME live PID; the daemon
 *         SHALL NOT mark the agent active on this code alone.
 *  -9  — resident rebound: no agent code was reloaded; fresh daemon-owned
 *         log/downlink endpoints were adopted from the already initialized
 *         implant and begin with an exact resident-identity frame.
 */
#ifndef VOBOOST_INJECTOR_H
#define VOBOOST_INJECTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vbi_agent_pipe_fds {
    int record_read_fd;
    int state_reply_fd;
};

/*
 * Inject a shared library into a target process via ptrace.
 *
 *   pid         — target process id
 *   so_path     — absolute path to the .so (e.g. libimplant.so)
 *   init_sym    — name of the entry symbol to remote-call after dlopen
 *                 (e.g. "implant_init"); pass NULL to skip the remote-call
 *   expect_argv0 — process name (argv[0]) the daemon selected this pid by;
 *                 re-verified after the PID's bounded thread-group inventory
 *                 is stopped and bound to one TGID/starttime. This is a
 *                 consistency check, not standalone target authority.
 *                 Missing or mismatched input returns -7.
 *   expect_starttime — exact daemon-observed leader starttime from
 *                 `/proc/<tgid>/stat`;
 *                 required and re-verified after the whole group is stopped.
 *                 Zero or mismatch returns -7 before remote mutation.
 *   expect_uid — fixed process-security UID; all four
 *                 `/proc/<tgid>/status` `Uid:` fields must match before remote
 *                 mutation. The daemon supplies Android user-0 UID 1000.
 *   expect_selinux_context — fixed process-security
 *                 `/proc/<tgid>/attr/current` context; the daemon supplies
 *                 `u:r:system_app:s0`. One trailing newline or NUL from
 *                 procfs is accepted.
 *   config_path  — passed as init_sym's first argument. One of:
 *                    @pipe-bootstrap-init  — bootstrap mode token (initial)
 *                    @pipe-bootstrap-load  — bootstrap mode token (reload)
 *                    <path>                — root-owned bootstrap descriptor
 *                                          path (daemon injector.rs passes a
 *                                          real filesystem path here)
 *                  pass NULL for none.
 *
 *   pipe_fds     — receives daemon-owned record-read and state-reply fds;
 *                 each field is -1 when that direction is unavailable
 *   dlerr_out   — optional caller-owned buffer (min 1 byte) that receives the
 *                 NUL-terminated phase-qualified remote linker error when
 *                 namespace loading fails
 *                 (return -3). The daemon logs it at ERROR via log.rs so the
 *                 real linker reason is surfaced without the injector logging
 *                 directly (per the agent-logging contract: the injector never
 *                 uses logcat — diagnostics ride return codes + out-params).
 *                 Pass NULL to skip. Untouched on non-dlopen failures/success.
 *   dlerr_out_sz — capacity of dlerr_out in bytes (0 when dlerr_out is NULL).
 *                  The written string is truncated to dlerr_out_sz-1 + NUL.
 *
 * Returns 0 on success, negative on error (see codes above).
 */
/* -10: owned bootstrap capsule staged; helper restore/detach still required. */
int vbi_inject(int pid, const char *so_path, const char *init_sym,
               const char *config_path, const char *expect_argv0, uint64_t expect_starttime,
               uint32_t expect_uid, const char *expect_selinux_context,
               struct vbi_agent_pipe_fds *pipe_fds,
               char *dlerr_out, size_t dlerr_out_sz);

#ifdef __cplusplus
}
#endif

#endif /* VOBOOST_INJECTOR_H */
