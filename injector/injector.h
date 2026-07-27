/*
 * injector.h — C-ABI contract for the ptrace injector.
 *
 * The daemon's sole extern "C" seam to the native layer. The daemon calls
 * vbi_inject(pid, so_path, init_sym, config_path) to inject a .so into a
 * target process via ptrace. The injector handles bitness detection, remote
 * dlopen, and the explicit implant_init remote-call (see native-payload spec).
 *
 * Return codes (consumed by daemon safety logic):
 *   0  — success: .so loaded and init_sym called
 *  -1  — denied (ptrace ATTACH failed — permission or SELinux)
 *  -2  — target gone (process exited during injection)
 *  -3  — dlopen failed (.so could not be loaded in target)
 *  -4  — init failed (init_sym could not be resolved or called)
 *  -5  — bitness detection failed
 */
#ifndef VOBOOST_INJECTOR_H
#define VOBOOST_INJECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Inject a shared library into a target process via ptrace.
 *
 *   pid         — target process id
 *   so_path     — absolute path to the .so (e.g. libimplant.so)
 *   init_sym    — name of the entry symbol to remote-call after dlopen
 *                 (e.g. "implant_init"); pass NULL to skip the remote-call
 *   config_path — channel-B config file path passed as init_sym's argument
 *                 (e.g. implant_init(const char *cfg)); pass NULL for none
 *
 * Returns 0 on success, negative on error (see codes above).
 */
int vbi_inject(int pid, const char *so_path, const char *init_sym,
                const char *config_path);

#ifdef __cplusplus
}
#endif

#endif /* VOBOOST_INJECTOR_H */
