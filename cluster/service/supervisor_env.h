#ifndef VBC_SUPERVISOR_ENV_H
#define VBC_SUPERVISOR_ENV_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VBC_SUPERVISOR_ENV_MAX_ENTRIES 128u
#define VBC_SUPERVISOR_ENV_MAX_BYTES 8192u
#define VBC_SUPERVISOR_ENV_MAX_STRING 1024u
#define VBC_SUPERVISOR_ENV_MAX_STAMP 128u
typedef struct {
    char *entries[VBC_SUPERVISOR_ENV_MAX_ENTRIES + 4u];
    char bytes[VBC_SUPERVISOR_ENV_MAX_BYTES];
} VbcSupervisorEnvStorage;
/* Pure bounded augmentation, not authentication or exec interposition. Inputs
 * must be readable C strings/a NULL-terminated vector within the stated bounds.
 * Storage must not alias any input. Caller owns its lifetime through execve.
 * Prepared paths must be absolute printable ASCII without whitespace/colon;
 * stamp uses ASCII letters, digits, '.', '_' or '-'. All are nonempty.
 * Only /usr/bin/{sysmgr,gauge,point,light} are targets. Controlled duplicates
 * (even identical), conflicting bootfile/stamp, malformed preload token lists,
 * or any bound failure return envp unchanged. NULL envp is an empty environment
 * for a valid target. Unrelated entries retain order and original pointers.
 * No heap, locks, globals with mutable state, syscalls or errno access.
 */
char *const *vbc_supervisor_env_prepare(const char *path, char *const envp[],
    const char *implant, const char *bootfile, const char *stamp,
    VbcSupervisorEnvStorage *storage);
#ifdef __cplusplus
}
#endif
#endif
