#ifndef VBC_SUPERVISOR_EXEC_H
#define VBC_SUPERVISOR_EXEC_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { const char *implant, *bootfile, *stamp; } VbcSupervisorDeliveryValues;
int vbc_supervisor_current(VbcSupervisorDeliveryValues *out);
int vbc_supervisor_exec_set_original(void *original);
int vbc_supervisor_execve(const char *path, char *const argv[], char *const envp[]);
#ifdef __cplusplus
}
#endif
#endif
