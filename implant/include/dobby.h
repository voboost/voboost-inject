/*
 * dobby.h — Dobby inline-hook API (subset used by the implant).
 *
 * The full Dobby header lives in the Dobby source; this is a minimal forward
 * declaration for the symbols the dobby_adapter links against.
 */
#ifndef DOBBY_H
#define DOBBY_H

#ifdef __cplusplus
extern "C" {
#endif

int DobbyHook(void *address, void *replace_call, void **origin_call);
int DobbyDestroy(void *address);

#ifdef __cplusplus
}
#endif

#endif /* DOBBY_H */
