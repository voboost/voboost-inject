/* policy_inject.h — inject the generated voboost rules into a policydb.
 *
 * All symbols are resolved by NAME at runtime against the firmware policy;
 * missing non-voboost symbols (e.g. untrusted_app_29 on an Android 9 base)
 * are skipped with a kmsg note, missing voboost symbols are a hard error
 * (they are created by inject_types first).
 */
#ifndef VOBOOST_POLICY_INJECT_H
#define VOBOOST_POLICY_INJECT_H

#include <sepol/policydb/policydb.h>

/* Returns 0 on success (or already-applied), nonzero on failure. */
int voboost_policy_applied(policydb_t *pdb);
int voboost_policy_inject(policydb_t *pdb);

/* Returns 1 only if the candidate retains all previous concrete type names. */
int voboost_policy_preserves_types(const policydb_t *candidate,
                                   const policydb_t *previous);

#endif /* VOBOOST_POLICY_INJECT_H */
