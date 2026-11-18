#include "../service/supervisor_env.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char implant[] = "/persist/voboost/bin/libvoboost-cluster-inject.so";
static const char bootfile[] = "/persist/voboost/config/cluster.json";
static const char stamp[] = "abc123-def456";
static char *const *prepare(const char *path, char *const env[], VbcSupervisorEnvStorage *out) {
    return vbc_supervisor_env_prepare(path,env,implant,bootfile,stamp,out);
}
static const char *value(char *const *env, const char *key) {
    size_t i, n = strlen(key);
    for (i = 0; env && env[i]; ++i) if (!strncmp(env[i],key,n)) return env[i]+n;
    return NULL;
}
static size_t count(char *const *env) {
    size_t n = 0;
    while (env && env[n]) ++n;
    return n;
}
static void targets_and_unrelated_entries(void) {
    const char *paths[] = {"/usr/bin/sysmgr","/usr/bin/gauge","/usr/bin/point","/usr/bin/light"};
    char unrelated[] = "SAME=original";
    char *env[] = {unrelated,"PATH=/usr/bin",NULL};
    size_t i;
    for (i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        VbcSupervisorEnvStorage out;
        errno = EDOM;
        char *const *got = prepare(paths[i],env,&out);
        assert(errno == EDOM);
        assert(got != env && count(got) == 5 && got[0] == unrelated && got[1] == env[1]);
        assert(!strcmp(value(got,"LD_PRELOAD="),implant));
        assert(!strcmp(value(got,"VOBOOST_CLUSTER_BOOTFILE="),bootfile));
        assert(!strcmp(value(got,"VOBOOST_CLUSTER_SUPERVISOR="),stamp));
        assert(env[0] == unrelated && !strcmp(unrelated,"SAME=original") && env[2] == NULL);
    }
    {
        VbcSupervisorEnvStorage out;
        const char *other[] = {"/usr/bin/gauge.backup","gauge","/tmp/gauge","/usr/bin/../bin/gauge","/usr/bin/clusterboot",""};
        for (i = 0; i < sizeof(other)/sizeof(other[0]); ++i) assert(prepare(other[i],env,&out) == env);
        assert(prepare(NULL,env,&out) == env);
        assert(prepare("/usr/bin/gauge",env,NULL) == env);
    }
}
static void missing_empty_and_existing_values(void) {
    VbcSupervisorEnvStorage out;
    char *empty[] = {NULL};
    char *const *got = prepare("/usr/bin/gauge",NULL,&out);
    assert(got != NULL && count(got) == 3);
    got = prepare("/usr/bin/gauge",empty,&out);
    assert(got != empty && count(got) == 3);
    {
        char existing[] = "LD_PRELOAD=/lib/a.so:relative.so";
        char *env[] = {existing,"OTHER=value",NULL};
        char expected[256];
        got = prepare("/usr/bin/gauge",env,&out);
        assert(got != env && count(got) == 4 && got[1] == env[1]);
        assert(snprintf(expected,sizeof(expected),"/lib/a.so:relative.so:%s",implant) > 0);
        assert(!strcmp(value(got,"LD_PRELOAD="),expected));
        assert(!strcmp(existing,"LD_PRELOAD=/lib/a.so:relative.so"));
    }
    {
        char ld[256], boot[256], supervisor[256];
        char *env[] = {ld,boot,supervisor,NULL};
        snprintf(ld,sizeof(ld),"LD_PRELOAD=/lib/a.so:%s:/lib/b.so",implant);
        snprintf(boot,sizeof(boot),"VOBOOST_CLUSTER_BOOTFILE=%s",bootfile);
        snprintf(supervisor,sizeof(supervisor),"VOBOOST_CLUSTER_SUPERVISOR=%s",stamp);
        got = prepare("/usr/bin/sysmgr",env,&out);
        assert(got != env && count(got) == 3 && got[0] == ld && got[1] == boot && got[2] == supervisor);
        assert(prepare("/usr/bin/gauge",got,&out) == got); /* Same output vector refuses aliasing. */
    }
}
static void conflicts_and_duplicate_variables(void) {
    VbcSupervisorEnvStorage out;
    char *cases[][4] = {
        {"LD_PRELOAD=a","LD_PRELOAD=a",NULL,NULL},
        {"LD_PRELOAD=a","LD_PRELOAD=b",NULL,NULL},
        {"VOBOOST_CLUSTER_BOOTFILE=/other",NULL,NULL,NULL},
        {"VOBOOST_CLUSTER_SUPERVISOR=other",NULL,NULL,NULL},
        {"LD_PRELOAD=",NULL,NULL,NULL},
        {"LD_PRELOAD=:a",NULL,NULL,NULL},
        {"LD_PRELOAD=a:",NULL,NULL,NULL},
        {"LD_PRELOAD=a::b",NULL,NULL,NULL},
        {"LD_PRELOAD=a b",NULL,NULL,NULL},
    };
    size_t i;
    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
        assert(prepare("/usr/bin/gauge",cases[i],&out) == cases[i]);
    {
        char boot[256], supervisor[256], duplicate_ld[256];
        char *boots[] = {boot,boot,NULL};
        char *stamps[] = {supervisor,supervisor,NULL};
        char *ld[] = {duplicate_ld,NULL};
        snprintf(boot,sizeof(boot),"VOBOOST_CLUSTER_BOOTFILE=%s",bootfile);
        snprintf(supervisor,sizeof(supervisor),"VOBOOST_CLUSTER_SUPERVISOR=%s",stamp);
        snprintf(duplicate_ld,sizeof(duplicate_ld),"LD_PRELOAD=%s:%s",implant,implant);
        assert(prepare("/usr/bin/gauge",boots,&out) == boots);
        assert(prepare("/usr/bin/gauge",stamps,&out) == stamps);
        assert(prepare("/usr/bin/gauge",ld,&out) == ld);
    }
}
static void bounds_and_prepared_strings(void) {
    VbcSupervisorEnvStorage out;
    char long_string[VBC_SUPERVISOR_ENV_MAX_STRING+2];
    char *long_env[] = {long_string,NULL};
    char *too_many[VBC_SUPERVISOR_ENV_MAX_ENTRIES+2];
    char *empty[] = {NULL};
    size_t i;
    memset(long_string,'a',sizeof(long_string)-1); long_string[sizeof(long_string)-1] = 0;
    assert(prepare("/usr/bin/gauge",long_env,&out) == long_env);
    for (i = 0; i <= VBC_SUPERVISOR_ENV_MAX_ENTRIES; ++i) too_many[i] = "A=B";
    too_many[i] = NULL;
    assert(prepare("/usr/bin/gauge",too_many,&out) == too_many);
    too_many[VBC_SUPERVISOR_ENV_MAX_ENTRIES] = NULL;
    assert(prepare("/usr/bin/gauge",too_many,&out) != too_many);
    for (i = 0; i < 8; ++i) too_many[i] = long_string;
    long_string[VBC_SUPERVISOR_ENV_MAX_STRING] = 0;
    too_many[8] = NULL;
    assert(prepare("/usr/bin/gauge",too_many,&out) == too_many);
    {
        char near_limit[901];
        memset(near_limit,'b',sizeof(near_limit)-1); near_limit[sizeof(near_limit)-1] = 0;
        for (i = 0; i < 7; ++i) too_many[i] = long_string;
        too_many[7] = near_limit; too_many[8] = NULL;
        /* Input fits 8192 bytes; the appended control values would exceed it. */
        assert(prepare("/usr/bin/gauge",too_many,&out) == too_many);
    }
    {
        char full_ld[VBC_SUPERVISOR_ENV_MAX_STRING+1];
        char *env[] = {full_ld,NULL};
        memset(full_ld,'a',sizeof(full_ld)-1); full_ld[sizeof(full_ld)-1] = 0;
        memcpy(full_ld,"LD_PRELOAD=",11);
        assert(prepare("/usr/bin/gauge",env,&out) == env); /* Appending exceeds bound. */
    }
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,"relative",bootfile,stamp,&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,"/bad:path",bootfile,stamp,&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,implant,"/bad path",stamp,&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,implant,bootfile,"bad=stamp",&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,NULL,bootfile,stamp,&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,implant,bootfile,"",&out) == empty);
    assert(vbc_supervisor_env_prepare("/usr/bin/gauge",empty,implant,bootfile,long_string,&out) == empty);
}
int main(void) {
    targets_and_unrelated_entries();
    missing_empty_and_existing_values();
    conflicts_and_duplicate_variables();
    bounds_and_prepared_strings();
    puts("supervisor_env PASS");
    return 0;
}
