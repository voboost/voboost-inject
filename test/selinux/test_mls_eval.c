/* test_mls_eval.c — kernel-style MLS constraint evaluation regression test.
 *
 * Evaluates the dir/file MLS constraints exactly the way the kernel's
 * security_compute_av does (RPN stack machine over constraint_expr_t),
 * before and after voboost_policy_inject on a real firmware policy dump.
 *
 * Guards the MLS fix: su (and voboost) must join mlstrustedsubject
 * constraint bitmaps, so the installer can chown/push into categorized
 * app_data_file, while MLS must stay enforced for everyone else.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/mls_types.h>
#include "policy_inject.h"

typedef struct { uint32_t type; mls_range_t r; } sctx;

static policydb_t *read_or_die(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2);}
    fseek(f,0,SEEK_END); long n = ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *buf = malloc(n); if (fread(buf,1,n,f) != (size_t)n) exit(2); fclose(f);
    policydb_t *p = calloc(1,sizeof(*p)); if (policydb_init(p)) exit(2);
    struct sepol_policy_file *spf = NULL; sepol_policy_file_create(&spf);
    sepol_policy_file_set_mem(spf,(char*)buf,n);
    if (policydb_read(p,(struct policy_file*)spf,0)) { fprintf(stderr,"FAIL: read\n"); exit(1);}
    return p;
}
static uint32_t tval(policydb_t *p, const char *n) {
    type_datum_t *d = hashtab_search(p->symtab[SYM_TYPES].table,(hashtab_key_t)n);
    return d ? d->s.value : 0;
}
static mls_level_t mk_level(policydb_t *p, const char **cats, unsigned ncats) {
    mls_level_t l; mls_level_init(&l);
    level_datum_t *sd = hashtab_search(p->symtab[SYM_LEVELS].table,(hashtab_key_t)"s0");
    l.sens = sd ? sd->level->sens : 1;
    for (unsigned i = 0; i < ncats; i++) {
        cat_datum_t *cd = hashtab_search(p->symtab[SYM_CATS].table,(hashtab_key_t)cats[i]);
        if (cd) ebitmap_set_bit(&l.cat, cd->s.value - 1, 1);
    }
    return l;
}
static int eval_expr(constraint_expr_t *head, sctx *s, sctx *t) {
    int stack[CEXPR_MAXDEPTH]; int sp = 0;
    for (constraint_expr_t *e = head; e; e = e->next) {
        switch (e->expr_type) {
        case CEXPR_NOT: stack[sp-1] = !stack[sp-1]; break;
        case CEXPR_AND: sp--; stack[sp-1] = stack[sp-1] && stack[sp]; break;
        case CEXPR_OR:  sp--; stack[sp-1] = stack[sp-1] || stack[sp]; break;
        case CEXPR_ATTR: {
            mls_level_t *l1, *l2; int a = e->attr;
            if (a & CEXPR_L1H1)      { l1=&s->r.level[0]; l2=&s->r.level[1]; }
            else if (a & CEXPR_L2H2) { l1=&t->r.level[0]; l2=&t->r.level[1]; }
            else if (a & CEXPR_H1L2) { l1=&s->r.level[1]; l2=&t->r.level[0]; }
            else if (a & CEXPR_L1H2) { l1=&s->r.level[0]; l2=&t->r.level[1]; }
            else if (a & CEXPR_H1H2) { l1=&s->r.level[1]; l2=&t->r.level[1]; }
            else                     { l1=&s->r.level[0]; l2=&t->r.level[0]; }
            int v;
            switch (e->op) {
            case CEXPR_EQ:   v = mls_level_eq(l1,l2); break;
            case CEXPR_NEQ:  v = !mls_level_eq(l1,l2); break;
            case CEXPR_DOM:  v = mls_level_dom(l1,l2); break;
            case CEXPR_DOMBY:v = mls_level_dom(l2,l1); break;
            default:         v = mls_level_incomp(l1,l2); break;
            }
            stack[sp++] = v; break;
        }
        case CEXPR_NAMES: {
            int a = e->attr, v = 0;
            if (a & CEXPR_TYPE) {
                uint32_t ty = (a & CEXPR_XTARGET) ? 0
                            : ((a & CEXPR_TARGET) ? t->type : s->type);
                v = ty ? ebitmap_get_bit(&e->names, ty - 1) : 0;
            } else {
                v = 1; /* single-user/role Android; not exercised here */
            }
            stack[sp++] = (e->op == CEXPR_EQ) ? v : !v;
            break;
        }
        default: stack[sp++] = 0;
        }
    }
    return sp ? stack[0] : 1;
}
static int check(policydb_t *p, const char *cls, const char *perm, sctx *s, sctx *t) {
    class_datum_t *c = hashtab_search(p->symtab[SYM_CLASSES].table,(hashtab_key_t)cls);
    if (!c) { fprintf(stderr,"FAIL: class %s\n", cls); exit(1); }
    perm_datum_t *pd = hashtab_search(c->permissions.table,(hashtab_key_t)perm);
    uint32_t pval;
    if (pd) pval = pd->s.value;
    else {
        // Perms inherited from the common (e.g. file's write/open) live in
        // the common datum and take bit values below the class-specific set.
        common_datum_t *cm = c->comkey ? hashtab_search(p->symtab[SYM_COMMONS].table, c->comkey) : NULL;
        perm_datum_t *cpd = cm ? hashtab_search(cm->permissions.table,(hashtab_key_t)perm) : NULL;
        if (!cpd) { fprintf(stderr,"FAIL: perm %s:%s\n", cls, perm); exit(1); }
        pval = cpd->s.value;
    }
    uint32_t pbit = 1u << (pval - 1);
    for (constraint_node_t *cn = c->constraints; cn; cn = cn->next)
        if ((cn->permissions & pbit) && !eval_expr(cn->expr, s, t))
            return 0;
    return 1;
}
struct case_t { const char *sty, *tty, *cls, *perm, *name;
                const char **sc; unsigned scn; const char **tc; unsigned tcn; int allow; };
static int run_cases(policydb_t *p, struct case_t *cs, unsigned n, const char *tag) {
    int fails = 0;
    for (unsigned i = 0; i < n; i++) {
        struct case_t *c = &cs[i];
        uint32_t sv = tval(p, c->sty), tv = tval(p, c->tty);
        if (!sv || !tv) { printf("FAIL %-52s type missing\n", c->name); fails++; continue; }
        sctx s = { .type = sv };
        s.r.level[0] = s.r.level[1] = mk_level(p, c->sc, c->scn);
        sctx t = { .type = tv };
        t.r.level[0] = t.r.level[1] = mk_level(p, c->tc, c->tcn);
        int got = check(p, c->cls, c->perm, &s, &t);
        printf("%s %-49s %s\n", got == c->allow ? "ok:" : "FAIL:", c->name,
               got ? "ALLOWED" : "DENIED");
        if (got != c->allow) fails++;
    }
    (void)tag;
    return fails;
}
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr,"usage: %s <policy.bin>\n", argv[0]); return 2; }
    policydb_t *p = read_or_die(argv[1]);
    const char *appcats[] = {"c55","c256","c512","c768"};
    const char *miscats[] = {"c1","c2"};
    struct case_t raw[] = {
        {"su","app_data_file","dir","open","su:s0 -> appdir cats {open} (observed denial)",NULL,0,appcats,4,0},
        {"su","app_data_file","dir","search","su:s0 -> appdir cats {search}",NULL,0,appcats,4,0},
        {"untrusted_app","app_data_file","dir","open","untrusted mismatched cats {open}",miscats,2,appcats,4,0},
        {"untrusted_app","app_data_file","dir","open","untrusted same cats {open}",appcats,4,appcats,4,1},
    };
    int fails = run_cases(p, raw, sizeof(raw)/sizeof(raw[0]), "raw");
    if (voboost_policy_inject(p)) { fprintf(stderr,"FAIL: inject\n"); return 1; }
    if (voboost_policy_inject(p)) { fprintf(stderr,"FAIL: second inject\n"); return 1; }
    struct case_t inj[] = {
        {"su","voboost_uninstall_result_file","file","read","root admission observer -> result {read}",NULL,0,NULL,0,1},
        {"su","voboost_uninstall_result_file","file","open","root admission observer -> result {open}",NULL,0,NULL,0,1},
        {"su","voboost_uninstall_result_file","file","getattr","root admission observer -> result {getattr}",NULL,0,NULL,0,1},
        {"voboost","voboost_uninstall_result_file","file","read","resident result producer -> result {read}",NULL,0,NULL,0,1},
        {"voboost","voboost_uninstall_result_file","file","write","resident result producer -> result {write}",NULL,0,NULL,0,1},
        {"voboost_relabel","voboost_uninstall_result_file","file","read","init relabel reader -> result {read}",NULL,0,NULL,0,1},
        {"voboost_uninstall","voboost_uninstall_result_file","file","unlink","terminal uninstaller -> result {unlink}",NULL,0,NULL,0,1},
        {"su","app_data_file","dir","open","su:s0 -> appdir cats {open} after inject",NULL,0,appcats,4,1},
        {"su","app_data_file","dir","search","su:s0 -> appdir cats {search} after inject",NULL,0,appcats,4,1},
        {"su","app_data_file","file","open","su:s0 -> appfile cats {open} after inject",NULL,0,appcats,4,1},
        {"untrusted_app","app_data_file","dir","open","untrusted mismatched cats {open} after inject",miscats,2,appcats,4,0},
        {"untrusted_app","app_data_file","dir","open","untrusted same cats {open} after inject",appcats,4,appcats,4,1},
        {"untrusted_app","voboost_ota_socket","unix_stream_socket","connectto",
         "app cats -> OTA socket s0 {connectto}",appcats,4,NULL,0,1},
        {"shell","app_data_file","dir","open","shell (fw mlstrustedsubject) {open} after inject",NULL,0,appcats,4,1},
        {"voboost","app_data_file","dir","open","voboost:s0 -> appdir cats {open} after inject",NULL,0,appcats,4,1},
        {"voboost_relabel","app_data_file","dir","open","voboost_relabel:s0 -> appdir cats {open} after inject",NULL,0,appcats,4,1},
        // Process access is narrowed by TE, not MLS: voboost must remain an
        // mlstrustedsubject so it can consume categorized incoming staging.
        // The real-policy effective-AV test separately proves that only
        // system_app receives the target-labeled procfs and ptrace allows.
        {"voboost","system_app","file","read","voboost:s0 -> system_app:s0 proc file {read}",NULL,0,NULL,0,1},
        {"voboost","system_app","dir","search","voboost:s0 -> system_app:s0 proc dir {search}",NULL,0,NULL,0,1},
        {"voboost","untrusted_app","file","read","MLS alone permits trusted voboost -> categorized unrelated proc file",NULL,0,appcats,4,1},
        // Regression boundary: losing the app categories from
        // generations/next makes staging fail under the real MLS constraints.
        {"untrusted_app","voboost_incoming_file","dir","write","app cats -> incoming dir s0 {write} (range loss)",appcats,4,NULL,0,0},
        {"untrusted_app","voboost_incoming_file","dir","add_name","app cats -> incoming dir s0 {add_name} (range loss)",appcats,4,NULL,0,0},
        {"untrusted_app","voboost_incoming_file","file","write","app cats -> incoming file s0 {write} (range loss)",appcats,4,NULL,0,0},
        {"shell","voboost_incoming_file","dir","write","shell -> incoming dir {write} after inject",NULL,0,NULL,0,1},
        // MLS stays enforced for everyone else on the incoming type too.
        {"untrusted_app","voboost_incoming_file","dir","write","app miscats -> incoming dir {write} after inject",miscats,2,NULL,0,0},
        // The descriptor-bound relabel preserves these categories, so the
        // app's write is l1 == l2 and the daemon (voboost, s0) can still
        // read/consume what the app staged.
        {"untrusted_app","voboost_incoming_file","dir","write","app cats -> incoming dir cats {write} after inject",appcats,4,appcats,4,1},
        {"untrusted_app","voboost_incoming_file","file","write","app cats -> incoming file cats {write} after inject",appcats,4,appcats,4,1},
        {"voboost","voboost_incoming_file","dir","search","voboost:s0 -> incoming dir cats {search} after inject",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","dir","read","voboost:s0 -> incoming dir cats {read} after inject",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","file","read","voboost:s0 -> incoming file cats {read} after inject",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","file","open","voboost:s0 -> incoming file cats {open} after inject",NULL,0,appcats,4,1},
        // Daemon consumes the staged generation: rename/unlink inside the
        // app-categories-labeled next/ tree (activation + cleanup).
        {"voboost","voboost_incoming_file","dir","write","voboost:s0 -> incoming dir cats {write} (activate)",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","dir","add_name","voboost:s0 -> incoming dir cats {add_name} (activate)",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","dir","remove_name","voboost:s0 -> incoming dir cats {remove_name} (cleanup)",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","file","rename","voboost:s0 -> incoming file cats {rename} (activate)",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","file","unlink","voboost:s0 -> incoming file cats {unlink} (cleanup)",NULL,0,appcats,4,1},
        {"voboost","voboost_incoming_file","file","setattr","voboost:s0 -> incoming file cats {setattr} (activate)",NULL,0,appcats,4,1},
    };
    fails += run_cases(p, inj, sizeof(inj)/sizeof(inj[0]), "injected");
    if (fails) { fprintf(stderr,"test_mls_eval: %d FAILURES\n", fails); return 1; }
    printf("test_mls_eval: OK\n");
    return 0;
}
