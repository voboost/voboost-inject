/* policy_inject.c — inject the generated voboost rules into a binary policydb.
 *
 * Mechanism (expanded-policy mutation, the libsepol-native path):
 *   - new types via hashtab_insert into p_types + type_val_to_struct +
 *     type_attr_map/attr_type_map ebitmaps (attribute membership = bits);
 *   - the new domain is added to the role held by `init`;
 *   - allow rules via avtab_insert (AVTAB_ALLOWED);
 *   - process transition init -> voboost_exec -> voboost via avtab
 *     (AVTAB_TRANSITION);
 *   - the filename transition for "generations" via the filename_trans list.
 *
 * Non-voboost symbols that do not exist in the firmware policy are skipped
 * (expected across Android versions); voboost symbols are created by
 * inject_types() before any rule references them.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "policy_inject.h"
#include "rules.gen.h"

static void klog(const char *fmt, ...);

#include <stdarg.h>
static void klog(const char *fmt, ...)
{
    (void)fmt;
}

/* --- symbol lookup helpers ------------------------------------------- */

static type_datum_t *lookup_type(policydb_t *pdb, const char *name)
{
    return (type_datum_t *)hashtab_search(pdb->symtab[SYM_TYPES].table,
                                          (const hashtab_key_t)name);
}

static uint32_t type_value(policydb_t *pdb, const char *name)
{
    type_datum_t *d = lookup_type(pdb, name);
    return d ? d->s.value : 0; /* 0 = absent */
}

static class_datum_t *lookup_class(policydb_t *pdb, const char *name)
{
    return (class_datum_t *)hashtab_search(pdb->symtab[SYM_CLASSES].table,
                                           (const hashtab_key_t)name);
}

/* --- type creation ---------------------------------------------------- */

static int ensure_type_attr_arrays(policydb_t *pdb, unsigned wanted_nprim)
{
    unsigned nprim = pdb->symtab[SYM_TYPES].nprim;
    if (wanted_nprim == 0 || wanted_nprim < nprim) {
        return -1;
    }
    if (wanted_nprim == nprim) {
        return 0; /* arrays already cover the existing types */
    }
    nprim = wanted_nprim;

    ebitmap_t *tam = realloc(pdb->type_attr_map, nprim * sizeof(ebitmap_t));
    if (!tam) {
        return -1;
    }
    pdb->type_attr_map = tam;
    ebitmap_t *atm = realloc(pdb->attr_type_map, nprim * sizeof(ebitmap_t));
    if (!atm) {
        return -1;
    }
    pdb->attr_type_map = atm;

    type_datum_t **tvs =
        (type_datum_t **)realloc((void *)pdb->type_val_to_struct, nprim * sizeof(type_datum_t *));
    if (!tvs) {
        return -1;
    }
    pdb->type_val_to_struct = tvs;

    /* New slots are at indices >= previous nprim; the arrays are reused
     * across patches, so only initialize slots that are still zero-meaning
     * (ebitmap_start with empty map). We re-init every slot defensively only
     * for freshly added values tracked by the caller. */
    return 0;
}

/* Create one type with the given attributes; returns its 1-based value. */
static uint32_t create_type(policydb_t *pdb, const char *name,
                            unsigned *created_count)
{
    uint32_t existing = type_value(pdb, name);
    if (existing) {
        return existing;
    }

    if (ensure_type_attr_arrays(pdb, pdb->symtab[SYM_TYPES].nprim + 1) != 0) {
        return 0;
    }

    type_datum_t *t = calloc(1, sizeof(*t));
    if (!t) {
        return 0;
    }
    t->flavor = TYPE_TYPE;
    t->primary = 1;
    t->s.value = pdb->symtab[SYM_TYPES].nprim + 1;
    if (hashtab_insert(pdb->symtab[SYM_TYPES].table,
                       (hashtab_key_t)strdup(name),
                       (hashtab_datum_t)t) != 0) {
        free(t);
        return 0;
    }
    pdb->symtab[SYM_TYPES].nprim = t->s.value;
    unsigned idx = t->s.value - 1;
    pdb->type_val_to_struct[idx] = t;
    ebitmap_init(&pdb->type_attr_map[idx]);
    ebitmap_init(&pdb->attr_type_map[idx]);
    /* Expanded policies always include the self bit. */
    ebitmap_set_bit(&pdb->type_attr_map[idx], idx, 1);
    ebitmap_set_bit(&pdb->attr_type_map[idx], idx, 1);
    (*created_count)++;
    return t->s.value;
}

/* Set attribute membership bits for a 1-based type value. */
static int set_attr(policydb_t *pdb, uint32_t tval, const char *attr_name)
{
    uint32_t aval = type_value(pdb, attr_name);
    if (!aval) {
        klog("attribute %s missing in firmware policy; skipped", attr_name);
        return 0; /* skip, not fatal */
    }
    ebitmap_set_bit(&pdb->type_attr_map[tval - 1], aval - 1, 1);
    ebitmap_set_bit(&pdb->attr_type_map[aval - 1], tval - 1, 1);
    return 0;
}

/* Add the domain to the role that holds init's type (Android: role "r"). */
static int add_to_init_role(policydb_t *pdb, uint32_t tval)
{
    role_datum_t *role = (role_datum_t *)hashtab_search(
        pdb->symtab[SYM_ROLES].table, (const hashtab_key_t)"r");
    if (!role) {
        /* Fall back to the role of any existing type (single-role Android). */
        if (pdb->symtab[SYM_ROLES].nprim < 1) {
            return -1;
        }
        role = pdb->role_val_to_struct[0];
    }
    if (!role) {
        return -1;
    }
    ebitmap_set_bit(&role->types.types, tval - 1, 1);
    return 0;
}

/* --- permission bits --------------------------------------------------- */

/* Resolve one permission name against a class (incl. its common table). */
static uint32_t perm_bit(policydb_t *pdb, class_datum_t *cls,
                         const char *perm)
{
    perm_datum_t *d = (perm_datum_t *)hashtab_search(
        cls->permissions.table, (const hashtab_key_t)perm);
    if (d) {
        return 1u << (d->s.value - 1);
    }
    if (cls->comdatum) {
        d = (perm_datum_t *)hashtab_search(
            cls->comdatum->permissions.table, (const hashtab_key_t)perm);
        if (d) {
            return 1u << (d->s.value - 1);
        }
    }
    return 0;
}

/* --- avtab rules ------------------------------------------------------- */

static int insert_allow(policydb_t *pdb, uint32_t sval, uint32_t tval,
                        class_datum_t *cls, const char *const *perms,
                        unsigned perms_len)
{
    uint32_t bits = 0;
    for (unsigned i = 0; i < perms_len; i++) {
        uint32_t bit = perm_bit(pdb, cls, perms[i]);
        if (!bit) {
            klog("permission %s missing; skipped", perms[i]);
            continue;
        }
        bits |= bit;
    }
    if (!bits) {
        return 0;
    }

    /* avtab keys use 1-based type/class values both in libsepol's
     * in-memory representation and in the binary on-disk format (verified
     * against the OEM policy of f0506h 4.14: 1-based searches hit existing
     * rules; 0-based keys silently grant nothing after a kernel reload). */
    avtab_key_t key = {
        .source_type = (uint16_t)(sval),
        .target_type = (uint16_t)(tval),
        .target_class = (uint16_t)(cls->s.value),
        .specified = AVTAB_ALLOWED,
    };
    avtab_datum_t *existing = avtab_search(&pdb->te_avtab, &key);
    if (existing) {
        existing->data |= bits;
        return 0;
    }
    avtab_datum_t datum = {.data = bits, .ops = NULL};
    return avtab_insert(&pdb->te_avtab, &key, &datum) == 0 ? 0 : -1;
}

/* Exact ioctl numbers only; never synthesize a whole-driver bitmap. */
static int insert_ioctl_allow(policydb_t *pdb, uint32_t source, uint32_t target,
                              class_datum_t *cls, unsigned short command)
{
    if (pdb->policyvers < POLICYDB_VERSION_IOCTL_OPERATIONS ||
        pdb->type_val_to_struct[source - 1]->flavor != TYPE_TYPE ||
        pdb->type_val_to_struct[target - 1]->flavor != TYPE_TYPE) {
        return -1;
    }
    avtab_key_t key = {
        .source_type = (uint16_t)source,
        .target_type = (uint16_t)target,
        .target_class = (uint16_t)cls->s.value,
        .specified = AVTAB_OPNUM_ALLOWED,
    };
    unsigned driver = command >> 8, function = command & 255;
    for (avtab_ptr_t node = avtab_search_node(&pdb->te_avtab, &key); node;
         node = avtab_search_node_next(node, AVTAB_OPNUM_ALLOWED)) {
        avtab_operations_t *ops = node->datum.ops;
        if (ops && ops->specified == AVTAB_XPERMS_IOCTLFUNCTION &&
            ops->driver == driver) {
            ops->perms[function / 32] |= 1u << (function % 32);
            return 0;
        }
    }
    avtab_operations_t ops = { .specified = AVTAB_XPERMS_IOCTLFUNCTION,
                               .driver = (uint8_t)driver };
    ops.perms[function / 32] = 1u << (function % 32);
    avtab_datum_t datum = { .data = 0, .ops = &ops };
    return avtab_insert_nonunique(&pdb->te_avtab, &key, &datum) ? 0 : -1;
}

/* dontaudit suppression: the kernel semantic for an AVTAB_AUDITDENY entry is
 * inverted relative to allow — a SET bit suppresses the audit of the
 * corresponding denied permission (libsepol avtab.h: AVTAB_AUDITDENY).  An
 * absent entry defaults to auditing all denials, so a fresh entry here is
 * what silences the expected skip; an existing entry gets the bits ORed in. */
static int insert_dontaudit(policydb_t *pdb, uint32_t sval, uint32_t tval,
                            class_datum_t *cls, const char *const *perms,
                            unsigned perms_len)
{
    uint32_t bits = 0;
    for (unsigned i = 0; i < perms_len; i++) {
        uint32_t bit = perm_bit(pdb, cls, perms[i]);
        if (!bit) {
            klog("permission %s missing; dontaudit skipped", perms[i]);
            continue;
        }
        bits |= bit;
    }
    if (!bits) {
        return 0;
    }
    avtab_key_t key = {
        .source_type = (uint16_t)(sval),
        .target_type = (uint16_t)(tval),
        .target_class = (uint16_t)(cls->s.value),
        .specified = AVTAB_AUDITDENY,
    };
    avtab_datum_t *existing = avtab_search(&pdb->te_avtab, &key);
    if (existing) {
        existing->data |= bits;
        return 0;
    }
    avtab_datum_t datum = {.data = bits, .ops = NULL};
    return avtab_insert(&pdb->te_avtab, &key, &datum) == 0 ? 0 : -1;
}

static int insert_transition(policydb_t *pdb, uint32_t sval, uint32_t tval,
                             class_datum_t *cls, uint32_t new_val)
{
    avtab_key_t key = {
        .source_type = (uint16_t)(sval),
        .target_type = (uint16_t)(tval),
        .target_class = (uint16_t)(cls->s.value),
        .specified = AVTAB_TRANSITION,
    };
    if (avtab_search(&pdb->te_avtab, &key)) {
        return 0;
    }
    avtab_datum_t datum = {.data = new_val, .ops = NULL};
    return avtab_insert(&pdb->te_avtab, &key, &datum) == 0 ? 0 : -1;
}

static int insert_filename_trans(policydb_t *pdb, uint32_t sval, uint32_t tval,
                                 class_datum_t *cls, uint32_t new_val,
                                 const char *filename)
{
    for (filename_trans_t *ft = pdb->filename_trans; ft; ft = ft->next) {
        if (ft->stype == sval && ft->ttype == tval && ft->tclass == cls->s.value &&
            !strcmp(ft->name, filename)) {
            return 0; /* already present */
        }
    }
    filename_trans_t *ft = calloc(1, sizeof(*ft));
    if (!ft) {
        return -1;
    }
    /* filename_trans fields are 1-based type/class values, both on disk
     * and in the kernel's in-memory policy (expand.c compares stype == i+1). */
    ft->stype = sval;
    ft->ttype = tval;
    ft->tclass = cls->s.value;
    ft->name = strdup(filename);
    ft->otype = new_val;
    ft->next = pdb->filename_trans;
    pdb->filename_trans = ft;
    return 0;
}

/* --- attribute expansion ---------------------------------------------- */

/* Binary policies carry no attribute-keyed avtab rules: checkpolicy expands
 * them at build time and the kernel does exact-type lookups in compute_av.
 * A rule injected against an attribute (e.g. `allow voboost domain:file`)
 * therefore grants nothing unless we expand it into concrete members using
 * attr_type_map. Nested attributes are already flattened by the firmware
 * compiler, so one level of expansion suffices. */
static int is_attribute(policydb_t *pdb, uint32_t val)
{
    /* Kernel policies do not use type_datum flavors: a symbol is an
     * attribute iff attr_type_map holds members besides itself. */
    ebitmap_t *m = &pdb->attr_type_map[val - 1];
    ebitmap_node_t *node;
    unsigned b, count = 0;
    ebitmap_for_each_bit(m, node, b) {
        if (ebitmap_get_bit(m, b) && ++count > 1) {
            return 1;
        }
    }
    return 0;
}

static int insert_allow_expanded(policydb_t *pdb, uint32_t sval, uint32_t tval,
                                 class_datum_t *cls, const char *const *perms,
                                 unsigned perms_len)
{
    if (!is_attribute(pdb, sval) && !is_attribute(pdb, tval)) {
        return insert_allow(pdb, sval, tval, cls, perms, perms_len);
    }

    if (is_attribute(pdb, sval)) {
        ebitmap_t *members = &pdb->attr_type_map[sval - 1];
        ebitmap_node_t *node;
        unsigned b;
        int rc = 0;
        ebitmap_for_each_bit(members, node, b) {
            if (!ebitmap_get_bit(members, b) || (unsigned)b == sval - 1) {
                continue;
            }
            if (insert_allow_expanded(pdb, (uint32_t)b + 1, tval, cls, perms, perms_len) != 0) {
                rc = -1;
            }
        }
        return rc;
    }

    ebitmap_t *members = &pdb->attr_type_map[tval - 1];
    ebitmap_node_t *node;
    unsigned b;
    int rc = 0;
    ebitmap_for_each_bit(members, node, b) {
        if (!ebitmap_get_bit(members, b) || (unsigned)b == tval - 1) {
            continue;
        }
        if (insert_allow(pdb, sval, (uint32_t)b + 1, cls, perms, perms_len) != 0) {
            rc = -1;
        }
    }
    return rc;
}

/* Binary policies expand attribute references inside constraint
 * expressions into fixed type bitmaps at compile time (t1 == mlstrustedsubject
 * becomes a literal name list). Adding our types to the attribute afterwards
 * updates type_attr_map but NOT those bitmaps, so MLS constraints still
 * deny our reads of categorized objects. Patch every CEXPR_NAMES node whose
 * name list equals the attribute's member set by adding our type bits. */
typedef struct {
    ebitmap_t *members;
    uint32_t vals[8]; /* types to add to matching exprs (same attribute) */
    unsigned vals_len;
    int patched;
} constraint_patch_ctx;

static int constraint_expr_cb(hashtab_key_t key, hashtab_datum_t datum,
                              void *arg)
{
    (void)key;
    class_datum_t *cl = (class_datum_t *)datum;
    constraint_patch_ctx *ctx = (constraint_patch_ctx *)arg;
    for (int which = 0; which < 2; which++) {
        for (constraint_node_t *c = which ? cl->validatetrans : cl->constraints;
             c; c = c->next) {
            for (constraint_expr_t *e = c->expr; e; e = e->next) {
                if (e->expr_type != CEXPR_NAMES || !(e->attr & CEXPR_TYPE)) {
                    continue;
                }
                if (!ebitmap_cmp(&e->names, ctx->members)) {
                    continue;
                }
                for (unsigned v = 0; v < ctx->vals_len; v++) {
                    if (ebitmap_set_bit(&e->names, ctx->vals[v] - 1, 1) != 0) {
                        return -1; /* abort hashtab_map */
                    }
                }
                ctx->patched++;
            }
        }
    }
    return 0;
}

static int patch_constraint_exprs(policydb_t *pdb, const char *attr_name,
                                  const ebitmap_t *baseline,
                                  const uint32_t *vals, unsigned vals_len)
{
    uint32_t aval = type_value(pdb, attr_name);
    if (!aval) {
        return 0;
    }
    /* `baseline` is the attribute's PRE-inject member bitmap, snapshotted
     * before the create loop added any of our type bits. The constraint
     * nodes' `names` bitmaps carry exactly that compile-time-expanded list.
     * All types joining the SAME attribute must be patched in one pass:
     * exprs are matched by exact bitmap equality, so a second pass would
     * compare against bitmaps already carrying the first pass's bits and
     * silently match nothing. */
    constraint_patch_ctx ctx = {
        .members = (ebitmap_t *)baseline,
        .vals_len = vals_len,
        .patched = 0,
    };
    memcpy(ctx.vals, vals, vals_len * sizeof(vals[0]));
    int rc = hashtab_map(pdb->symtab[SYM_CLASSES].table, constraint_expr_cb,
                         &ctx);
    if (rc != 0) {
        return -1;
    }
    klog("constraint bitmaps patched via %s for %u types (%d exprs)",
         attr_name, vals_len, ctx.patched);
    return 0;
}

/* --- public API -------------------------------------------------------- */

int voboost_policy_applied(policydb_t *pdb)
{
    /* The type alone is a weak marker: a firmware update could ship its own
     * `voboost` type. Require the load-bearing rule we inject as well —
     * init -> voboost_exec:process -> voboost (init_daemon_domain) — so the
     * probe detects OUR patch, not just a name collision. */
    type_datum_t *vd = lookup_type(pdb, "voboost");
    type_datum_t *ve = lookup_type(pdb, "voboost_exec");
    type_datum_t *ud = lookup_type(pdb, "voboost_uninstall");
    type_datum_t *ue = lookup_type(pdb, "voboost_uninstall_exec");
    type_datum_t *df = lookup_type(pdb, "voboost_data_file");
    type_datum_t *gf = lookup_type(pdb, "voboost_generation_file");
    if (!vd || !ve || !ud || !ue || !df || !gf) {
        return 0;
    }
    type_datum_t *initd = lookup_type(pdb, "init");
    class_datum_t *proc = lookup_class(pdb, "process");
    if (!initd || !proc) {
        return 0;
    }
    avtab_key_t daemon_key = {
        .source_type = (uint16_t)(initd->s.value),
        .target_type = (uint16_t)(ve->s.value),
        .target_class = (uint16_t)(proc->s.value),
        .specified = AVTAB_TRANSITION,
    };
    avtab_key_t uninstall_key = {
        .source_type = (uint16_t)(initd->s.value),
        .target_type = (uint16_t)(ue->s.value),
        .target_class = (uint16_t)(proc->s.value),
        .specified = AVTAB_TRANSITION,
    };
    int generation_transition = 0;
    for (filename_trans_t *transition = pdb->filename_trans; transition;
         transition = transition->next) {
        if (transition->stype == vd->s.value &&
            transition->ttype == df->s.value &&
            transition->otype == gf->s.value &&
            !strcmp(transition->name, "generations")) {
            generation_transition = 1;
            break;
        }
    }
    return generation_transition &&
           avtab_search(&pdb->te_avtab, &daemon_key) != NULL &&
           avtab_search(&pdb->te_avtab, &uninstall_key) != NULL;
}

int voboost_policy_inject(policydb_t *pdb)
{
    unsigned created = 0;

    /* Snapshot the MLS attributes' ORIGINAL member bitmaps BEFORE the create
     * loop adds our type bits via set_attr: the constraint `names` bitmaps
     * equal exactly these compile-time lists, so they are the comparison
     * baselines for patch_constraint_exprs below. */
    ebitmap_t subj_baseline, obj_baseline;
    int have_subj = 0, have_obj = 0;
    uint32_t subj_aval = type_value(pdb, "mlstrustedsubject");
    uint32_t obj_aval = type_value(pdb, "mlstrustedobject");
    if (subj_aval) {
        if (ebitmap_cpy(&subj_baseline, &pdb->attr_type_map[subj_aval - 1]) != 0) {
            return -1;
        }
        have_subj = 1;
    }
    if (obj_aval) {
        if (ebitmap_cpy(&obj_baseline, &pdb->attr_type_map[obj_aval - 1]) != 0) {
            return -1;
        }
        have_obj = 1;
    }

    for (unsigned i = 0; i < VR_TYPES_COUNT; i++) {
        const vr_type *t = &vr_types[i];
        uint32_t val = create_type(pdb, t->name, &created);
        if (!val) {
            klog("failed to create type %s", t->name);
            return -1;
        }
        for (unsigned a = 0; a < t->attrs_len; a++) {
            set_attr(pdb, val, t->attrs[a]);
        }
        if (!strcmp(t->name, "voboost") ||
            !strcmp(t->name, "voboost_install") ||
            !strcmp(t->name, "voboost_restore") ||
            !strcmp(t->name, "voboost_relabel") ||
            !strcmp(t->name, "voboost_reboot") ||
            !strcmp(t->name, "voboost_uninstall")) {
            if (add_to_init_role(pdb, val) != 0) {
                klog("failed to add %s to role", t->name);
                return -1;
            }
            /* Linux 4.14 security_bounded_transition() walks the NEW type's
             * bounds chain and requires it to reach init; without bounds the
             * daemon service can never enter this domain (verified on the
             * f0506h firmware). The price is bounds masking in
             * security_compute_av: every permission granted to voboost must
             * also be granted to init or the kernel silently strips it.
             * The allow loop below mirrors voboost-sourced rules onto init. */
            type_datum_t *initd = lookup_type(pdb, "init");
            if (!initd) {
                klog("type init missing");
                return -1;
            }
            ((type_datum_t *)hashtab_search(pdb->symtab[SYM_TYPES].table,
                                            (hashtab_key_t)t->name))
                ->bounds = initd->s.value;
        }
    }

    for (unsigned i = 0; i < VR_IOCTL_ALLOWS_COUNT; i++) {
        const vr_ioctl_allow *r = &vr_ioctl_allows[i];
        uint32_t source = type_value(pdb, r->src);
        uint32_t target = type_value(pdb, r->tgt);
        class_datum_t *cls = lookup_class(pdb, r->cls);
        if ((!source && !strncmp(r->src, "voboost", 7)) ||
            (!target && !strncmp(r->tgt, "voboost", 7))) {
            return -1;
        }
        if (!source || !target) {
            continue; /* Firmware-optional OEM target, like ordinary allows. */
        }
        if (!cls || !perm_bit(pdb, cls, "ioctl")) {
            return -1;
        }
        if (!strcmp(r->src, "voboost") && !strcmp(r->tgt, "can_device") &&
            !strcmp(r->cls, "chr_file")) {
            static const char *const required[] = { "open", "read", "write", "getattr", "ioctl" };
            for (unsigned j = 0; j < sizeof(required) / sizeof(required[0]); j++) {
                if (!perm_bit(pdb, cls, required[j])) {
                    return -1;
                }
            }
        }
        for (unsigned j = 0; j < r->commands_len; j++) {
            if (insert_ioctl_allow(pdb, source, target, cls, r->commands[j])) {
                return -1;
            }
        }
    }

    for (unsigned i = 0; i < VR_ALLOWS_COUNT; i++) {
        const vr_allow *r = &vr_allows[i];
        uint32_t sval = type_value(pdb, r->src);
        /* `self` is the TE keyword: the target equals the source type. */
        uint32_t tval = !strcmp(r->tgt, "self") ? sval : type_value(pdb, r->tgt);
        class_datum_t *cls = lookup_class(pdb, r->cls);
        if (!cls) {
            klog("class %s missing; rule skipped", r->cls);
            continue;
        }
        int src_is_ours = !strncmp(r->src, "voboost", 7);
        int tgt_is_ours = !strncmp(r->tgt, "voboost", 7);
        if (!sval) {
            if (src_is_ours) {
                return -1;
            }
            klog("source %s missing; rule skipped", r->src);
            continue;
        }
        if (!tval) {
            if (tgt_is_ours && strcmp(r->tgt, "self") != 0) {
                return -1;
            }
            klog("target %s missing; rule skipped", r->tgt);
            continue;
        }
        if (insert_allow_expanded(pdb, sval, tval, cls, r->perms, r->perms_len) != 0) {
            klog("avtab insert failed for %s %s:%s", r->src, r->tgt, r->cls);
            return -1;
        }
        /* Bounds masking (kernel type_attribute_bounds_av): a check
         * (voboost, T) is intersected with (init, T), and when T is itself
         * bounded (T == voboost, e.g. all `self` checks) the kernel computes
         * the mask against (init, init). Mirror voboost grants onto init
         * accordingly or they are silently stripped. */
        if (src_is_ours) {
            uint32_t init_val = type_value(pdb, "init");
            int tgt_is_voboost =
                !strcmp(r->tgt, "voboost") ||
                !strcmp(r->tgt, "voboost_install") ||
                !strcmp(r->tgt, "voboost_restore") ||
                !strcmp(r->tgt, "voboost_relabel") ||
                !strcmp(r->tgt, "voboost_reboot") ||
                !strcmp(r->tgt, "voboost_uninstall") ||
                !strcmp(r->tgt, "self");
            if (init_val) {
                if (insert_allow_expanded(pdb, init_val, tval, cls, r->perms,
                                 r->perms_len) != 0) {
                    klog("avtab mirror insert failed for init %s:%s",
                         r->tgt, r->cls);
                    return -1;
                }
                if (tgt_is_voboost &&
                    insert_allow(pdb, init_val, init_val, cls, r->perms,
                                 r->perms_len) != 0) {
                    klog("avtab init-self mirror insert failed for %s:%s",
                         r->tgt, r->cls);
                    return -1;
                }
            }
        }
    }

    for (unsigned i = 0; i < VR_DONTAUDITS_COUNT; i++) {
        const vr_dontaudit *r = &vr_dontaudits[i];
        uint32_t sval = type_value(pdb, r->src);
        uint32_t tval = !strcmp(r->tgt, "self") ? sval : type_value(pdb, r->tgt);
        class_datum_t *cls = lookup_class(pdb, r->cls);
        if (!cls) {
            klog("class %s missing; dontaudit skipped", r->cls);
            continue;
        }
        if (!sval || !tval) {
            klog("type %s/%s missing; dontaudit skipped", r->src, r->tgt);
            continue;
        }
        if (insert_dontaudit(pdb, sval, tval, cls, r->perms, r->perms_len) != 0) {
            klog("avtab dontaudit insert failed for %s %s:%s", r->src, r->tgt, r->cls);
            return -1;
        }
    }

    for (unsigned i = 0; i < VR_TRANSITIONS_COUNT; i++) {
        const vr_transition *t = &vr_transitions[i];
        uint32_t sval = type_value(pdb, t->src);
        uint32_t tval = type_value(pdb, t->tgt);
        uint32_t nval = type_value(pdb, t->new_type);
        class_datum_t *cls = lookup_class(pdb, t->cls);
        if (!sval) {
            klog("transition source %s missing; skipped", t->src);
            continue;
        }
        if (!tval || !nval || !cls) {
            klog("transition symbols missing (%s); aborting", t->new_type);
            return -1;
        }
        int rc = t->filename
                     ? insert_filename_trans(pdb, sval, tval, cls, nval,
                                             t->filename)
                     : insert_transition(pdb, sval, tval, cls, nval);
        if (rc != 0) {
            klog("transition insert failed");
            return -1;
        }
    }

    /* MLS constraint bitmaps carry compile-time-expanded attribute member
     * lists; extend them for our attribute memberships (see
     * patch_constraint_exprs). Types sharing an attribute are patched in a
     * single pass; voboost and su both join mlstrustedsubject. su is a
     * firmware domain; the installer (su) must chown/push into categorized
     * app_data_file during provisioning, and TE allows alone are
     * insufficient — MLS category constraints still deny (observed
     * "avc: denied { open } ... app_data_file:s0:c55,c256,c512,c768"). */
    {
        uint32_t subj_vals[8], subj_n = 0;
        uint32_t gval = type_value(pdb, "voboost_generation_file");
        const char *subject_types[] = {
            "voboost", "voboost_install", "voboost_restore",
            "voboost_relabel", "voboost_uninstall", "voboost_ota_socket", "su"
        };
        for (size_t i = 0;
             i < sizeof(subject_types) / sizeof(subject_types[0]); i++) {
            uint32_t value = type_value(pdb, subject_types[i]);
            if (value && subj_n < 8) {
                subj_vals[subj_n++] = value;
            }
        }
        if (subj_n && patch_constraint_exprs(pdb, "mlstrustedsubject", &subj_baseline, subj_vals,
                                             subj_n) != 0) {
            return -1;
        }
        if (gval) {
            uint32_t obj_vals[1] = { gval };
            if (patch_constraint_exprs(pdb, "mlstrustedobject", &obj_baseline, obj_vals, 1) != 0) {
                return -1;
            }
        }
        if (have_subj) {
            ebitmap_destroy(&subj_baseline);
        }
        if (have_obj) {
            ebitmap_destroy(&obj_baseline);
        }
    }

    klog("injected %u new types, %u allow rules, %d transitions", created,
         (unsigned)VR_ALLOWS_COUNT, (int)VR_TRANSITIONS_COUNT);
    return 0;
}

int voboost_policy_preserves_types(const policydb_t *candidate,
                                   const policydb_t *previous) {
    if (!candidate || !previous || !candidate->p_types.table ||
        !previous->p_types.table) {
        return 0;
    }
    hashtab_t table = previous->p_types.table;
    for (unsigned bucket = 0; bucket < table->size; ++bucket) {
        for (hashtab_ptr_t entry = table->htable[bucket]; entry;
             entry = entry->next) {
            const type_datum_t *old = entry->datum;
            if (old->flavor != TYPE_TYPE) {
                continue;
            }
            const type_datum_t *current =
                hashtab_search(candidate->p_types.table, entry->key);
            if (!current || current->flavor != TYPE_TYPE) {
                klog("product update candidate loses concrete type %s", entry->key);
                return 0;
            }
        }
    }
    return 1;
}
