/* test_inject.c — unit tests for policy_inject on a synthetic policydb.
 *
 * Builds a minimal Android-like expanded policydb in memory (types, classes,
 * role, avtab), runs voboost_policy_inject, and asserts the injected rules
 * are present. Exercised by test/selinux/run.sh (host build only).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>

#include "policy_inject.h"
#include "rules.gen.h"

static int failures = 0;

#define CHECK(cond, msg)                                                       \
        do {                                                                       \
            if (!(cond)) {                                                         \
                fprintf(stderr, "FAIL: %s\n", msg);                                \
                failures++;                                                        \
            } else {                                                               \
                fprintf(stderr, "ok: %s\n", msg);                                  \
            }                                                                      \
        } while (0)

/* --- synthetic policy construction ------------------------------------- */

static type_datum_t *add_type_raw(policydb_t *p, const char *name, int flavor) {
    type_datum_t *t = calloc(1, sizeof(*t));
    t->flavor = flavor;
    t->primary = 1;
    t->s.value = p->symtab[SYM_TYPES].nprim + 1;
    hashtab_insert(p->symtab[SYM_TYPES].table, (hashtab_key_t)strdup(name),
                   (hashtab_datum_t)t);
    p->symtab[SYM_TYPES].nprim = t->s.value;
    return t;
}

static void add_class_perm(class_datum_t *cls, const char *perm) {
    perm_datum_t *d = calloc(1, sizeof(*d));
    d->s.value = cls->permissions.nprim + 1;
    hashtab_insert(cls->permissions.table, (hashtab_key_t)strdup(perm),
                   (hashtab_datum_t)d);
    cls->permissions.nprim = d->s.value;
}

static class_datum_t *add_class(policydb_t *p, const char *name,
                                const char *const *perms, unsigned n) {
    class_datum_t *c = calloc(1, sizeof(*c));
    c->s.value = p->symtab[SYM_CLASSES].nprim + 1;
    symtab_init(&c->permissions, 64);
    for (unsigned i = 0; i < n; i++) {
        add_class_perm(c, perms[i]);
    }
    hashtab_insert(p->symtab[SYM_CLASSES].table, (hashtab_key_t)strdup(name),
                   (hashtab_datum_t)c);
    p->symtab[SYM_CLASSES].nprim = c->s.value;
    return c;
}

/* Minimal Android-like base: init, app domains, proc, attributes, classes. */
static void build_base(policydb_t *p) {
    const char *attrs[] = {"domain",       "exec_type",  "file_type",
                           "data_file_type", "mlstrustedsubject",
                           "mlstrustedobject", "vendor_file_type",
                           "mlstrustedsubject"};
    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        add_type_raw(p, attrs[i], TYPE_ATTRIB);
    }

    const char *types[] = {
        "init",          "untrusted_app", "untrusted_app_25",
        "untrusted_app_27", "untrusted_app_29", "platform_app",
        "system_app", "system_server", "system",        "priv_app",
        "radio",         "proc",          "property_socket",
        "ctl_start_prop", "ctl_stop_prop", "toolbox_exec",
        "shell_exec",    "labeledfs",     "system_file",
        "vendor_file",   "vendor_overlay_file",
        "system_data_file", "app_data_file", "kmsg_device",
        "zygote_exec", "block_device"
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        add_type_raw(p, types[i], TYPE_TYPE);
    }

    /* roles_init() (called by policydb_init) already created "object_r".
    * A read policy would index it in role_val_to_struct; do the same. */
    role_datum_t *objr = (role_datum_t *)hashtab_search(
        p->symtab[SYM_ROLES].table, (const hashtab_key_t)"object_r");
    p->role_val_to_struct = calloc(1, sizeof(role_datum_t *));
    p->role_val_to_struct[0] = objr;

    const char *file_perms[] = {
        "read", "write", "open", "getattr", "setattr", "create",
        "unlink", "rename", "append", "ioctl", "lock", "map",
        "execute", "execute_no_trans", "entrypoint", "relabelfrom",
        "relabelto"
    };
    const char *dir_perms[] = {"read",    "write", "open",  "getattr", "setattr",
                               "create",  "add_name", "remove_name",
                               "search",  "rename", "rmdir", "reparent", "lock",
                               "relabelfrom", "relabelto"};
    const char *lnk_perms[] = {"read", "open", "getattr", "write"};
    const char *process_perms[] = {
        "ptrace", "getsched", "setsched", "signal", "transition", "fork",
        "sigchld", "noatsecure", "siginh", "rlimitinh", "setexec"
    };
    const char *cap_perms[] = {"sys_ptrace", "setuid", "setgid",
                               "dac_read_search", "dac_override", "kill",
                               "sys_admin", "sys_boot"};
    add_class(p, "file", file_perms, sizeof(file_perms) / sizeof(*file_perms));
    add_class(p, "dir", dir_perms, sizeof(dir_perms) / sizeof(*dir_perms));
    add_class(p, "lnk_file", lnk_perms, 4);
    add_class(p, "process", process_perms,
              sizeof(process_perms) / sizeof(*process_perms));
    add_class(p, "capability", cap_perms,
              sizeof(cap_perms) / sizeof(*cap_perms));
    const char *sock_file_perms[] = {"write", "open", "read", "getattr"};
    const char *stream_perms[] = {"connectto", "create", "bind", "connect",
                                  "accept", "read", "write", "setopt"};
    const char *property_perms[] = {"set"};
    const char *filesystem_perms[] = {"remount"};
    const char *chr_perms[] = {"open", "write", "getattr", "append"};
    add_class(p, "sock_file", sock_file_perms, 4);
    add_class(p, "unix_stream_socket", stream_perms, 8);
    add_class(p, "property_service", property_perms, 1);
    add_class(p, "filesystem", filesystem_perms, 1);
    add_class(p, "chr_file", chr_perms, 4);
    add_class(p, "blk_file", file_perms, sizeof(file_perms) / sizeof(*file_perms));

    /* policydb_read allocates the avtab; do the same for the synthetic base. */
    if (avtab_alloc(&p->te_avtab, 512) != 0) {
        abort();
    }

    /* The arrays type_attr_map etc. are grown by the injector; start them
     * at the base nprim so create_type's realloc path is exercised. */
    unsigned n = p->symtab[SYM_TYPES].nprim;
    p->type_attr_map = calloc(n, sizeof(ebitmap_t));
    p->attr_type_map = calloc(n, sizeof(ebitmap_t));
    p->type_val_to_struct = calloc(n, sizeof(type_datum_t *));
    for (unsigned i = 0; i < n; i++) {
        ebitmap_init(&p->type_attr_map[i]);
        ebitmap_init(&p->attr_type_map[i]);
        ebitmap_set_bit(&p->type_attr_map[i], i, 1);
        ebitmap_set_bit(&p->attr_type_map[i], i, 1);
        /* resolve type_val_to_struct via the hashtab (value order) */
    }
    /* Attach type_val_to_struct by lookup for every known name. */
    const char *all[] = {"domain",       "exec_type",  "file_type",
                         "data_file_type", "mlstrustedsubject",
                         "mlstrustedobject", "init",   "untrusted_app",
                         "untrusted_app_25", "system_app", "system_server", "system",
                         "priv_app", "radio", "proc", "property_socket",
                         "ctl_start_prop", "ctl_stop_prop", "toolbox_exec",
                         "shell_exec", "labeledfs", "system_file",
                         "vendor_file", "vendor_overlay_file",
                         "system_data_file", "kmsg_device",
                         "zygote_exec", "block_device"};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        type_datum_t *d = (type_datum_t *)hashtab_search(
            p->symtab[SYM_TYPES].table, (hashtab_key_t)all[i]);
        if (d && d->s.value <= n) {
            p->type_val_to_struct[d->s.value - 1] = d;
        }
    }
}

/* --- helpers over the patched policy ------------------------------------ */

static type_datum_t *get_type(policydb_t *p, const char *name) {
    return (type_datum_t *)hashtab_search(p->symtab[SYM_TYPES].table,
                                          (const hashtab_key_t)name);
}

static uint32_t val(policydb_t *p, const char *name) {
    type_datum_t *d = get_type(p, name);
    return d ? d->s.value : 0;
}

static class_datum_t *get_class(policydb_t *p, const char *name) {
    return (class_datum_t *)hashtab_search(p->symtab[SYM_CLASSES].table,
                                           (const hashtab_key_t)name);
}

static int allow_present(policydb_t *p, const char *s, const char *t,
                         const char *c, uint32_t need_bits) {
    class_datum_t *cls = get_class(p, c);
    avtab_key_t key = {
        .source_type = (uint16_t)(val(p, s)),
        .target_type = (uint16_t)(val(p, t)),
        .target_class = (uint16_t)(cls->s.value),
        .specified = AVTAB_ALLOWED,
    };
    avtab_datum_t *d = avtab_search(&p->te_avtab, &key);
    return d && (d->data & need_bits) == need_bits;
}

static uint32_t bit_for(policydb_t *p, const char *cls_name, const char *perm) {
    class_datum_t *c = get_class(p, cls_name);
    perm_datum_t *d = (perm_datum_t *)hashtab_search(c->permissions.table,
                                                     (const hashtab_key_t)perm);
    return d ? 1u << (d->s.value - 1) : 0;
}

static void test_firmware_type_preservation(void) {
    policydb_t baseline, previous;
    CHECK(policydb_init(&baseline) == 0, "baseline policy initializes");
    CHECK(policydb_init(&previous) == 0, "previous policy initializes");
    add_type_raw(&baseline, "firmware_domain", TYPE_TYPE);
    add_type_raw(&baseline, "firmware_exec", TYPE_TYPE);
    add_type_raw(&baseline, "voboost", TYPE_TYPE);
    add_type_raw(&baseline, "voboost_exec", TYPE_TYPE);
    add_type_raw(&previous, "voboost", TYPE_TYPE);
    add_type_raw(&previous, "voboost_exec", TYPE_TYPE);
    add_type_raw(&previous, "firmware_exec", TYPE_TYPE);
    add_type_raw(&previous, "firmware_domain", TYPE_TYPE);
    CHECK(voboost_policy_preserves_types(&baseline, &previous),
          "firmware names survive reordered IDs and existing product types");
    add_type_raw(&previous, "can_early_inputs", TYPE_TYPE);
    CHECK(!voboost_policy_preserves_types(&baseline, &previous),
          "update rejects missing CIL-only firmware type before publication");
    add_type_raw(&baseline, "can_early_inputs", TYPE_TYPE);
    CHECK(voboost_policy_preserves_types(&baseline, &previous),
          "retained CIL-only firmware type is accepted");
    add_type_raw(&previous, "voboost_unknown_firmware", TYPE_TYPE);
    CHECK(!voboost_policy_preserves_types(&baseline, &previous),
          "an unknown product-like prefix is not an ownership exemption");
    type_datum_t *replacement =
        add_type_raw(&baseline, "voboost_unknown_firmware", TYPE_ATTRIB);
    CHECK(!voboost_policy_preserves_types(&baseline, &previous),
          "attribute cannot replace a concrete firmware type");
    replacement->flavor = TYPE_TYPE;
    CHECK(voboost_policy_preserves_types(&baseline, &previous),
          "same concrete firmware types are accepted");
    CHECK(!voboost_policy_preserves_types(NULL, &previous),
          "absent baseline fails closed");
    policydb_destroy(&baseline);
    policydb_destroy(&previous);
}

int main(void) {
    test_firmware_type_preservation();
    policydb_t pdb;
    policydb_init(&pdb);
    pdb.policyvers = POLICYDB_VERSION_MAX;
    build_base(&pdb);

    /* Pre-state: the voboost domain does not exist. */
    CHECK(!voboost_policy_applied(&pdb), "not applied before inject");

    CHECK(voboost_policy_inject(&pdb) == 0, "inject succeeds");

    CHECK(voboost_policy_applied(&pdb), "applied after inject");
    /* This platform has block devices but no OEM vdh_device target. */
    CHECK(get_type(&pdb, "vdh_device") == NULL, "optional OEM NV type is not manufactured");
    CHECK(!allow_present(&pdb, "voboost", "block_device", "blk_file",
                         bit_for(&pdb, "blk_file", "open")) &&
              !allow_present(&pdb, "voboost", "block_device", "blk_file",
                             bit_for(&pdb, "blk_file", "read")),
          "absent OEM NV target does not fall back to generic block reads");


    /* All five declared types exist. */
    for (unsigned i = 0; i < VR_TYPES_COUNT; i++) {
        CHECK(get_type(&pdb, vr_types[i].name) != NULL, vr_types[i].name);
    }

    /* Attribute membership: voboost has domain+mlstrustedsubject bits. */
    uint32_t v = val(&pdb, "voboost");
    uint32_t dom = val(&pdb, "domain");
    uint32_t mls = val(&pdb, "mlstrustedsubject");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[v - 1], dom - 1),
          "voboost in domain attr");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[v - 1], mls - 1),
          "voboost in mlstrustedsubject attr");
    CHECK(ebitmap_get_bit(&pdb.attr_type_map[dom - 1], v - 1),
          "reverse attr map updated");

    uint32_t u = val(&pdb, "voboost_uninstall");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[u - 1], dom - 1),
          "voboost_uninstall in domain attr");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[u - 1], mls - 1),
          "voboost_uninstall in mlstrustedsubject attr");
    uint32_t relabel = val(&pdb, "voboost_relabel");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[relabel - 1], mls - 1),
          "voboost_relabel in mlstrustedsubject attr");

    /* voboost_exec in exec_type. */
    uint32_t ve = val(&pdb, "voboost_exec");
    uint32_t exec_attr = val(&pdb, "exec_type");
    CHECK(ebitmap_get_bit(&pdb.type_attr_map[ve - 1], exec_attr - 1),
          "voboost_exec in exec_type attr");

    /* Role membership. */
    role_datum_t *r = pdb.role_val_to_struct[0];
    const char *init_domains[] = {
        "voboost", "voboost_install", "voboost_restore",
        "voboost_relabel", "voboost_reboot", "voboost_uninstall"
    };
    uint32_t init_value = val(&pdb, "init");
    for (size_t i = 0; i < sizeof(init_domains) / sizeof(init_domains[0]); i++) {
        type_datum_t *domain = get_type(&pdb, init_domains[i]);
        CHECK(r && domain && ebitmap_get_bit(&r->types.types, domain->s.value - 1),
              "init role holds Voboost service domain");
        CHECK(domain && domain->bounds == init_value,
              "Voboost service domain is bounded by init");
    }

    CHECK(allow_present(&pdb, "su", "voboost_data_file", "sock_file",
                        bit_for(&pdb, "sock_file", "write")),
          "root management peer can reach owner pathname socket");
    CHECK(allow_present(&pdb, "su", "voboost", "unix_stream_socket",
                        bit_for(&pdb, "unix_stream_socket", "connectto")),
          "root management peer can connect to owner domain");
    CHECK(!allow_present(&pdb, "su", "voboost_data_file", "sock_file",
                         bit_for(&pdb, "sock_file", "read")),
          "owner socket grant does not authorize socket-file reads");
    CHECK(allow_present(&pdb, "voboost", "su", "lnk_file",
                        bit_for(&pdb, "lnk_file", "read")),
          "owner can resolve the signed management peer proc executable link");
    CHECK(!allow_present(&pdb, "voboost", "su", "lnk_file",
                         bit_for(&pdb, "lnk_file", "open")) &&
              !allow_present(&pdb, "voboost", "su", "lnk_file",
                             bit_for(&pdb, "lnk_file", "getattr")) &&
              !allow_present(&pdb, "voboost", "su", "lnk_file",
                             bit_for(&pdb, "lnk_file", "write")),
          "peer executable link inspection grants only readlink permission");

    /* Keep the complete injection surface on the two exact target domains
     * system_app and signed launcher/system_server; reject domain attribute and
     * representative non-target domains. */
    uint32_t ptrace = bit_for(&pdb, "process", "ptrace");
    CHECK(allow_present(&pdb, "voboost", "system_app", "process", ptrace),
          "ptrace exact system_app target");
    CHECK(!allow_present(&pdb, "voboost", "domain", "process", ptrace),
          "no ptrace grant through domain attribute");
    CHECK(!allow_present(&pdb, "voboost", "untrusted_app", "process", ptrace) &&
              !allow_present(&pdb, "voboost", "system", "process", ptrace) &&
              !allow_present(&pdb, "voboost", "radio", "process", ptrace),
          "no ptrace grant to representative non-target domains");

    uint32_t proc_file = bit_for(&pdb, "file", "read") |
                         bit_for(&pdb, "file", "open") |
                         bit_for(&pdb, "file", "getattr");
    uint32_t proc_dir = bit_for(&pdb, "dir", "search") |
                        bit_for(&pdb, "dir", "read") |
                        bit_for(&pdb, "dir", "open") |
                        bit_for(&pdb, "dir", "getattr");
    CHECK(allow_present(&pdb, "voboost", "system_app", "file", proc_file),
          "proc regular-file access for exact system_app target");
    CHECK(allow_present(&pdb, "voboost", "system_app", "dir", proc_dir),
          "proc directory access for exact system_app target");
    CHECK(!allow_present(&pdb, "voboost", "domain", "file", proc_file) &&
              !allow_present(&pdb, "voboost", "domain", "dir", proc_dir),
          "no proc access through domain attribute");
    CHECK(!allow_present(&pdb, "voboost", "untrusted_app", "file", proc_file) &&
              !allow_present(&pdb, "voboost", "system", "dir", proc_dir),
          "no proc access to representative non-target domains");

    uint32_t lnk = bit_for(&pdb, "lnk_file", "read") |
                   bit_for(&pdb, "lnk_file", "open") |
                   bit_for(&pdb, "lnk_file", "getattr");
    CHECK(allow_present(&pdb, "voboost", "system_app", "lnk_file", lnk),
          "proc magic-link access for exact system_app target");
    CHECK(!allow_present(&pdb, "voboost", "domain", "lnk_file", lnk) &&
              !allow_present(&pdb, "voboost", "radio", "lnk_file", lnk),
          "no proc magic-link access to broad or unrelated domains");

    uint32_t payload_file = proc_file | bit_for(&pdb, "file", "execute") |
                            bit_for(&pdb, "file", "map");
    uint32_t payload_dir = bit_for(&pdb, "dir", "search") |
                           bit_for(&pdb, "dir", "getattr");
    CHECK(allow_present(&pdb, "system_app", "voboost_data_file", "file",
                        payload_file) &&
              allow_present(&pdb, "system_app", "voboost_data_file", "dir",
                            payload_dir),
          "exact system_app target can load the payload");
    CHECK(!allow_present(&pdb, "untrusted_app", "voboost_data_file", "file",
                         payload_file) &&
              !allow_present(&pdb, "system", "voboost_data_file", "dir",
                             payload_dir),
          "non-target domains cannot load the payload");

    CHECK(allow_present(&pdb, "voboost", "system_server", "process", ptrace) &&
              allow_present(&pdb, "voboost", "system_server", "file", proc_file) &&
              allow_present(&pdb, "voboost", "system_server", "dir", proc_dir) &&
              allow_present(&pdb, "voboost", "system_server", "lnk_file", lnk) &&
              allow_present(&pdb, "system_server", "voboost_data_file", "file", payload_file) &&
              allow_present(&pdb, "system_server", "voboost_data_file", "dir", payload_dir),
          "exact launcher system_server target has proc and payload authority");
    CHECK(!allow_present(&pdb, "voboost", "system_server", "process", bit_for(&pdb, "process", "signal")) &&
              !allow_present(&pdb, "voboost", "system_server", "file", bit_for(&pdb, "file", "write")),
          "system_server has no runtime signal or proc-write authority");

    uint32_t file_w = bit_for(&pdb, "file", "write") |
                      bit_for(&pdb, "file", "create");
    CHECK(allow_present(&pdb, "voboost", "voboost_data_file", "file", file_w),
          "data_file write");

    uint32_t relabel_file = bit_for(&pdb, "file", "read") |
                            bit_for(&pdb, "file", "open") |
                            bit_for(&pdb, "file", "getattr") |
                            bit_for(&pdb, "file", "relabelfrom") |
                            bit_for(&pdb, "file", "relabelto");
    uint32_t relabel_dir = bit_for(&pdb, "dir", "open") |
                           bit_for(&pdb, "dir", "getattr") |
                           bit_for(&pdb, "dir", "relabelfrom") |
                           bit_for(&pdb, "dir", "relabelto");
    /* Boot-1 chicken-and-egg: the relabeler binary itself still carries the
     * /data default label, so init needs execute and the relabeler domain
     * needs entrypoint on that exact type (firmwares where the type is
     * system_data_file; system_data_root_file-only rules are skipped as
     * missing-target there). */
    uint32_t bootstrap_exec = bit_for(&pdb, "file", "execute") |
                              bit_for(&pdb, "file", "read") |
                              bit_for(&pdb, "file", "open") |
                              bit_for(&pdb, "file", "getattr") |
                              bit_for(&pdb, "file", "map");
    CHECK(allow_present(&pdb, "init", "system_data_file", "file",
                        bootstrap_exec) &&
              allow_present(&pdb, "voboost_relabel", "system_data_file",
                            "file",
                            bootstrap_exec |
                                bit_for(&pdb, "file", "entrypoint") |
                                bit_for(&pdb, "file", "relabelfrom")),
          "boot-1 bootstrap exec on the /data default label");
    CHECK(allow_present(&pdb, "init", "init", "process",
                        bit_for(&pdb, "process", "transition") |
                            bit_for(&pdb, "process", "noatsecure") |
                            bit_for(&pdb, "process", "siginh") |
                            bit_for(&pdb, "process", "rlimitinh")),
          "bounds masking: init-self carries the exec transition set");
    CHECK(allow_present(&pdb, "voboost_relabel", "voboost_operation_file",
                        "file", relabel_file),
          "relabel can revisit an already labeled operation file");
    CHECK(allow_present(&pdb, "voboost_relabel", "voboost_generation_file",
                        "dir", relabel_dir) &&
              allow_present(&pdb, "voboost_relabel", "voboost_incoming_file",
                            "dir", relabel_dir),
          "relabel can revisit generation and incoming directories");
    uint32_t app_data_read = bit_for(&pdb, "dir", "search") |
                             bit_for(&pdb, "dir", "open") |
                             bit_for(&pdb, "dir", "getattr");
    CHECK(allow_present(&pdb, "voboost_relabel", "app_data_file", "dir",
                        app_data_read),
          "relabel reads the exact app-data MLS range");
    uint32_t app_data_observe = bit_for(&pdb, "dir", "search") |
                                bit_for(&pdb, "dir", "getattr");
    CHECK(allow_present(&pdb, "voboost_uninstall", "app_data_file", "dir",
                        app_data_observe),
          "voboost-uninstall observes package-data absence");
    CHECK(!allow_present(&pdb, "voboost_uninstall", "app_data_file", "dir",
                         bit_for(&pdb, "dir", "read") |
                             bit_for(&pdb, "dir", "open") |
                             bit_for(&pdb, "dir", "write") |
                             bit_for(&pdb, "dir", "remove_name") |
                             bit_for(&pdb, "dir", "rmdir")),
          "voboost-uninstall cannot enumerate or remove package data");
    CHECK(allow_present(&pdb, "voboost_uninstall", "system_data_file", "lnk_file",
                        bit_for(&pdb, "lnk_file", "read") |
                            bit_for(&pdb, "lnk_file", "getattr")),
          "voboost-uninstall resolves the fixed package-data compatibility alias");

    /* self-rules: ptrace/getsched/setsched/signal on own process. */
    uint32_t sigmask = bit_for(&pdb, "process", "ptrace") |
                       bit_for(&pdb, "process", "getsched") |
                       bit_for(&pdb, "process", "setsched") |
                       bit_for(&pdb, "process", "signal");
    CHECK(allow_present(&pdb, "voboost", "voboost", "process", sigmask),
          "self process perms");
    uint32_t resident_caps = bit_for(&pdb, "capability", "sys_ptrace") |
                             bit_for(&pdb, "capability", "dac_override");
    CHECK(allow_present(&pdb, "voboost", "voboost", "capability",
                        resident_caps),
          "resident capabilities");
    uint32_t teardown_caps = bit_for(&pdb, "capability", "sys_admin");
    CHECK(!allow_present(&pdb, "voboost", "voboost", "capability",
                         teardown_caps),
          "resident has no teardown capabilities");
    CHECK(allow_present(&pdb, "voboost_uninstall", "voboost_uninstall",
                        "capability", teardown_caps),
          "voboost-uninstall owns teardown capabilities");
    /* voboost-uninstall requests the terminal reboot itself
     * ("avc: denied { sys_boot } scontext=voboost_uninstall"). */
    CHECK(allow_present(&pdb, "voboost_uninstall", "voboost_uninstall",
                        "capability", bit_for(&pdb, "capability", "sys_boot")),
          "voboost-uninstall owns the terminal reboot capability");

    uint32_t protected_read = bit_for(&pdb, "file", "read") |
                              bit_for(&pdb, "file", "open") |
                              bit_for(&pdb, "file", "getattr");
    CHECK(allow_present(&pdb, "voboost", "voboost_uninstall_data_file",
                        "file", protected_read),
          "resident reads protected uninstall authority");
    CHECK(!allow_present(&pdb, "voboost", "voboost_uninstall_data_file",
                         "file", bit_for(&pdb, "file", "write")),
          "resident cannot write protected uninstall authority");
    CHECK(!allow_present(&pdb, "voboost", "voboost_uninstall_data_file",
                         "file", bit_for(&pdb, "file", "unlink") |
                                     bit_for(&pdb, "file", "rename") |
                                     bit_for(&pdb, "file", "append") |
                                     bit_for(&pdb, "file", "setattr")),
          "resident cannot replace protected committed authority");
    uint32_t protected_dir_runtime = bit_for(&pdb, "dir", "search") |
                                     bit_for(&pdb, "dir", "read") |
                                     bit_for(&pdb, "dir", "open") |
                                     bit_for(&pdb, "dir", "getattr");
    CHECK(allow_present(&pdb, "voboost", "voboost_uninstall_data_file",
                        "dir", protected_dir_runtime),
          "resident traverses protected uninstall authority");
    CHECK(!allow_present(&pdb, "voboost", "voboost_uninstall_data_file",
                         "dir", bit_for(&pdb, "dir", "write") |
                                    bit_for(&pdb, "dir", "add_name") |
                                    bit_for(&pdb, "dir", "remove_name") |
                                    bit_for(&pdb, "dir", "rename")),
          "resident cannot mutate protected uninstall directory");
    CHECK(allow_present(&pdb, "voboost_uninstall",
                        "voboost_uninstall_data_file", "file", file_w),
          "voboost-uninstall writes protected uninstall authority");
    uint32_t execute_no_transition = bit_for(&pdb, "file", "execute") |
                                     bit_for(&pdb, "file", "execute_no_trans");
    CHECK(!allow_present(&pdb, "voboost_uninstall", "voboost_selinux_exec",
                         "file", execute_no_transition),
          "voboost-uninstall cannot execute the install-only SELinux program");
    CHECK(!allow_present(&pdb, "su", "voboost_selinux_exec", "file",
                         execute_no_transition),
          "su cannot execute the fixed SELinux program directly");
    CHECK(!allow_present(&pdb, "su", "voboost_uninstall_data_file", "file",
                         bit_for(&pdb, "file", "write") |
                             bit_for(&pdb, "file", "create") |
                             bit_for(&pdb, "file", "unlink") |
                             bit_for(&pdb, "file", "rename")),
          "su cannot mutate protected uninstall authority");
    CHECK(!allow_present(&pdb, "voboost", "system_file", "file",
                         bit_for(&pdb, "file", "write")),
          "resident cannot rewrite stock-labeled recovery authority");

    CHECK(allow_present(&pdb, "voboost", "ctl_start_prop",
                        "property_service",
                        bit_for(&pdb, "property_service", "set")),
          "resident owns exact ctl.start grant");
    CHECK(allow_present(&pdb, "voboost_uninstall", "ctl_stop_prop",
                        "property_service",
                        bit_for(&pdb, "property_service", "set")),
          "voboost-uninstall owns exact ctl.stop grant");
    uint32_t execute_no_trans = bit_for(&pdb, "file", "execute") |
                                bit_for(&pdb, "file", "execute_no_trans");
    CHECK(allow_present(&pdb, "voboost_uninstall", "shell_exec", "file",
                        execute_no_trans),
          "voboost-uninstall can execute its bounded package-tool shell");
    CHECK(!allow_present(&pdb, "voboost_uninstall", "shell_exec", "file",
                         bit_for(&pdb, "file", "entrypoint")) &&
          allow_present(&pdb, "init", "init", "process",
                        bit_for(&pdb, "process", "setexec")),
          "terminal successor enters only through signed uninstall exec");
    CHECK(allow_present(&pdb, "voboost_uninstall", "system_file", "file",
                        execute_no_trans),
          "voboost-uninstall can execute the fixed pm wrapper");
    CHECK(allow_present(&pdb, "voboost_uninstall", "zygote_exec", "file",
                        execute_no_trans),
          "voboost-uninstall can execute pm app_process");
    CHECK(allow_present(&pdb, "voboost_uninstall", "voboost", "process",
                        bit_for(&pdb, "process", "signal")),
          "voboost-uninstall can stop the exact resident daemon");
    uint32_t durable_parent = bit_for(&pdb, "dir", "search") |
                              bit_for(&pdb, "dir", "read") |
                              bit_for(&pdb, "dir", "open") |
                              bit_for(&pdb, "dir", "write") |
                              bit_for(&pdb, "dir", "remove_name");
    CHECK(allow_present(&pdb, "voboost_uninstall", "system_file", "dir",
                        durable_parent),
          "voboost-uninstall can durably remove the init hook and SELinux program");
    CHECK(allow_present(&pdb, "voboost_uninstall", "vendor_file", "dir",
                        durable_parent),
          "voboost-uninstall can durably publish the pristine policy");
    CHECK(allow_present(&pdb, "su", "voboost_data_file", "dir",
                        bit_for(&pdb, "dir", "lock")),
          "signed SELinux program can lock the retained root-zone authority");

    /* App writer into incoming staging. */
    CHECK(allow_present(&pdb, "untrusted_app_25", "voboost_incoming_file",
                        "file", file_w),
          "untrusted_app_25 writes incoming");

    /* Process transition init -> voboost_exec -> voboost. */
    class_datum_t *proc_cls = get_class(&pdb, "process");
    avtab_key_t tkey = {
        .source_type = (uint16_t)(val(&pdb, "init")),
        .target_type = (uint16_t)(ve),
        .target_class = (uint16_t)(proc_cls->s.value),
        .specified = AVTAB_TRANSITION,
    };
    avtab_datum_t *td = avtab_search(&pdb.te_avtab, &tkey);
    CHECK(td && td->data == v, "init exec transition to voboost");

    uint32_t ue = val(&pdb, "voboost_uninstall_exec");
    avtab_key_t ukey = {
        .source_type = (uint16_t)(val(&pdb, "init")),
        .target_type = (uint16_t)(ue),
        .target_class = (uint16_t)(proc_cls->s.value),
        .specified = AVTAB_TRANSITION,
    };
    avtab_datum_t *utd = avtab_search(&pdb.te_avtab, &ukey);
    CHECK(utd && utd->data == u,
          "init exec transition to voboost_uninstall");

    avtab_key_t sukey = {
        .source_type = (uint16_t)(val(&pdb, "su")),
        .target_type = (uint16_t)(ue),
        .target_class = (uint16_t)(proc_cls->s.value),
        .specified = AVTAB_TRANSITION,
    };
    avtab_datum_t *sutd = avtab_search(&pdb.te_avtab, &sukey);
    CHECK(sutd && sutd->data == u,
          "su exec transition enters voboost_uninstall");

    /* Runtime-created transaction inodes must receive purpose labels at
     * creation time; restorecon/file_contexts then preserves the same mapping
     * across post-fs-data and reboot. */
    int found_ft = 0;
    int result_tmp = 0;
    int incoming_next = 0;
    int operation_tmp = 0;
    int install_root = 0;
    int installed_state_tmp = 0;
    int recovery_root = 0;
    int update_candidate = 0;
    int update_journal_tmp = 0;
    for (filename_trans_t *ft = pdb.filename_trans; ft; ft = ft->next) {
        if (ft->stype == v && ft->ttype == val(&pdb, "voboost_data_file") &&
            !strcmp(ft->name, "generations") &&
            ft->otype == val(&pdb, "voboost_generation_file")) {
            found_ft = 1;
        }
        result_tmp |= ft->stype == v &&
                      ft->ttype == val(&pdb, "voboost_data_file") &&
                      !strcmp(ft->name, ".desktop-uninstall-result.json.tmp") &&
                      ft->otype == val(&pdb, "voboost_uninstall_result_file");
        incoming_next |=
            ft->stype == v &&
            ft->ttype == val(&pdb, "voboost_generation_file") &&
            !strcmp(ft->name, "next") &&
            ft->otype == val(&pdb, "voboost_incoming_file");
        operation_tmp |= ft->stype == v &&
                         ft->ttype == val(&pdb, "voboost_data_file") &&
                         !strcmp(ft->name, ".operation.json.tmp") &&
                         ft->otype == val(&pdb, "voboost_operation_file");
        install_root |= ft->stype == v &&
                        ft->ttype == val(&pdb, "voboost_data_file") &&
                        !strcmp(ft->name, "install") &&
                        ft->otype == val(&pdb, "voboost_install_root_dir");
        installed_state_tmp |= ft->stype == v &&
                               ft->ttype == val(&pdb, "voboost_install_root_dir") &&
                               !strcmp(ft->name, ".state.json.tmp") &&
                               ft->otype == val(&pdb, "voboost_installed_state_file");
        recovery_root |= ft->stype == v &&
                         ft->ttype == val(&pdb, "voboost_data_file") &&
                         !strcmp(ft->name, "recovery") &&
                         ft->otype == val(&pdb, "voboost_recovery_file");
        update_candidate |=
            ft->stype == v &&
            ft->ttype == val(&pdb, "voboost_install_staging_file") &&
            !strcmp(ft->name, "candidate") &&
            ft->otype == val(&pdb, "voboost_update_staging_file");
        update_journal_tmp |=
            ft->stype == v &&
            ft->ttype == val(&pdb, "voboost_install_staging_file") &&
            !strcmp(ft->name, ".update-journal.json.tmp") &&
            ft->otype == val(&pdb, "voboost_update_staging_file");
    }
    CHECK(result_tmp, "desktop result temp has isolated named transition");
    CHECK(allow_present(&pdb, "voboost", "voboost_uninstall_result_file",
                        "file", bit_for(&pdb, "file", "create") | bit_for(&pdb, "file", "write") |
                        bit_for(&pdb, "file", "rename")), "runtime can publish isolated result");
    CHECK(!allow_present(&pdb, "voboost", "voboost_uninstall_result_file",
                         "file", bit_for(&pdb, "file", "relabelfrom") | bit_for(&pdb, "file", "relabelto")),
          "runtime cannot relabel result");
    CHECK(allow_present(&pdb, "voboost_uninstall", "voboost_uninstall_result_file",
                        "file", bit_for(&pdb, "file", "getattr") | bit_for(&pdb, "file", "unlink")),
          "terminal uninstall can stat and remove the isolated desktop result");
    const char *result_private[] = {"read", "write", "open", "create", "relabelfrom", "relabelto"};
    for (size_t i = 0; i < sizeof(result_private) / sizeof(result_private[0]); ++i) {
        CHECK(!allow_present(&pdb, "voboost_uninstall", "voboost_uninstall_result_file",
                             "file", bit_for(&pdb, "file", result_private[i])),
              "terminal uninstall only needs metadata and removal for the isolated result");
    }
    CHECK(found_ft, "filename transition generations");
    CHECK(incoming_next, "filename transition incoming generation");
    CHECK(operation_tmp, "atomic operation descriptor temp transition");
    CHECK(install_root, "runtime install root transition");
    CHECK(installed_state_tmp, "installed state temporary file transition");
    CHECK(recovery_root, "runtime recovery root transition");
    CHECK(update_candidate, "update-owned candidate transition");
    CHECK(update_journal_tmp, "atomic update journal temp transition");
    /* Idempotency: second inject is a no-op that keeps the policy valid. */
    CHECK(voboost_policy_inject(&pdb) == 0, "second inject succeeds");
    CHECK(val(&pdb, "voboost") == v, "no duplicate voboost type");

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    fprintf(stderr, "all policy-inject tests passed\n");
    return 0;
}
