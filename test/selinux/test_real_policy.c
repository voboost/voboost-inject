/* test_real_policy.c — roundtrip + inject test against a real firmware policy
 * dump (f0506h free-09-chinese-6.0.3, policy v30 with ioctl xperms entries).
 *
 * Stages:
 *  1. read dump;
 *  2. write to memory, re-read, compare nel counters (roundtrip stability);
 *  3. inject voboost rules, verify the voboost type exists, write succeeds;
 *  4. re-read the injected policy, verify voboost_policy_applied() == 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include "policy_inject.h"

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path); exit(2);
    }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) {
        fprintf(stderr, "short read\n"); exit(2);
    }
    fclose(f); *len = (size_t)n; return buf;
}

static policydb_t *read_mem(unsigned char *buf, size_t len) {
    policydb_t *pdb = calloc(1, sizeof(*pdb));
    if (!pdb) {
        exit(2);
    }
    if (policydb_init(pdb)) {
        fprintf(stderr, "FAIL: policydb_init\n"); exit(1);
    }
    struct sepol_policy_file *spf = NULL;
    sepol_policy_file_create(&spf);
    sepol_policy_file_set_mem(spf, (char *)buf, len);
    if (policydb_read(pdb, (struct policy_file *)spf, 0)) {
        fprintf(stderr, "FAIL: policydb_read\n"); exit(1);
    }
    sepol_policy_file_free(spf);
    return pdb;
}

static void require_qnx_tcp_client(policydb_t *pdb);
static int filename_transition_has(policydb_t *pdb, const char *source,
                                   const char *parent, const char *class_name,
                                   const char *filename, const char *target);

static unsigned char *write_mem(policydb_t *pdb, size_t *len) {
    char temporary[] = "build/host/policy-roundtrip-XXXXXX";
    int temporary_fd = mkstemp(temporary);
    FILE *mf = temporary_fd < 0 ? NULL : fdopen(temporary_fd, "w+b");
    unlink(temporary);
    if (!mf) {
        perror("tmpfile"); exit(2);
    }
    struct sepol_policy_file *spf = NULL;
    sepol_policy_file_create(&spf);
    sepol_policy_file_set_fp(spf, mf);
    if (policydb_write(pdb, (struct policy_file *)spf)) {
        fprintf(stderr, "FAIL: policydb_write\n"); exit(1);
    }
    sepol_policy_file_free(spf);
    fflush(mf);
    long n = ftell(mf);
    rewind(mf);
    unsigned char *data = malloc(n);
    if (!data || fread(data, 1, n, mf) != (size_t)n) {
        fprintf(stderr, "short read\n"); exit(2);
    }
    fclose(mf);
    *len = (size_t)n;
    return data;
}

static uint32_t type_value(policydb_t *pdb, const char *name) {
    type_datum_t *type = hashtab_search(pdb->p_types.table, name);
    return type ? type->s.value : 0;
}

static uint32_t permission_bit(class_datum_t *class_datum, const char *name) {
    perm_datum_t *permission =
        hashtab_search(class_datum->permissions.table, name);
    if (!permission && class_datum->comdatum) {
        permission = hashtab_search(class_datum->comdatum->permissions.table,
                                    name);
    }
    return permission ? 1u << (permission->s.value - 1) : 0;
}

static int effective_allow_has(policydb_t *pdb, const char *source,
                               const char *target, const char *class_name,
                               const char *permission_a,
                               const char *permission_b) {
    class_datum_t *class_datum =
        hashtab_search(pdb->p_classes.table, class_name);
    if (!class_datum) {
        return 0;
    }
    uint32_t bits = permission_bit(class_datum, permission_a);
    if (permission_b) {
        bits |= permission_bit(class_datum, permission_b);
    }
    uint32_t source_value = type_value(pdb, source);
    uint32_t target_value = type_value(pdb, target);
    if (!bits || !source_value || !target_value) {
        return 0;
    }
    struct sepol_av_decision decision = {0};
    avtab_key_t key = {
        .target_class = (uint16_t)class_datum->s.value,
        .specified = AVTAB_AV,
    };
    ebitmap_t *source_attributes = &pdb->type_attr_map[source_value - 1];
    ebitmap_t *target_attributes = &pdb->type_attr_map[target_value - 1];
    ebitmap_node_t *source_node, *target_node;
    unsigned int source_bit, target_bit;
    ebitmap_for_each_bit(source_attributes, source_node, source_bit) {
        if (!ebitmap_node_get_bit(source_node, source_bit)) {
            continue;
        }
        ebitmap_for_each_bit(target_attributes, target_node, target_bit) {
            if (!ebitmap_node_get_bit(target_node, target_bit)) {
                continue;
            }
            key.source_type = (uint16_t)(source_bit + 1);
            key.target_type = (uint16_t)(target_bit + 1);
            for (avtab_ptr_t node = avtab_search_node(&pdb->te_avtab, &key);
                 node; node = avtab_search_node_next(node, key.specified)) {
                if (node->key.specified == AVTAB_ALLOWED) {
                    decision.allowed |= node->datum.data;
                }
            }
            cond_compute_av(&pdb->te_cond_avtab, &key, &decision);
        }
    }
    return (decision.allowed & bits) == bits;
}

/* Newly injected types precede rebuild of the value-to-name index. */
static const char *block_test_type_name(policydb_t *pdb, uint32_t value) {
    hashtab_t table = pdb->p_types.table;
    for (unsigned int i = 0; i < table->size; ++i) {
        for (hashtab_ptr_t node = table->htable[i]; node; node = node->next) {
            type_datum_t *type = node->datum;
            if (type->s.value == value && type->flavor == TYPE_TYPE) {
                return node->key;
            }
        }
    }
    fprintf(stderr, "FAIL: missing type name for block test value %u\n", value);
    exit(1);
}

static void require_qnx_tcp_client(policydb_t *pdb) {
    const char *port_type = NULL;
    for (ocontext_t *o = pdb->ocontexts[OCON_PORT]; o; o = o->next) {
        if (o->u.port.protocol == 6 && o->u.port.low_port <= 8000 &&
            o->u.port.high_port >= 8000) {
            port_type = block_test_type_name(pdb, o->context[0].type);
            break;
        }
    }
    if (!port_type) {
        for (ocontext_t *o = pdb->ocontexts[OCON_ISID]; o; o = o->next)
            if (o->sid[0] == SECINITSID_PORT)
                port_type = block_test_type_name(pdb, o->context[0].type);
    }
    if (!port_type || strcmp(port_type, "port")) {
        fprintf(stderr, "FAIL: QNX TCP8000 fixture port context changed\n"); exit(1);
    }
    const char *client[] = {"create", "connect", "read", "write", "getopt", "setopt", "shutdown"};
    const char *server[] = {"bind", "listen", "accept"};
    for (unsigned i = 0; i < sizeof(client)/sizeof(client[0]); i++)
        if (!effective_allow_has(pdb, "voboost", "voboost", "tcp_socket", client[i], NULL)) {
            fprintf(stderr, "FAIL: missing QNX TCP client %s\n", client[i]); exit(1);
        }
    if (!effective_allow_has(pdb, "voboost", port_type, "tcp_socket", "name_connect", NULL)) {
        fprintf(stderr, "FAIL: missing QNX port name_connect\n"); exit(1);
    }
    for (unsigned i = 0; i < sizeof(server)/sizeof(server[0]); i++)
        if (effective_allow_has(pdb, "voboost", "voboost", "tcp_socket", server[i], NULL)) {
            fprintf(stderr, "FAIL: unexpected QNX TCP server %s\n", server[i]); exit(1);
        }
    if (effective_allow_has(pdb, "voboost", "proc_net", "file", "read", NULL)) {
        fprintf(stderr, "FAIL: unexpected QNX proc_net access\n"); exit(1);
    }
}

/* Android common kernel bounds model: each source parent is compared with
 * the corresponding target parent when one exists. This is not MLS or
 * proof of the loaded OEM kernel implementation. */
static int bounded_allow_has(policydb_t *pdb, uint32_t source, uint32_t target,
                             const char *class_name, const char *permission) {
    if (!source || !target || source > pdb->p_types.nprim || target > pdb->p_types.nprim)
        return 0;
    for (uint32_t depth = 0; source && depth < pdb->p_types.nprim; ++depth) {
        if (!effective_allow_has(pdb, block_test_type_name(pdb, source),
                                 block_test_type_name(pdb, target),
                                 class_name, permission, NULL)) return 0;
        uint32_t parent = pdb->type_val_to_struct[source - 1]->bounds;
        if (!parent) return 1;
        uint32_t target_parent = pdb->type_val_to_struct[target - 1]->bounds;
        source = parent;
        if (target_parent) target = target_parent;
    }
    return 0;
}

static void require_ota_socket_isolation(policydb_t *pdb) {
    const char *label = "voboost_ota_socket";
    const char *socket = "unix_stream_socket";
    uint32_t type = type_value(pdb, label);
    if (!type || pdb->type_val_to_struct[type - 1]->bounds ||
        !effective_allow_has(pdb, "untrusted_app", label, socket, "connectto", NULL) ||
        effective_allow_has(pdb, "untrusted_app", "init", socket, "connectto", NULL) ||
        !bounded_allow_has(pdb, type_value(pdb, "voboost"), type, socket, "create") ||
        !bounded_allow_has(pdb, type_value(pdb, "voboost"),
                          type_value(pdb, "voboost"), "process", "setsockcreate")) {
        fprintf(stderr, "FAIL: OTA listener label or bounded access differs\n");
        exit(1);
    }
}

static int bounded_block_ioctl_av(policydb_t *pdb, uint32_t source,
                                  uint32_t target) {
    return bounded_allow_has(pdb, source, target, "blk_file", "ioctl");
}

static void require_uninstall_result_access(policydb_t *pdb) {
    const char *result = "voboost_uninstall_result_file";
    const char *readers[] = { "su", "voboost", "voboost_relabel" };
    const char *read_permissions[] = { "read", "open", "getattr" };
    for (unsigned i = 0; i < sizeof(readers) / sizeof(readers[0]); ++i)
        for (unsigned j = 0; j < sizeof(read_permissions) / sizeof(read_permissions[0]); ++j)
            if (!bounded_allow_has(pdb, type_value(pdb, readers[i]), type_value(pdb, result),
                                   "file", read_permissions[j])) {
                fprintf(stderr, "FAIL: uninstall result reader %s lacks %s\n",
                        readers[i], read_permissions[j]);
                exit(1);
            }
    const char *mutations[] = { "create", "write", "append", "setattr", "unlink", "rename",
                                "relabelfrom", "relabelto" };
    for (unsigned i = 0; i < sizeof(mutations) / sizeof(mutations[0]); ++i)
        if (effective_allow_has(pdb, "su", result, "file", mutations[i], NULL)) {
            fprintf(stderr, "FAIL: uninstall result root observer can %s\n", mutations[i]);
            exit(1);
        }
    const char *untrusted[] = { "shell", "untrusted_app", "untrusted_app_25",
                                "untrusted_app_27", "untrusted_app_29", "system_app" };
    for (unsigned i = 0; i < sizeof(untrusted) / sizeof(untrusted[0]); ++i)
        for (unsigned j = 0; j < sizeof(read_permissions) / sizeof(read_permissions[0]); ++j)
            if (effective_allow_has(pdb, untrusted[i], result, "file", read_permissions[j], NULL)) {
                fprintf(stderr, "FAIL: uninstall result exposed to %s: %s\n",
                        untrusted[i], read_permissions[j]);
                exit(1);
            }
    const char *writer[] = { "create", "write", "setattr", "unlink", "rename" };
    for (unsigned i = 0; i < sizeof(writer) / sizeof(writer[0]); ++i)
        if (!bounded_allow_has(pdb, type_value(pdb, "voboost"), type_value(pdb, result),
                               "file", writer[i])) {
            fprintf(stderr, "FAIL: uninstall result producer lacks %s\n", writer[i]);
            exit(1);
        }
    if (!bounded_allow_has(pdb, type_value(pdb, "voboost_uninstall"), type_value(pdb, result),
                           "file", "getattr") ||
        !bounded_allow_has(pdb, type_value(pdb, "voboost_uninstall"), type_value(pdb, result),
                           "file", "unlink") ||
        effective_allow_has(pdb, "voboost_uninstall", result, "file", "read", NULL) ||
        !filename_transition_has(pdb, "voboost", "voboost_data_file", "file",
                                 ".desktop-uninstall-result.json.tmp", result)) {
        fprintf(stderr, "FAIL: uninstall result producer/terminal cleanup boundary differs\n");
        exit(1);
    }
    printf("uninstall result access ok: root observer readonly, trusted lifecycle owners bounded\n");
}

static int effective_device_ioctl_has(policydb_t *pdb, const char *source,
                                     const char *target, const char *class_name,
                                     uint16_t command) {
    uint32_t s = type_value(pdb, source), t = type_value(pdb, target);
    class_datum_t *cls = hashtab_search(pdb->p_classes.table, class_name);
    if (!s || !t || !cls || !bounded_allow_has(pdb, s, t, class_name, "ioctl")) {
        return 0;
    }
    unsigned int extended = 0, allowed = 0;
    unsigned int driver = command >> 8, function = command & 255;
    ebitmap_t *sources = &pdb->type_attr_map[s - 1];
    ebitmap_t *targets = &pdb->type_attr_map[t - 1];
    avtab_t *tables[] = { &pdb->te_avtab, &pdb->te_cond_avtab };
    for (size_t i = 0; i < 2; ++i) {
        for (unsigned int bucket = 0; bucket < tables[i]->nslot; ++bucket) {
            for (avtab_ptr_t node = tables[i]->htable[bucket]; node;
                 node = node->next) {
                if (node->key.target_class != cls->s.value ||
                    !(node->key.specified & AVTAB_OP) ||
                    (i && !(node->key.specified & AVTAB_ENABLED)) ||
                    !ebitmap_get_bit(sources, node->key.source_type - 1) ||
                    !ebitmap_get_bit(targets, node->key.target_type - 1)) {
                    continue;
                }
                extended = 1;
                if (!(node->key.specified & AVTAB_OPNUM_ALLOWED)) {
                    continue;
                }
                avtab_operations_t *ops = node->datum.ops;
                if (ops->specified == AVTAB_XPERMS_IOCTLDRIVER) {
                    allowed |= !!(ops->perms[driver / 32] &
                                   (1u << (driver % 32)));
                } else if (ops->specified == AVTAB_XPERMS_IOCTLFUNCTION &&
                           ops->driver == driver) {
                    allowed |= !!(ops->perms[function / 32] &
                                   (1u << (function % 32)));
                }
            }
        }
    }
    /* Zero extended entries differs from entries for a different driver. */
    return !extended || allowed;
}

static int effective_block_ioctl_has(policydb_t *pdb, const char *source,
                                     const char *target, uint16_t command) {
    return effective_device_ioctl_has(pdb, source, target, "blk_file", command);
}

static void free_test_permission(hashtab_key_t key, hashtab_datum_t datum, void *arg) {
    (void)arg;
    free(key);
    free(datum);
}

static void require_can_missing_permissions_rejected(unsigned char *bytes, size_t len) {
    const char *permissions[] = { "open", "read", "write", "getattr", "ioctl" };
    int failures = 0;
    for (unsigned i = 0; i < 5; ++i) {
        policydb_t *copy = read_mem(bytes, len);
        class_datum_t *cls = hashtab_search(copy->p_classes.table, "chr_file");
        hashtab_t table = cls->permissions.table;
        if (!hashtab_search(table, permissions[i]))
            table = cls->comdatum ? cls->comdatum->permissions.table : NULL;
        if (!table || hashtab_remove(table, permissions[i], free_test_permission, NULL) ||
            permission_bit(cls, permissions[i])) {
            fprintf(stderr, "FAIL: missing-permission fixture %s\n", permissions[i]); exit(1);
        }
        if (!voboost_policy_inject(copy)) {
            fprintf(stderr, "FAIL: CAN accepted missing %s\n", permissions[i]);
            ++failures;
        } else {
            printf("CAN missing %s rejected\n", permissions[i]);
        }
        policydb_destroy(copy); free(copy);
    }
    if (failures) exit(1);
}

/* Exercise a pre-existing unrestricted ancestor and a pre-existing child
 * function bitmap in private in-memory fixture copies. */
static void require_can_xperm_controls(unsigned char *bytes, size_t len) {
    policydb_t *copy = read_mem(bytes, len);
    uint32_t init = type_value(copy, "init"), target = type_value(copy, "can_device");
    class_datum_t *cls = hashtab_search(copy->p_classes.table, "chr_file");
    avtab_key_t key = { .source_type = init, .target_type = target,
        .target_class = cls->s.value, .specified = AVTAB_ALLOWED };
    avtab_datum_t *existing = avtab_search(&copy->te_avtab, &key);
    uint32_t bit = permission_bit(cls, "ioctl");
    if (existing) existing->data |= bit;
    else {
        avtab_datum_t datum = { .data = bit };
        if (avtab_insert(&copy->te_avtab, &key, &datum)) exit(1);
    }
    const uint16_t commands[] = { 0, 1, 2, 0x0101, 0xffff };
    int before[5];
    for (unsigned i = 0; i < 5; ++i) {
        before[i] = effective_device_ioctl_has(copy, "init", "can_device", "chr_file", commands[i]);
        if (!before[i]) { fprintf(stderr, "FAIL: unrestricted init control 0x%x\n", commands[i]); exit(1); }
    }
    if (voboost_policy_inject(copy)) { fprintf(stderr, "FAIL: synthetic CAN injection\n"); exit(1); }
    for (unsigned i = 0; i < 5; ++i) {
        if (before[i] && !effective_device_ioctl_has(copy, "init", "can_device", "chr_file", commands[i])) {
            fprintf(stderr, "FAIL: init ioctl narrowed 0x%x\n", commands[i]); exit(1);
        }
    }
    key.source_type = type_value(copy, "voboost");
    key.specified = AVTAB_OPNUM_ALLOWED;
    avtab_ptr_t node = avtab_search_node(&copy->te_avtab, &key);
    while (node && (!node->datum.ops || node->datum.ops->specified != AVTAB_XPERMS_IOCTLFUNCTION || node->datum.ops->driver != 0))
        node = avtab_search_node_next(node, AVTAB_OPNUM_ALLOWED);
    if (!node) { fprintf(stderr, "FAIL: missing child xperm\n"); exit(1); }
    node->datum.ops->perms[0] |= 1u << 2;
    if (voboost_policy_inject(copy) || !(node->datum.ops->perms[0] & (1u << 1)) ||
        !(node->datum.ops->perms[0] & (1u << 2))) {
        fprintf(stderr, "FAIL: child xperm merge\n"); exit(1);
    }
    key.source_type = type_value(copy, "domain");
    avtab_operations_t inherited = { .specified = AVTAB_XPERMS_IOCTLFUNCTION, .driver = 0 };
    inherited.perms[0] = 1u << 3;
    avtab_datum_t conditional_datum = { .ops = &inherited };
    avtab_ptr_t conditional = avtab_insert_nonunique(&copy->te_cond_avtab, &key, &conditional_datum);
    if (!conditional || effective_device_ioctl_has(copy, "voboost", "can_device", "chr_file", 3)) {
        fprintf(stderr, "FAIL: disabled inherited xperm\n"); exit(1);
    }
    conditional->key.specified |= AVTAB_ENABLED;
    if (!effective_device_ioctl_has(copy, "voboost", "can_device", "chr_file", 3) ||
        voboost_policy_inject(copy) ||
        !effective_device_ioctl_has(copy, "voboost", "can_device", "chr_file", 3)) {
        fprintf(stderr, "FAIL: inherited conditional xperm merge\n"); exit(1);
    }
    policydb_destroy(copy); free(copy);
    copy = read_mem(bytes, len);
    copy->policyvers = POLICYDB_VERSION_IOCTL_OPERATIONS - 1;
    if (!voboost_policy_inject(copy)) { fprintf(stderr, "FAIL: old policy accepted xperm\n"); exit(1); }
    policydb_destroy(copy); free(copy);
    printf("CAN xperm controls ok: init monotonicity, child merge, old policy rejection\n");
}

#ifdef VOBOOST_METADATA_BASELINE
extern int baseline_policy_inject(policydb_t *pdb);
static void require_metadata_baseline(policydb_t *pdb, unsigned char *bytes, size_t len) {
    policydb_t *baseline = read_mem(bytes, len);
    if (baseline_policy_inject(baseline)) { fprintf(stderr, "FAIL: baseline inject\n"); exit(1); }
    const char *sources[] = { "voboost", "init" };
    const char *classes[] = { "dir", "file", "process" };
    uint32_t domain = type_value(pdb, "domain");
    ebitmap_t *members = &pdb->attr_type_map[domain - 1];
    ebitmap_node_t *member; unsigned int target;
    ebitmap_for_each_bit(members, member, target) {
        if (!ebitmap_node_get_bit(member, target) || pdb->type_val_to_struct[target]->flavor != TYPE_TYPE) continue;
        const char *name = block_test_type_name(pdb, target + 1);
        for (unsigned si = 0; si < 2; ++si) for (unsigned ci = 0; ci < 3; ++ci) {
            class_datum_t *cls = hashtab_search(pdb->p_classes.table, classes[ci]);
            hashtab_t tables[] = { cls->permissions.table, cls->comdatum ? cls->comdatum->permissions.table : NULL };
            for (unsigned ti = 0; ti < 2; ++ti) {
                hashtab_t table = tables[ti]; if (!table) continue;
                for (unsigned bucket = 0; bucket < table->size; ++bucket)
                    for (hashtab_ptr_t node = table->htable[bucket]; node; node = node->next) {
                        const char *perm = node->key;
                        if (ci == 0 && !strcmp(perm, "getattr")) continue;
                        int before = effective_allow_has(baseline, sources[si], name, classes[ci], perm, NULL);
                        int after = effective_allow_has(pdb, sources[si], name, classes[ci], perm, NULL);
                        if (before != after) {
                            fprintf(stderr, "FAIL: metadata delta %s %s %s:%s\n", sources[si], name, classes[ci], perm); exit(1);
                        }
                    }
            }
        }
    }
    policydb_destroy(baseline); free(baseline);
    printf("metadata baseline ok: runtime and init all domain dir/file/process AV except getattr\n");
}
#endif

static void require_bounded_target_controls(policydb_t *pdb) {
    size_t len; unsigned char *bytes = write_mem(pdb, &len);
    policydb_t *copy = read_mem(bytes, len); free(bytes);
    uint32_t source = type_value(copy, "voboost"), target = type_value(copy, "can_device");
    uint32_t parent = type_value(copy, "init"), target_parent = type_value(copy, "kernel");
    class_datum_t *cls = hashtab_search(copy->p_classes.table, "process");
    const char *permissions[] = { "ptrace", "transition", "dyntransition", "setcurrent", "execmem", "setsched", "sigkill", "setexec" };
    const char *perm = NULL;
    for (unsigned i = 0; i < 8; ++i) {
        if (permission_bit(cls, permissions[i]) &&
            !effective_allow_has(copy, "voboost", "can_device", "process", permissions[i], NULL) &&
            !effective_allow_has(copy, "init", "kernel", "process", permissions[i], NULL) &&
            !effective_allow_has(copy, "init", "can_device", "process", permissions[i], NULL)) {
            perm = permissions[i]; break;
        }
    }
    if (!perm) { fprintf(stderr, "FAIL: no isolated bounds control permission\n"); exit(1); }
    copy->type_val_to_struct[target - 1]->bounds = target_parent;
    uint32_t bit = permission_bit(cls, perm);
    avtab_key_t key = { .source_type = source, .target_type = target,
        .target_class = cls->s.value, .specified = AVTAB_ALLOWED };
    avtab_datum_t datum = { .data = bit };
    avtab_datum_t *child = avtab_search(&copy->te_avtab, &key);
    if (child) child->data |= bit;
    else if (avtab_insert(&copy->te_avtab, &key, &datum)) exit(1);
    key.source_type = parent; key.target_type = target_parent;
    avtab_datum_t *ancestor = avtab_search(&copy->te_avtab, &key);
    if (!ancestor) {
        if (avtab_insert(&copy->te_avtab, &key, &datum)) exit(1);
        ancestor = avtab_search(&copy->te_avtab, &key);
    } else ancestor->data |= bit;
    if (!bounded_allow_has(copy, source, target, "process", perm)) {
        fprintf(stderr, "FAIL: bounded target parent/parent grant\n"); exit(1);
    }
    ancestor->data &= ~bit;
    if (bounded_allow_has(copy, source, target, "process", perm)) {
        fprintf(stderr, "FAIL: bounded target parent/parent denial\n"); exit(1);
    }
    key.source_type = parent; key.target_type = target;
    avtab_datum_t *unbounded = avtab_search(&copy->te_avtab, &key);
    if (unbounded) unbounded->data |= bit;
    else if (avtab_insert(&copy->te_avtab, &key, &datum)) exit(1);
    if (!bounded_allow_has(copy, parent, target, "process", perm)) {
        fprintf(stderr, "FAIL: unbounded source and bounded target\n"); exit(1);
    }
    policydb_destroy(copy); free(copy);
    printf("bounded target controls ok: grant, denial, unbounded source\n");
}

static void require_native_can_and_pid_metadata(policydb_t *pdb) {
    uint32_t can_runtime=type_value(pdb,"voboost");
    const char *receive_perms[]={"create","bind","read","setopt","getopt"};
    for(unsigned i=0;i<5;i++) {
        if(!bounded_allow_has(pdb,can_runtime,can_runtime,"netlink_crypto_socket",receive_perms[i])) {
            fprintf(stderr,"FAIL: raw CAN receive permission %s missing\n",receive_perms[i]);exit(1);
        }
    }
    if(bounded_allow_has(pdb,can_runtime,can_runtime,"netlink_crypto_socket","write")) {
        fprintf(stderr,"FAIL: passive CAN logger gained netlink write\n");exit(1);
    }
    const char *log_perms[]={"create","open","read","write","append","getattr","lock","rename","unlink"};
    for(unsigned i=0;i<9;i++) {
        if(!bounded_allow_has(pdb,can_runtime,type_value(pdb,"voboost_data_file"),"file",log_perms[i])) {
            fprintf(stderr,"FAIL: canonical CAN log permission %s missing\n",log_perms[i]);exit(1);
        }
    }
    uint32_t runtime_identity = type_value(pdb, "voboost");
    uint32_t manager_identity = type_value(pdb, "servicemanager");
    const char *identity_reads[] = { "open", "read", "getattr" };
    for (unsigned i = 0; i < 3; ++i) {
        if (!bounded_allow_has(pdb, runtime_identity, manager_identity, "file", identity_reads[i])) {
            fprintf(stderr, "FAIL: early service identity file:%s denied through bounds\n", identity_reads[i]);
            exit(1);
        }
    }
    if (!bounded_allow_has(pdb, runtime_identity, manager_identity, "dir", "search") ||
        !bounded_allow_has(pdb, runtime_identity, type_value(pdb, "tmpfs"), "dir", "search")) {
        fprintf(stderr, "FAIL: early input traversal denied through bounds\n");
        exit(1);
    }
    if (effective_allow_has(pdb, "voboost", "servicemanager", "file", "write", NULL) ||
        effective_allow_has(pdb, "voboost", "servicemanager", "process", "ptrace", NULL) ||
        effective_allow_has(pdb, "voboost", "servicemanager", "dir", "add_name", NULL) ||
        effective_allow_has(pdb, "voboost", "tmpfs", "dir", "add_name", NULL)) {
        fprintf(stderr, "FAIL: early input discovery gained mutation authority\n");
        exit(1);
    }
    if (!bounded_allow_has(pdb, runtime_identity, type_value(pdb, "system_app"), "process", "signull")) {
        fprintf(stderr, "FAIL: native transport liveness denied through bounds\n");
        exit(1);
    }
    const char *read_targets[] = { "su", "exported_dalvik_prop", "exported2_system_prop" };
    for (unsigned t = 0; t < 3; ++t) {
        for (unsigned p = 0; p < 3; ++p) {
            if (!bounded_allow_has(pdb, runtime_identity, type_value(pdb, read_targets[t]), "file", identity_reads[p])) {
                fprintf(stderr, "FAIL: runtime read %s:%s denied through bounds\n", read_targets[t], identity_reads[p]);
                exit(1);
            }
        }
        if (effective_allow_has(pdb, "voboost", read_targets[t], "file", "write", NULL)) {
            fprintf(stderr, "FAIL: runtime read gained write to %s\n", read_targets[t]);
            exit(1);
        }
    }
    const char *state_classes[] = { "dir", "dir", "dir", "dir", "file", "file", "file" };
    const char *state_reads[] = { "search", "getattr", "open", "read", "getattr", "open", "read" };
    for (unsigned i = 0; i < 7; ++i) {
        if (!effective_allow_has(pdb, "su", "voboost_agent_state_file", state_classes[i], state_reads[i], NULL)) {
            fprintf(stderr, "FAIL: passive state observer lacks %s:%s\n", state_classes[i], state_reads[i]);
            exit(1);
        }
    }
    if (effective_allow_has(pdb, "su", "voboost_agent_state_file", "dir", "add_name", NULL) ||
        effective_allow_has(pdb, "su", "voboost_agent_state_file", "file", "write", NULL) ||
        effective_allow_has(pdb, "su", "voboost_agent_state_file", "file", "unlink", NULL)) {
        fprintf(stderr, "FAIL: passive state observer gained mutation rights\n");
        exit(1);
    }
    const char *can_perms[] = { "open", "read", "write", "getattr", "ioctl" };
    for (unsigned i = 0; i < 5; ++i) {
        if (!bounded_allow_has(pdb, type_value(pdb, "voboost"),
                               type_value(pdb, "can_device"), "chr_file",
                               can_perms[i])) {
            fprintf(stderr, "FAIL: native CAN %s missing through bounds\n", can_perms[i]);
            exit(1);
        }
    }
    if (!effective_device_ioctl_has(pdb, "voboost", "can_device", "chr_file", 1)) {
        fprintf(stderr, "FAIL: native CAN ioctl1 missing\n");
        exit(1);
    }
    const unsigned short forbidden[] = { 0, 2, 0x0101, 0xffff };
    for (unsigned i = 0; i < 4; ++i) {
        if (effective_device_ioctl_has(pdb, "voboost", "can_device", "chr_file", forbidden[i])) {
            fprintf(stderr, "FAIL: native CAN unrelated ioctl 0x%x\n", forbidden[i]);
            exit(1);
        }
    }
    uint32_t runtime = type_value(pdb, "voboost");
    uint32_t domain = type_value(pdb, "domain");
    ebitmap_t *members = &pdb->attr_type_map[domain - 1];
    ebitmap_node_t *member; unsigned int member_bit;
    ebitmap_for_each_bit(members, member, member_bit) {
        if (!ebitmap_node_get_bit(member, member_bit) ||
            pdb->type_val_to_struct[member_bit]->flavor != TYPE_TYPE) continue;
        if (!bounded_allow_has(pdb, runtime, member_bit + 1, "dir", "getattr")) {
            fprintf(stderr, "FAIL: bounded PID metadata %s\n", pdb->p_type_val_to_name[member_bit]);
            exit(1);
        }
    }
    const char *domains[] = { "init", "kernel", "vendor_init", "untrusted_app" };
    const char *denied[] = { "search", "read", "open" };
    for (unsigned i = 0; i < 4; ++i) {
        if (!bounded_allow_has(pdb, type_value(pdb, "voboost"),
                               type_value(pdb, domains[i]), "dir", "getattr")) {
            fprintf(stderr, "FAIL: PID metadata getattr %s\n", domains[i]);
            exit(1);
        }
        for (unsigned j = 0; j < 3; ++j) {
            if (effective_allow_has(pdb, "voboost", domains[i], "dir", denied[j], NULL)) {
                fprintf(stderr, "FAIL: PID inventory expanded %s dir:%s\n", domains[i], denied[j]);
                exit(1);
            }
        }
        if (effective_allow_has(pdb, "voboost", domains[i], "file", "read", NULL) ||
            effective_allow_has(pdb, "voboost", domains[i], "process", "ptrace", NULL)) {
            fprintf(stderr, "FAIL: PID inventory expanded process/file authority %s\n", domains[i]);
            exit(1);
        }
    }
}

static void require_stock_block_ioctl_control(policydb_t *pdb) {
    if (!effective_allow_has(pdb, "su", "system_block_device", "blk_file",
                             "ioctl", NULL) ||
        !effective_block_ioctl_has(pdb, "su", "system_block_device", 0x125d) ||
        effective_block_ioctl_has(pdb, "su", "system_block_device", 0x125e)) {
        fprintf(stderr, "FAIL: stock su ioctl xperm negative control\n");
        exit(1);
    }
}

static void require_lifecycle_block_ioctls(policydb_t *pdb) {
    const char *domains[] = {
        "init", "voboost_install", "voboost_restore", "voboost_uninstall"
    };
    const char *targets[] = {
        "block_device", "system_block_device", "vendor_block_device"
    };
    require_stock_block_ioctl_control(pdb);
    for (size_t t = 0; t < 3; ++t) {
        if (!type_value(pdb, targets[t])) {
            continue; /* firmware-optional target */
        }
        for (size_t s = 0; s < 4; ++s) {
            if (!effective_block_ioctl_has(pdb, domains[s], targets[t], 0x125d) ||
                !effective_block_ioctl_has(pdb, domains[s], targets[t], 0x125e)) {
                fprintf(stderr, "FAIL: effective lifecycle BLKROSET/GET %s %s\n",
                        domains[s], targets[t]);
                exit(1);
            }
            if (s && effective_allow_has(pdb, domains[s], targets[t],
                                          "blk_file", "write", NULL)) {
                fprintf(stderr, "FAIL: lifecycle block write authority %s %s\n",
                        domains[s], targets[t]);
                exit(1);
            }
        }
        if (effective_block_ioctl_has(pdb, "voboost", targets[t], 0x125d) ||
            effective_block_ioctl_has(pdb, "voboost", targets[t], 0x125e)) {
            fprintf(stderr, "FAIL: runtime has block protection authority\n");
            exit(1);
        }
    }
}

static void require_block_ioctl_decision_controls(policydb_t *pdb) {
    /* Mutate only a throwaway in-memory policy: product policy stays exact. */
    size_t len;
    unsigned char *bytes = write_mem(pdb, &len);
    policydb_t *copy = read_mem(bytes, len);
    free(bytes);
    uint32_t s = type_value(copy, "voboost_restore");
    uint32_t t = type_value(copy, "system_block_device");
    uint32_t runtime = type_value(copy, "voboost");
    type_datum_t *domain = copy->type_val_to_struct[s - 1];
    uint32_t parent = domain->bounds;
    if (!parent || !effective_block_ioctl_has(copy, "voboost_restore",
                                             "system_block_device", 0x125e)) {
        fprintf(stderr, "FAIL: no-extended-entry control\n");
        exit(1);
    }
    /* Keep child plain AV; a denied bounded ancestor must mask it. */
    type_datum_t *ancestor = copy->type_val_to_struct[parent - 1];
    type_datum_t *denied = copy->type_val_to_struct[runtime - 1];
    uint32_t ancestor_bounds = ancestor->bounds, denied_bounds = denied->bounds;
    denied->bounds = 0;
    ancestor->bounds = runtime;
    if (!effective_allow_has(copy, "voboost_restore", "system_block_device",
                             "blk_file", "ioctl", NULL) ||
        effective_block_ioctl_has(copy, "voboost_restore",
                                  "system_block_device", 0x125e)) {
        fprintf(stderr, "FAIL: source ancestor bounds control\n");
        exit(1);
    }
    ancestor->bounds = ancestor_bounds;
    denied->bounds = denied_bounds;
    class_datum_t *cls = hashtab_search(copy->p_classes.table, "blk_file");
    uint32_t attribute = type_value(copy, "domain");
    if (!attribute || !ebitmap_get_bit(&copy->type_attr_map[s - 1], attribute - 1)) {
        fprintf(stderr, "FAIL: missing source attribute for ioctl control\n");
        exit(1);
    }
    avtab_key_t key = { .source_type = (uint16_t)attribute,
        .target_type = (uint16_t)t, .target_class = (uint16_t)cls->s.value,
        .specified = AVTAB_OPNUM_ALLOWED };
    avtab_operations_t ops = { .specified = AVTAB_XPERMS_IOCTLFUNCTION,
                               .driver = 0x13 };
    ops.perms[0x5d / 32] = 1u << (0x5d % 32);
    avtab_datum_t datum = { .ops = &ops };
    avtab_ptr_t conditional = avtab_insert_nonunique(&copy->te_cond_avtab,
                                                     &key, &datum);
    if (!conditional || !effective_block_ioctl_has(copy, "voboost_restore",
                                                    "system_block_device", 0x125d)) {
        fprintf(stderr, "FAIL: disabled conditional extended entry control\n");
        exit(1);
    }
    conditional->key.specified |= AVTAB_ENABLED;
    if (effective_block_ioctl_has(copy, "voboost_restore",
                                  "system_block_device", 0x125d)) {
        fprintf(stderr, "FAIL: enabled conditional extended entry control\n");
        exit(1);
    }
    conditional->key.specified &= ~AVTAB_ENABLED;
    avtab_ptr_t node = avtab_insert_nonunique(&copy->te_avtab, &key, &datum);
    if (!node || effective_block_ioctl_has(copy, "voboost_restore",
                                           "system_block_device", 0x125d)) {
        fprintf(stderr, "FAIL: other-driver extended entry control\n");
        exit(1);
    }
    node->datum.ops->driver = 0x12;
    if (!effective_block_ioctl_has(copy, "voboost_restore", "system_block_device", 0x125d) ||
        effective_block_ioctl_has(copy, "voboost_restore", "system_block_device", 0x125e)) {
        fprintf(stderr, "FAIL: function bitmap extended entry control\n");
        exit(1);
    }
    node->datum.ops->specified = AVTAB_XPERMS_IOCTLDRIVER;
    memset(node->datum.ops->perms, 0, sizeof(node->datum.ops->perms));
    node->datum.ops->perms[0] = 1u << 0x12;
    if (!effective_block_ioctl_has(copy, "voboost_restore", "system_block_device", 0x125d) ||
        !effective_block_ioctl_has(copy, "voboost_restore", "system_block_device", 0x125e)) {
        fprintf(stderr, "FAIL: driver bitmap extended entry control\n");
        exit(1);
    }
    policydb_destroy(copy);
    free(copy);
    printf("ioctl controls ok: stock restriction, bounds, absent/other driver, function/driver bitmap\n");
}

#define allow_has effective_allow_has

static void require_cache_directory_permissions(policydb_t *pdb) {
    const char *targets[] = { "rootfs", "proc", "system_data_root_file" };
    const char *permissions[] = { "open", "read", "search", "getattr" };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        /* system_data_root_file is absent on the retained Free09 policy. */
        if (!type_value(pdb, targets[i])) {
            continue;
        }
        for (size_t j = 0; j < sizeof(permissions) / sizeof(permissions[0]); j++) {
            class_datum_t *dir = hashtab_search(pdb->p_classes.table, "dir");
            avtab_key_t direct_key = {
                .source_type = (uint16_t)type_value(pdb, "voboost_uninstall"),
                .target_type = (uint16_t)type_value(pdb, targets[i]),
                .target_class = (uint16_t)dir->s.value,
                .specified = AVTAB_ALLOWED,
            };
            avtab_datum_t *direct = avtab_search(&pdb->te_avtab, &direct_key);
            uint32_t bit = permission_bit(dir, permissions[j]);
            /* Require an explicit grant: some firmware inherits proc access
             * from domain; another supported firmware need not do so. */
            if (!direct || !(direct->data & bit) || !allow_has(pdb, "voboost_uninstall", targets[i], "dir", permissions[j], NULL)) {
                fprintf(stderr, "FAIL: cache cleanup voboost_uninstall %s:dir %s\n", targets[i], permissions[j]);
                exit(1);
            }
        }
    }
    if (!allow_has(pdb, "voboost_uninstall", "voboost_uninstall", "capability", "sys_ptrace", NULL)) {
        fprintf(stderr, "FAIL: cache cleanup lacks proc READ capability\n");
        exit(1);
    }
    if (allow_has(pdb, "voboost_uninstall", "system_app", "process", "ptrace", NULL)) {
        fprintf(stderr, "FAIL: cache cleanup grants process attach authority\n");
        exit(1);
    }

}

static int domain_is_permissive(policydb_t *pdb, const char *source) {
    uint32_t value = type_value(pdb, source);
    return value && ebitmap_get_bit(&pdb->permissive_map, value);
}

static int effective_transition_has(policydb_t *pdb, const char *source,
                                    const char *entrypoint,
                                    const char *new_domain) {
    class_datum_t *process = hashtab_search(pdb->p_classes.table, "process");
    uint32_t source_value = type_value(pdb, source);
    uint32_t entrypoint_value = type_value(pdb, entrypoint);
    uint32_t new_value = type_value(pdb, new_domain);
    if (!process || !source_value || !entrypoint_value || !new_value) {
        return 0;
    }
    ebitmap_t *source_attributes = &pdb->type_attr_map[source_value - 1];
    ebitmap_t *entrypoint_attributes = &pdb->type_attr_map[entrypoint_value - 1];
    ebitmap_node_t *source_node, *entrypoint_node;
    unsigned int source_bit, entrypoint_bit;
    ebitmap_for_each_bit(source_attributes, source_node, source_bit) {
        if (!ebitmap_node_get_bit(source_node, source_bit)) {
            continue;
        }
        ebitmap_for_each_bit(entrypoint_attributes, entrypoint_node, entrypoint_bit) {
            if (!ebitmap_node_get_bit(entrypoint_node, entrypoint_bit)) {
                continue;
            }
            avtab_key_t key = {
                .source_type = (uint16_t)(source_bit + 1),
                .target_type = (uint16_t)(entrypoint_bit + 1),
                .target_class = (uint16_t)process->s.value,
                .specified = AVTAB_TRANSITION,
            };
            avtab_datum_t *datum = avtab_search(&pdb->te_avtab, &key);
            if (datum && datum->data == new_value) {
                return 1;
            }
        }
    }
    return 0;
}

static int filename_transition_has(policydb_t *pdb, const char *source,
                                   const char *parent, const char *class_name,
                                   const char *name, const char *result) {
    class_datum_t *class_datum =
        hashtab_search(pdb->p_classes.table, class_name);
    uint32_t source_value = type_value(pdb, source);
    uint32_t parent_value = type_value(pdb, parent);
    uint32_t result_value = type_value(pdb, result);
    if (!class_datum || !source_value || !parent_value || !result_value) {
        return 0;
    }
    for (filename_trans_t *ft = pdb->filename_trans; ft; ft = ft->next) {
        if (ft->stype == source_value && ft->ttype == parent_value &&
            ft->tclass == class_datum->s.value && ft->otype == result_value &&
            !strcmp(ft->name, name)) {
            return 1;
        }
    }
    return 0;
}

/* Kernel object creation uses a matching filename transition, then an unnamed
 * transition; otherwise the new object inherits its parent's type. */
static uint32_t created_directory_type(policydb_t *pdb, const char *source,
                                       const char *parent, const char *name) {
    class_datum_t *dir = hashtab_search(pdb->p_classes.table, "dir");
    uint32_t source_value = type_value(pdb, source);
    uint32_t parent_value = type_value(pdb, parent);
    if (!dir || !source_value || !parent_value) {
        return 0;
    }
    for (filename_trans_t *ft = pdb->filename_trans; ft; ft = ft->next) {
        if (ft->stype == source_value && ft->ttype == parent_value &&
            ft->tclass == dir->s.value && !strcmp(ft->name, name)) {
            return ft->otype;
        }
    }
    ebitmap_t *sources = &pdb->type_attr_map[source_value - 1];
    ebitmap_t *parents = &pdb->type_attr_map[parent_value - 1];
    ebitmap_node_t *sn, *pn;
    unsigned int sb, pb;
    ebitmap_for_each_bit(sources, sn, sb) {
        if (!ebitmap_node_get_bit(sn, sb)) {
            continue;
        }
        ebitmap_for_each_bit(parents, pn, pb) {
            if (!ebitmap_node_get_bit(pn, pb)) {
                continue;
            }
            avtab_key_t key = {
                .source_type = (uint16_t)(sb + 1),
                .target_type = (uint16_t)(pb + 1),
                .target_class = (uint16_t)dir->s.value,
                .specified = AVTAB_TRANSITION,
            };
            avtab_datum_t *datum = avtab_search(&pdb->te_avtab, &key);
            if (datum) {
                return datum->data;
            }
        }
    }
    return parent_value;
}

static int root_zone_rewrite_allowed(policydb_t *pdb, const char *source) {
    static const char *file_permissions[] = {
        "create", "write", "append", "unlink", "rename",
    };
    static const char *directory_permissions[] = {
        "create", "write", "add_name", "remove_name", "rename",
    };
    for (size_t i = 0; i < sizeof(file_permissions) / sizeof(file_permissions[0]); i++) {
        if (effective_allow_has(pdb, source, "voboost_data_file", "file",
                                file_permissions[i], NULL)) {
            return 1;
        }
    }
    for (size_t i = 0; i < sizeof(directory_permissions) / sizeof(directory_permissions[0]); i++) {
        if (effective_allow_has(pdb, source, "voboost_data_file", "dir",
                                directory_permissions[i], NULL)) {
            return 1;
        }
    }
    return 0;
}

static int resident_target_surface_complete(policydb_t *pdb,
                                            const char *target) {
    return effective_allow_has(pdb, "voboost", target, "process", "ptrace",
                               "sigstop") &&
           effective_allow_has(pdb, "voboost", target, "file", "read",
                               "open") &&
           effective_allow_has(pdb, "voboost", target, "file", "getattr",
                               NULL) &&
           effective_allow_has(pdb, "voboost", target, "dir", "search",
                               "read") &&
           effective_allow_has(pdb, "voboost", target, "dir", "open",
                               "getattr") &&
           effective_allow_has(pdb, "voboost", target, "lnk_file", "read",
                               "open") &&
           effective_allow_has(pdb, "voboost", target, "lnk_file", "getattr",
                               NULL);
}

static int resident_target_surface_any(policydb_t *pdb, const char *target) {
    static const char *const file_permissions[] = {"read", "open", "getattr"};
    static const char *const directory_permissions[] = {
        "search", "read", "open", "getattr",
    };
    static const char *const link_permissions[] = {"read", "open", "getattr"};
    if (effective_allow_has(pdb, "voboost", target, "process", "ptrace",
                            "sigstop")) {
        return 1;
    }
    for (size_t i = 0;
         i < sizeof(file_permissions) / sizeof(file_permissions[0]); i++) {
        if (!strcmp(target, "su") ||
            !strcmp(target, "servicemanager")) {
            continue;
        }
        if (effective_allow_has(pdb, "voboost", target, "file",
                                file_permissions[i], NULL)) {
            return 1;
        }
    }
    for (size_t i = 0;
         i < sizeof(directory_permissions) / sizeof(directory_permissions[0]);
         i++) {
        if (!strcmp(directory_permissions[i], "getattr") ||
            ((!strcmp(target, "su") || !strcmp(target, "servicemanager")) &&
             !strcmp(directory_permissions[i], "search"))) {
            continue;
        }
        if (effective_allow_has(pdb, "voboost", target, "dir",
                                directory_permissions[i], NULL)) {
            return 1;
        }
    }
    for (size_t i = 0;
         i < sizeof(link_permissions) / sizeof(link_permissions[0]); i++) {
        if (!strcmp(target, "su") && !strcmp(link_permissions[i], "read")) {
            continue;
        }
        if (effective_allow_has(pdb, "voboost", target, "lnk_file",
                                link_permissions[i], NULL)) {
            return 1;
        }
    }
    return 0;
}

static int resident_target_domain_is_exact(policydb_t *pdb) {
    uint32_t domain_value = type_value(pdb, "domain");
    uint32_t system_app_value = type_value(pdb, "system_app");
    uint32_t system_server_value = type_value(pdb, "system_server");
    uint32_t bluetooth_value = type_value(pdb, "bluetooth");
    if (!domain_value || !system_app_value || !system_server_value || !bluetooth_value ||
        !resident_target_surface_complete(pdb, "system_app") ||
        !resident_target_surface_complete(pdb, "system_server") ||
        !resident_target_surface_complete(pdb, "bluetooth")) {
        return 0;
    }
    ebitmap_t *domain_members = &pdb->attr_type_map[domain_value - 1];
    ebitmap_node_t *node;
    unsigned int bit;
    ebitmap_for_each_bit(domain_members, node, bit) {
        if (!ebitmap_node_get_bit(node, bit) || bit + 1 == system_app_value ||
            bit + 1 == system_server_value || bit + 1 == bluetooth_value) {
            continue;
        }
        const char *name = pdb->p_type_val_to_name[bit];
        if (name && resident_target_surface_any(pdb, name)) {
            fprintf(stderr,
                    "FAIL: resident target-process surface reaches non-target domain %s\n",
                    name);
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <policy-dump>\n", argv[0]); return 2;
    }

    size_t len;
    unsigned char *buf = slurp(argv[1], &len);
    policydb_t *pdb = read_mem(buf, len);
    printf("read ok: vers=%d types=%u avtab nel=%u\n",
           pdb->policyvers, pdb->p_types.nprim, pdb->te_avtab.nel);
    /* Types and attributes share this policy symbol table. Check before injection. */
    if (hashtab_search(pdb->p_types.table, "voboost") ||
        hashtab_search(pdb->p_types.table, "voboost_exec")) {
        fprintf(stderr, "FAIL: stock policy collides with Voboost domain symbols\n");
        return 1;
    }
    printf("stock collision check ok: voboost and voboost_exec symbols absent\n");
    uint32_t nel0 = pdb->te_avtab.nel, types0 = pdb->p_types.nprim;
    /* Free A9 stock permissions must not require extra bluetooth grants. */
    if (!effective_allow_has(pdb, "bluetooth", "bluetooth", "process", "execmem", NULL) ||
        !effective_allow_has(pdb, "bluetooth", "init", "process", "sigchld", NULL) ||
        !effective_allow_has(pdb, "bluetooth", "init", "unix_stream_socket", "connectto", NULL)) {
        fprintf(stderr, "FAIL: stock bluetooth trampoline or bounds support missing\n");
        return 1;
    }
    printf("stock bluetooth evidence ok: execmem and init socket/sigchld already allowed\n");

    require_stock_block_ioctl_control(pdb);
    require_can_missing_permissions_rejected(buf, len);
    require_can_xperm_controls(buf, len);

    /* Stock-policy evidence for the distinct partial-install recovery.
     * A bootstrap that is already running in su may execute system_file.
     * Android init itself cannot be treated as a post-reboot su bootstrap: the
     * canonical stock policy lacks the complete init -> su entry contract. */
    printf("stock init-to-su service: transition=%s setexec=%s system_file-entrypoint=%s\n",
           allow_has(pdb, "init", "su", "process", "transition", NULL) ? "allow" : "deny",
           allow_has(pdb, "init", "self", "process", "setexec", NULL) ? "allow" : "deny",
           allow_has(pdb, "su", "system_file", "file", "entrypoint", NULL) ? "allow" : "deny");
    printf("stock init shell transition=%s\n",
           effective_transition_has(pdb, "init", "shell_exec", "shell") ? "shell" : "absent");
    printf("stock init-to-su binary: execute=%s open-read=%s transition-permission=%s entrypoint=%s type-transition=%s\n",
           allow_has(pdb, "init", "su_exec", "file", "execute", NULL) ? "allow" : "deny",
           allow_has(pdb, "init", "su_exec", "file", "open", "read") ? "allow" : "deny",
           allow_has(pdb, "init", "su", "process", "transition", NULL) ? "allow" : "deny",
           allow_has(pdb, "su", "su_exec", "file", "entrypoint", NULL) ? "allow" : "deny",
           effective_transition_has(pdb, "init", "su_exec", "su") ? "su" : "absent");
    if (domain_is_permissive(pdb, "su") ||
        !allow_has(pdb, "su", "system_file", "file", "execute",
                   "execute_no_trans") ||
        !allow_has(pdb, "su", "system_file", "file", "open", "read") ||
        !allow_has(pdb, "su", "system_file", "file", "getattr", "unlink") ||
        !allow_has(pdb, "su", "system_file", "dir", "search", "write") ||
        !allow_has(pdb, "su", "system_file", "dir", "remove_name", NULL) ||
        !allow_has(pdb, "su", "system_data_file", "dir", "search", "write") ||
        !allow_has(pdb, "su", "system_data_file", "dir", "remove_name", NULL) ||
        !allow_has(pdb, "su", "system_data_file", "dir", "rmdir", NULL) ||
        !allow_has(pdb, "su", "vendor_file", "file", "open", "read") ||
        !allow_has(pdb, "su", "shell_exec", "file", "execute", "execute_no_trans") ||
        !allow_has(pdb, "su", "toolbox_exec", "file", "execute", "execute_no_trans") ||
        !allow_has(pdb, "su", "ctl_start_prop", "property_service", "set", NULL) ||
        !allow_has(pdb, "su", "powerctl_prop", "property_service", "set", NULL)) {
        fprintf(stderr, "FAIL: stock su cannot reach partial-install recovery\n");
        return 1;
    }
    printf("stock provisioning-recovery evidence ok: enforcing su can execute system_file, start the watchdog and request reboot\n");
    const char *repair_checks[][4] = {
        {"su", "system_file", "file", "create"},
        {"su", "system_file", "file", "write"},
        {"su", "system_file", "file", "rename"},
        {"su", "system_file", "file", "setattr"},
        {"su", "system_file", "dir", "add_name"},
        {"su", "vendor_file", "file", "create"},
        {"su", "vendor_file", "file", "write"},
        {"su", "vendor_file", "file", "unlink"},
        {"su", "vendor_file", "file", "rename"},
        {"su", "vendor_file", "file", "setattr"},
        {"su", "vendor_file", "dir", "search"},
        {"su", "vendor_file", "dir", "write"},
        {"su", "vendor_file", "dir", "add_name"},
        {"su", "vendor_file", "dir", "remove_name"},
        {"su", "self", "capability", "sys_admin"},
        {"su", "self", "capability", "sys_boot"},
        {"su", "kernel", "security", "load_policy"},
        {"su", "kernel", "security", "setenforce"},
    };
    int missing_sys_admin = 0, missing_sys_boot = 0;
    int missing_load_policy = 0, missing_setenforce = 0;
    for (size_t i = 0; i < sizeof(repair_checks) / sizeof(repair_checks[0]); i++) {
        int permitted = allow_has(pdb, repair_checks[i][0], repair_checks[i][1],
                                  repair_checks[i][2], repair_checks[i][3], NULL);
        printf("stock repair permission %s %s:%s %s=%s\n",
               repair_checks[i][0], repair_checks[i][1], repair_checks[i][2],
               repair_checks[i][3], permitted ? "allow" : "deny");
        if (!permitted) {
            if (!strcmp(repair_checks[i][3], "sys_admin")) {
                missing_sys_admin = 1;
            } else if (!strcmp(repair_checks[i][3], "sys_boot")) {
                missing_sys_boot = 1;
            } else if (!strcmp(repair_checks[i][3], "load_policy")) {
                missing_load_policy = 1;
            } else if (!strcmp(repair_checks[i][3], "setenforce")) {
                missing_setenforce = 1;
            } else {
                fprintf(stderr, "FAIL: stock repair additionally misses %s %s:%s %s\n",
                        repair_checks[i][0], repair_checks[i][1],
                        repair_checks[i][2], repair_checks[i][3]);
                return 1;
            }
        }
    }
    if (missing_setenforce) {
        fprintf(stderr, "FAIL: stock repair cannot enter its bounded permissive window\n");
        return 1;
    }
    printf("stock repair bounded-window evidence: setenforce=allow sys_admin=%s sys_boot=%s load_policy=%s\n",
           missing_sys_admin ? "deny-before-window" : "allow",
           missing_sys_boot ? "deny-before-window" : "allow",
           missing_load_policy ? "deny-before-window" : "allow");
    printf("stock repair reboot property: su powerctl_prop:property_service set=%s\n",
           allow_has(pdb, "su", "powerctl_prop", "property_service", "set", NULL)
               ? "allow"
               : "deny");
    int app_exec = allow_has(pdb, "untrusted_app_27", "su_exec", "file", "execute", NULL);
    int app_open = allow_has(pdb, "untrusted_app_27", "su_exec", "file", "open", "read");
    int app_transition_permission =
        allow_has(pdb, "untrusted_app_27", "su", "process", "transition", NULL);
    int su_entrypoint = allow_has(pdb, "su", "su_exec", "file", "entrypoint", NULL);
    int app_transition =
        effective_transition_has(pdb, "untrusted_app_27", "su_exec", "su");
    printf("stock app-to-su bootstrap: execute=%s open-read=%s process-transition=%s entrypoint=%s type-transition=%s\n",
           app_exec ? "allow" : "deny", app_open ? "allow" : "deny",
           app_transition_permission ? "allow" : "deny",
           su_entrypoint ? "allow" : "deny",
           app_transition ? "su" : "absent");
    int shell_exec = allow_has(pdb, "shell", "su_exec", "file", "execute", NULL);
    int shell_open = allow_has(pdb, "shell", "su_exec", "file", "open", "read");
    int shell_transition_permission =
        allow_has(pdb, "shell", "su", "process", "transition", NULL);
    int shell_transition = effective_transition_has(pdb, "shell", "su_exec", "su");
    printf("stock shell-to-su bootstrap: execute=%s open-read=%s process-transition=%s entrypoint=%s type-transition=%s\n",
           shell_exec ? "allow" : "deny", shell_open ? "allow" : "deny",
           shell_transition_permission ? "allow" : "deny",
           su_entrypoint ? "allow" : "deny",
           shell_transition ? "su" : "absent");
    printf("stock shell-to-su dynamic: execute-no-trans=%s setcurrent=%s dyntransition=%s\n",
           allow_has(pdb, "shell", "su_exec", "file", "execute_no_trans", NULL)
               ? "allow" : "deny",
           allow_has(pdb, "shell", "self", "process", "setcurrent", NULL)
               ? "allow" : "deny",
           allow_has(pdb, "shell", "su", "process", "dyntransition", NULL)
               ? "allow" : "deny");
    printf("stock app-to-su dynamic: execute-no-trans=%s setcurrent=%s dyntransition=%s\n",
           allow_has(pdb, "untrusted_app_27", "su_exec", "file", "execute_no_trans", NULL)
               ? "allow" : "deny",
           allow_has(pdb, "untrusted_app_27", "self", "process", "setcurrent", NULL)
               ? "allow" : "deny",
           allow_has(pdb, "untrusted_app_27", "su", "process", "dyntransition", NULL)
               ? "allow" : "deny");

    /* Roundtrip: write what we read, re-read, counters must match. */
    size_t rt_len;
    unsigned char *rt = write_mem(pdb, &rt_len);
    policydb_t *pdb2 = read_mem(rt, rt_len);
    if (pdb2->te_avtab.nel != nel0 || pdb2->p_types.nprim != types0) {
        fprintf(stderr, "FAIL: roundtrip counters differ (avtab %u->%u, types %u->%u)\n",
                nel0, pdb2->te_avtab.nel, types0, pdb2->p_types.nprim);
        return 1;
    }
    printf("roundtrip ok: avtab nel=%u (written %zu bytes vs original %zu)\n",
           pdb2->te_avtab.nel, rt_len, len);
    policydb_destroy(pdb2);
    free(rt);

    /* Inject on the fresh copy read from the original dump. */
    if (voboost_policy_applied(pdb) != 0) {
        fprintf(stderr, "FAIL: dump reports voboost policy already applied\n");
        return 1;
    }
    const char *execution_services[] = { "activity_service", "jobscheduler_service", "user_service" };
    int stock_su_execution_finds[3];
    for (size_t i = 0; i < 3; ++i) {
        stock_su_execution_finds[i] = allow_has(pdb, "su", execution_services[i],
                                               "service_manager", "find", NULL);
    }
    const char *cil_permissions[] = { "read", "open", "getattr", "write", "create", "unlink" };
    int stock_su_cil[6];
    for (size_t i = 0; i < 6; ++i)
        stock_su_cil[i] = effective_allow_has(pdb, "su", "sepolicy_file", "file", cil_permissions[i], NULL);
    const char *idmap_stock_permissions[] = { "read", "open", "getattr", "map", "write" };
    int idmap_stock_overlay[5];
    for (size_t i = 0; i < 5; ++i) {
        idmap_stock_overlay[i] = effective_allow_has(pdb, "idmap", "vendor_overlay_file",
                                                     "file", idmap_stock_permissions[i], NULL);
    }
    if (voboost_policy_inject(pdb) != 0) {
        fprintf(stderr, "FAIL: voboost_policy_inject\n");
        return 1;
    }
    /* Normal RRO permissions: exercise actual OEM bounds. */
    if (!filename_transition_has(pdb, "voboost_install", "vendor_overlay_file", "file",
                                 ".voboost-setting-ru.apk.staged", "voboost_resource_overlay_file") ||
        !filename_transition_has(pdb, "voboost_install", "vendor_overlay_file", "file",
                                 ".voboost-setting-ru-a11.apk.staged", "voboost_resource_overlay_file") ||
        filename_transition_has(pdb, "voboost_install", "vendor_overlay_file", "file",
                                ".voboost-setting-ru-a12.apk.staged", "voboost_resource_overlay_file") ||
        filename_transition_has(pdb, "voboost_install", "vendor_overlay_file", "file",
                                ".voboost-setting-ru-a11.apk.staged.other", "voboost_resource_overlay_file")) {
        fprintf(stderr, "FAIL: resource APK staged filename transition scope\n");
        return 1;
    }
    const char *rro_install[] = {"create","write","open","read","getattr","setattr","rename","unlink","relabelfrom","relabelto"};
    for (size_t i=0;i<sizeof(rro_install)/sizeof(rro_install[0]);i++) {
        if (!effective_allow_has(pdb,"voboost_install","voboost_resource_overlay_file","file",rro_install[i],NULL)) {
            fprintf(stderr,"FAIL: normal RRO installer bounds permission %s\n",rro_install[i]); return 1;
        }
    }
    const char *rro_remove[] = {"read","open","getattr","unlink"};
    for(size_t i=0;i<sizeof(rro_remove)/sizeof(rro_remove[0]);i++) {
        if(!effective_allow_has(pdb,"voboost_restore","voboost_resource_overlay_file","file",rro_remove[i],NULL) ||
           !effective_allow_has(pdb,"voboost_uninstall","voboost_resource_overlay_file","file",rro_remove[i],NULL)) return 1;
    }
    if(!effective_allow_has(pdb,"voboost","voboost_resource_overlay_file","file","read","open") ||
       effective_allow_has(pdb,"voboost","voboost_resource_overlay_file","file","write",NULL) ||
       effective_allow_has(pdb,"voboost_restore","voboost_resource_overlay_file","file","create",NULL) ||
       effective_allow_has(pdb,"voboost_uninstall","voboost_resource_overlay_file","file","write",NULL) ||
       !effective_allow_has(pdb,"voboost","overlay_service","service_manager","find",NULL) ||
       !effective_allow_has(pdb,"voboost_restore","overlay_service","service_manager","find",NULL) ||
       !effective_allow_has(pdb,"voboost_uninstall","overlay_service","service_manager","find",NULL)) {
       fprintf(stderr,"FAIL: RRO reader/remove/service bounded contract\n"); return 1;
    }
    if (!effective_allow_has(pdb, "idmap", "voboost_resource_overlay_file", "file", "read", "open") ||
        !effective_allow_has(pdb, "idmap", "voboost_resource_overlay_file", "file", "getattr", "map") ||
        effective_allow_has(pdb, "idmap", "voboost_resource_overlay_file", "file", "write", NULL) ||
        domain_is_permissive(pdb, "idmap")) {
        fprintf(stderr, "FAIL: idmap overlay read or confinement\n");
        return 1;
    }
    for (size_t i = 0; i < 5; ++i) {
        if (effective_allow_has(pdb, "idmap", "vendor_overlay_file", "file",
                                idmap_stock_permissions[i], NULL) != idmap_stock_overlay[i]) {
            fprintf(stderr, "FAIL: idmap stock overlay permission changed: %s\n",
                    idmap_stock_permissions[i]);
            return 1;
        }
    }
    const char *readers[] = {"system_server", "platform_app", "system_app"};
    for(size_t i=0;i<3;i++) {
        if(!effective_allow_has(pdb,readers[i],"voboost_resource_overlay_file","file","read","open") ||
           !effective_allow_has(pdb,readers[i],"voboost_resource_overlay_file","file","getattr","map")) {
            fprintf(stderr,"FAIL: normal RRO read access %s\n",readers[i]); return 1;
        }
    }
    if(effective_allow_has(pdb,"voboost_install","vendor_overlay_file","file","write",NULL) ||
       effective_allow_has(pdb,"voboost_install","vendor_overlay_file","file","relabelfrom",NULL)) {
        fprintf(stderr,"FAIL: normal RRO installer may mutate OEM overlay file label\n"); return 1;
    }
    printf("normal RRO proposed bounds: install/remove/read/service assertions passed\n");
    const char *helper_domains[] = {"init", "voboost", "voboost_restore", "voboost_uninstall"};
    for (size_t i = 0; i < sizeof(helper_domains) / sizeof(helper_domains[0]); ++i) {
        if (!effective_allow_has(pdb, helper_domains[i], "voboost_resource_journal_file",
                                 "file", "read", "map")) {
            fprintf(stderr, "FAIL: retained Java helper cannot be mapped by %s\n", helper_domains[i]);
            return 1;
        }
    }
    /* Regression: actual317 retained-authority create must survive init bounds. */
    const char *journal_ops[] = {"create", "write", "open", "read", "getattr", "setattr", "rename", "unlink"};
    for (size_t i=0;i<sizeof(journal_ops)/sizeof(journal_ops[0]);i++) {
        if (!effective_allow_has(pdb,"voboost_install","voboost_resource_journal_file","file",journal_ops[i],NULL)) { fprintf(stderr,"FAIL journal install %s\n",journal_ops[i]); return 1; }
    }
    if (!filename_transition_has(pdb,"voboost_install","voboost_data_file","dir","i18n-resource-transaction","voboost_resource_journal_file") || effective_allow_has(pdb,"voboost_install","voboost_data_file","file","create",NULL) || effective_allow_has(pdb,"appdomain","voboost_resource_journal_file","file","read",NULL)) { fprintf(stderr,"FAIL journal confinement\n"); return 1; }
    const char *walk_classes[]={"dir","file"};
    for(size_t i=0;i<2;i++) {
        if(!effective_allow_has(pdb,"voboost_relabel","voboost_resource_journal_file",walk_classes[i],"relabelfrom","relabelto") || !effective_allow_has(pdb,"init","voboost_resource_journal_file",walk_classes[i],"relabelfrom","relabelto")) { fprintf(stderr,"FAIL journal repeated relabel bounds\n"); return 1; }
    }
    for (size_t i = 0; i < 6; ++i) {
        if (effective_allow_has(pdb, "voboost_restore", "sepolicy_file", "file", cil_permissions[i], NULL) != (i < 3) ||
            effective_allow_has(pdb, "su", "sepolicy_file", "file", cil_permissions[i], NULL) != stock_su_cil[i]) {
            fprintf(stderr, "FAIL: Restore CIL digest must be read-only without changing stock su: %s\n", cil_permissions[i]);
            return 1;
        }
    }
    for (size_t i = 0; i < 3; ++i) {
        if (!allow_has(pdb, "voboost", execution_services[i], "service_manager", "find", NULL) ||
            !allow_has(pdb, "init", execution_services[i], "service_manager", "find", NULL) ||
            allow_has(pdb, "su", execution_services[i], "service_manager", "find", NULL) != stock_su_execution_finds[i]) {
            fprintf(stderr, "FAIL: APK execution service grant/bounds or stock su changed: %s\n", execution_services[i]);
            return 1;
        }
    }
    if (allow_has(pdb, "voboost", "system_file", "file", "write", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "file",
                  "write", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "file",
                  "append", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "file",
                  "setattr", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "file",
                  "unlink", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "file",
                  "rename", NULL) ||
        allow_has(pdb, "voboost", "voboost_uninstall_data_file", "dir",
                  "rename", NULL)) {
        fprintf(stderr, "FAIL: resident daemon can rewrite uninstall recovery authority\n");
        return 1;
    }
    if (!allow_has(pdb, "su", "voboost_uninstall_exec", "file", "execute",
                   NULL) ||
        allow_has(pdb, "su", "voboost_uninstall_exec", "file",
                  "execute_no_trans", NULL) ||
        !allow_has(pdb, "su", "voboost_uninstall_exec", "file", "open",
                   "read") ||
        allow_has(pdb, "su", "voboost_uninstall_data_file", "dir", "write",
                  NULL) ||
        allow_has(pdb, "su", "voboost_uninstall_data_file", "file", "write",
                  NULL) ||
        allow_has(pdb, "su", "voboost_selinux_exec", "file", "execute",
                  NULL)) {
        fprintf(stderr, "FAIL: injected policy does not isolate signed uninstall transition\n");
        return 1;
    }
    if (!allow_has(pdb, "voboost", "zygote_exec", "file", "execute",
                   "execute_no_trans") ||
        !allow_has(pdb, "voboost", "zygote_exec", "file", "read", "map")) {
        fprintf(stderr, "FAIL: daemon cannot execute its fixed signed QNX courier\n");
        return 1;
    }
    if (!allow_has(pdb, "voboost_uninstall", "shell_exec", "file", "execute",
                   "execute_no_trans") ||
        allow_has(pdb, "voboost_uninstall", "shell_exec", "file", "entrypoint",
                  NULL) ||
        !allow_has(pdb, "init", "init", "process", "setexec", NULL) ||
        !allow_has(pdb, "voboost_uninstall", "system_file", "file", "execute",
                   "execute_no_trans") ||
        !allow_has(pdb, "voboost_uninstall", "zygote_exec", "file", "execute",
                   "execute_no_trans")) {
        fprintf(stderr, "FAIL: injected policy cannot execute the fixed pm teardown chain\n");
        return 1;
    }
    if (!allow_has(pdb, "voboost_uninstall", "voboost", "process", "signal",
                   NULL) ||
        allow_has(pdb, "voboost_uninstall", "kernel", "security", "setenforce",
                  NULL) ||
        !allow_has(pdb, "voboost_uninstall", "ctl_start_prop", "property_service", "set",
                   NULL) ||
        !allow_has(pdb, "voboost_uninstall", "powerctl_prop", "property_service", "set",
                   NULL) ||
        !allow_has(pdb, "voboost_uninstall", "system_file", "dir", "open",
                   "read") ||
        !allow_has(pdb, "voboost_uninstall", "vendor_file", "dir", "open",
                   "read")) {
        fprintf(stderr, "FAIL: injected policy cannot stop daemon or fsync teardown parents\n");
        return 1;
    }
    if (allow_has(pdb, "voboost_uninstall", "voboost_selinux_exec", "file",
                  "execute", NULL) ||
        allow_has(pdb, "voboost_uninstall", "voboost_selinux_exec", "file",
                  "execute_no_trans", NULL)) {
        fprintf(stderr, "FAIL: uninstaller can execute the install-only SELinux program\n");
        return 1;
    }
    if (hashtab_search(pdb->p_types.table, "voboost_runtime") ||
        hashtab_search(pdb->p_types.table, "voboost_runtime_exec")) {
        fprintf(stderr, "FAIL: obsolete runtime domain aliases remain after inject\n");
        return 1;
    }
    if (!hashtab_search(pdb->p_types.table, "voboost_exec")) {
        fprintf(stderr, "FAIL: voboost_exec type missing after inject\n");
        return 1;
    }
    if (!hashtab_search(pdb->p_types.table, "voboost")) {
        fprintf(stderr, "FAIL: voboost type missing after inject\n");
        return 1;
    }
    const char *property_domains[] = {
        "voboost_install", "voboost_install", "voboost", "voboost_uninstall"
    };
    const char *property_types[] = {
        "exported3_system_prop", "exported_default_prop", "exported_default_prop", "default_prop"
    };
    const char *property_reads[] = { "read", "open", "getattr", "map" };
    for (size_t i = 0; i < sizeof(property_domains) / sizeof(property_domains[0]); ++i) {
        for (size_t j = 0; j < 4; ++j) {
            if (!effective_allow_has(pdb, property_domains[i], property_types[i],
                                     "file", property_reads[j], NULL)) {
                fprintf(stderr, "FAIL: native property read %s %s:%s\n",
                        property_domains[i], property_types[i], property_reads[j]);
                return 1;
            }
        }
        if (effective_allow_has(pdb, property_domains[i], property_types[i],
                                "file", "write", NULL) ||
            effective_allow_has(pdb, property_domains[i], property_types[i],
                                "property_service", "set", NULL)) {
            fprintf(stderr, "FAIL: native property read grants mutation authority\n");
            return 1;
        }
    }
    /* Physical 358 AVCs: read-only native property areas and protocol-21 CAN RX. */
    const char *runtime_property_types[] = { "default_prop", "system_prop" };
    for (size_t i = 0; i < 2; ++i) {
        if (!effective_allow_has(pdb, "voboost", runtime_property_types[i],
                                 "file", "read", "map") ||
            effective_allow_has(pdb, "voboost", runtime_property_types[i],
                                "file", "write", NULL)) {
            fprintf(stderr, "FAIL: bounded native property read/map authority\n");
            return 1;
        }
    }
    const char *can_receive[] = { "create", "bind", "read" };
    for (size_t i = 0; i < 3; ++i) {
        if (!effective_allow_has(pdb, "voboost", "voboost",
                                 "netlink_crypto_socket", can_receive[i], NULL)) {
            fprintf(stderr, "FAIL: bounded native CAN receiver %s\n", can_receive[i]);
            return 1;
        }
    }
    if (effective_allow_has(pdb, "voboost", "voboost",
                            "netlink_crypto_socket", "write", NULL) ||
        !effective_allow_has(pdb, "voboost", "block_device", "dir", "search", NULL) ||
        effective_allow_has(pdb, "voboost", "block_device", "blk_file", "write", NULL) ||
        effective_allow_has(pdb, "voboost", "block_device", "blk_file", "ioctl", NULL)) {
        fprintf(stderr, "FAIL: bounded native CAN/NV read-only authority\n");
        return 1;
    }
    /* Retained f0506h vendor contexts bind exactly /dev/block/vdh to vdh_device. */
    const char *nv_read[] = { "open", "read", "getattr" };
    if (!type_value(pdb, "vdh_device")) {
        fprintf(stderr, "FAIL: expected OEM vdh_device fixture type is missing\n");
        return 1;
    }
    const char *nv_domains[] = { "voboost", "voboost_install" };
    if (!effective_allow_has(pdb, "voboost_install", "block_device", "dir", "search", NULL) ||
        effective_allow_has(pdb, "voboost_install", "block_device", "dir", "write", NULL)) {
        fprintf(stderr, "FAIL: install-time NV path requires search-only block directory access\n");
        return 1;
    }
    const char *nv_mutation[] = { "write", "ioctl", "map" };
    for (size_t domain = 0; domain < 2; ++domain) {
        for (size_t i = 0; i < 3; ++i) {
            if (!effective_allow_has(pdb, nv_domains[domain], "vdh_device",
                                     "blk_file", nv_read[i], NULL)) {
                fprintf(stderr, "FAIL: exact OEM NV %s read permission %s\n",
                        nv_domains[domain], nv_read[i]);
                return 1;
            }
            if (effective_allow_has(pdb, nv_domains[domain], "vdh_device",
                                    "blk_file", nv_mutation[i], NULL)) {
                fprintf(stderr, "FAIL: exact OEM NV %s grants %s\n",
                        nv_domains[domain], nv_mutation[i]);
                return 1;
            }
        }
    }
    const char *other_blocks[] = {
        "block_device", "system_block_device", "boot_block_device",
        "modem_block_device", "persist_block_device", "misc_block_device", "gpt_block_device"
    };
    const char *other_access[] = { "open", "read", "write", "ioctl" };
    for (size_t i = 0; i < sizeof(other_blocks) / sizeof(other_blocks[0]); ++i) {
        if (!type_value(pdb, other_blocks[i])) {
            continue;
        }
        for (size_t j = 0; j < 4; ++j) {
            if (effective_allow_has(pdb, "voboost", other_blocks[i],
                                    "blk_file", other_access[j], NULL)) {
                fprintf(stderr, "FAIL: NV probe grants other block %s:%s\n",
                        other_blocks[i], other_access[j]);
                return 1;
            }
        }
    }
    const char *publication_domains[] = { "voboost_install", "voboost_restore" };
    printf("root-parent AV uninstall-data=%d init-data=%d root-type=%u uninstall-root=%d app-delete=%d\n",
           effective_allow_has(pdb, "voboost_uninstall", "system_data_file", "dir", "write", "remove_name"),
           effective_allow_has(pdb, "init", "system_data_file", "dir", "write", "remove_name"),
           type_value(pdb, "system_data_root_file"),
           effective_allow_has(pdb, "voboost_uninstall", "system_data_root_file", "dir", "write", "remove_name"),
           effective_allow_has(pdb, "system_app", "voboost_data_file", "dir", "remove_name", NULL));
    if (!effective_allow_has(pdb, "voboost_uninstall", "system_data_file", "dir", "write", "remove_name") ||
        !effective_allow_has(pdb, "init", "system_data_file", "dir", "write", "remove_name") ||
        (type_value(pdb, "system_data_root_file") && !effective_allow_has(pdb, "voboost_uninstall", "system_data_root_file", "dir", "write", "remove_name")) ||
        effective_allow_has(pdb, "system_app", "voboost_data_file", "dir", "remove_name", NULL)) {
        fprintf(stderr, "FAIL: exact-zero root unlink needs both stock data-parent contexts\n");
        exit(1);
    }
    if (!effective_allow_has(pdb, "voboost_uninstall", "block_device", "blk_file", "open", "read") ||
        !effective_allow_has(pdb, "voboost_uninstall", "block_device", "blk_file", "getattr", "ioctl") ||
        !effective_allow_has(pdb, "init", "block_device", "blk_file", "open", "ioctl") ||
        effective_allow_has(pdb, "voboost", "block_device", "blk_file", "ioctl", NULL) ||
        effective_allow_has(pdb, "voboost_uninstall", "proc", "filesystem", "remount", NULL)) {
        fprintf(stderr, "FAIL: bounded uninstall block protection authority\n");
        exit(1);
    }
    for (size_t i = 0; i < sizeof(publication_domains) / sizeof(publication_domains[0]); ++i) {
        const char *domain = publication_domains[i];
        if (!effective_allow_has(pdb, domain, "vendor_configs_file", "file", "create", "write") ||
            !effective_allow_has(pdb, domain, "vendor_configs_file", "file", "rename", "unlink") ||
            !effective_allow_has(pdb, domain, "vendor_configs_file", "file", "relabelfrom", "relabelto") ||
            !effective_allow_has(pdb, domain, "vendor_configs_file", "dir", "add_name", "remove_name")) {
            fprintf(stderr, "FAIL: protected policy config publication for %s\n", domain);
            exit(1);
        }
    }
    if (!allow_has(pdb, "init", "voboost_restore", "process", "transition", NULL) ||
        !allow_has(pdb, "voboost_restore", "system_file", "file", "entrypoint", NULL) ||
        !effective_allow_has(pdb, "voboost_restore", "voboost_operation_file", "file",
                             "write", "rename") ||
        !effective_allow_has(pdb, "voboost_restore", "voboost_recovery_file", "file",
                             "write", "rename") ||
        domain_is_permissive(pdb, "voboost_restore")) {
        fprintf(stderr, "FAIL: init-owned restore effective rail is incomplete or permissive\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost_uninstall", "voboost_resource_journal_file",
                             "dir", "rmdir", NULL) ||
        effective_allow_has(pdb, "voboost_restore", "voboost_resource_journal_file",
                            "dir", "rmdir", NULL)) {
        fprintf(stderr, "FAIL: resource journal terminal removal must remain uninstall-owned\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost_restore", "kernel", "security",
                             "read_policy", NULL) ||
        effective_allow_has(pdb, "voboost_restore", "kernel", "security",
                            "load_policy", NULL) ||
        !filename_transition_has(pdb, "voboost_restore", "system_file", "file",
                                 ".voboost.rc.product-rollback.tmp", "voboost_init_rollback_file") ||
        !effective_allow_has(pdb, "voboost_restore", "voboost_init_rollback_file", "file",
                             "create", "relabelfrom") ||
        effective_allow_has(pdb, "voboost_restore", "system_file", "file",
                            "create", NULL)) {
        fprintf(stderr, "FAIL: product update must inspect policy and stage only the owned init rollback\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost_restore", "voboost_install_staging_file",
                             "dir", "open", "read") ||
        !effective_allow_has(pdb, "voboost_restore", "voboost_install_staging_file",
                             "dir", "search", "getattr") ||
        effective_allow_has(pdb, "voboost_restore", "voboost_install_staging_file",
                            "dir", "write", NULL) ||
        effective_allow_has(pdb, "voboost_restore", "voboost_install_staging_file",
                            "file", "write", NULL)) {
        fprintf(stderr, "FAIL: restore terminal install inspection must remain read-only\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost_restore", "voboost_install_root_dir",
                             "dir", "add_name", "remove_name") ||
        !effective_allow_has(pdb, "voboost_restore", "voboost_installed_state_file",
                             "file", "rename", "relabelto") ||
        effective_allow_has(pdb, "voboost_restore", "voboost_installed_state_file",
                            "file", "write", NULL)) {
        fprintf(stderr, "FAIL: restore must publish installed state without rewriting it\n");
        return 1;
    }
    /* Restore admission and first-phase closure: authority, inventory, WAL,
     * staged product inputs and pristine policy must be readable before any
     * firmware mutation. Check effective AV, including attributes/conditions. */
    const char *restore_read_dirs[] = {
        "voboost_data_file", "voboost_recovery_file",
        "voboost_uninstall_data_file", "voboost_generation_file", "apk_data_file"
    };
    const char *restore_read_files[] = {
        "voboost_data_file", "voboost_operation_file", "voboost_recovery_file",
        "voboost_uninstall_data_file", "voboost_generation_file", "apk_data_file",
        "voboost_install_staging_file",
        "voboost_exec", "voboost_install_exec", "voboost_uninstall_exec",
        "voboost_selinux_exec", "system_file", "vendor_file", "vendor_configs_file"
    };
    for (size_t i = 0; i < sizeof(restore_read_dirs) / sizeof(restore_read_dirs[0]); ++i) {
        if (!effective_allow_has(pdb, "voboost_restore", restore_read_dirs[i], "dir", "open", "read") ||
            !effective_allow_has(pdb, "voboost_restore", restore_read_dirs[i], "dir", "search", "getattr")) {
            fprintf(stderr, "FAIL: restore admission directory read %s\n", restore_read_dirs[i]);
            return 1;
        }
    }
    for (size_t i = 0; i < sizeof(restore_read_files) / sizeof(restore_read_files[0]); ++i) {
        if (!effective_allow_has(pdb, "voboost_restore", restore_read_files[i], "file", "open", "read") ||
            !effective_allow_has(pdb, "voboost_restore", restore_read_files[i], "file", "getattr", NULL)) {
            fprintf(stderr, "FAIL: restore admission file read %s\n", restore_read_files[i]);
            return 1;
        }
    }
    if (!allow_has(pdb, "init", "voboost_relabel", "process", "transition", NULL) ||
        !allow_has(pdb, "voboost_relabel", "voboost_selinux_exec", "file", "entrypoint", NULL) ||
        !effective_allow_has(pdb, "voboost_relabel", "voboost_exec", "file",
                             "relabelto", NULL) ||
        !effective_allow_has(pdb, "voboost_relabel", "default_prop", "property_service",
                             "set", NULL) ||
        domain_is_permissive(pdb, "voboost_relabel")) {
        fprintf(stderr, "FAIL: fixed init relabel effective rail is incomplete or permissive\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost_relabel", "voboost_install_root_dir", "file", "read", "open") ||
        !effective_allow_has(pdb, "voboost_relabel", "voboost_install_root_dir", "file", "getattr", "relabelfrom") ||
        effective_allow_has(pdb, "voboost_relabel", "voboost_install_root_dir", "file", "write", NULL) ||
        effective_allow_has(pdb, "voboost_relabel", "voboost_install_root_dir", "file", "relabelto", NULL)) {
        fprintf(stderr, "FAIL: inherited install-root file labels cannot be repaired within relabel bounds\n");
        return 1;
    }
    class_datum_t *directory_class = hashtab_search(pdb->p_classes.table, "dir");
    if (!directory_class) return 1;
    const char *staging_creators[] = {"su"};
    for (size_t i = 0; i < sizeof(staging_creators) / sizeof(staging_creators[0]); ++i) {
        avtab_key_t key = {0};
        key.source_type = type_value(pdb, staging_creators[i]);
        key.target_type = type_value(pdb, "voboost_install_root_dir");
        key.target_class = directory_class->s.value;
        key.specified = AVTAB_TRANSITION;
        avtab_datum_t *transition = avtab_search(&pdb->te_avtab, &key);
        if (!transition || transition->data != type_value(pdb, "voboost_install_staging_file")) {
            fprintf(stderr, "FAIL: private transaction directories inherit the install-root type\n");
            return 1;
        }
    }
    if (!effective_allow_has(pdb, "voboost_restore", "voboost_data_file", "dir", "lock", NULL)) {
        fprintf(stderr, "FAIL: signed system update cannot lock its owned Cluster directory\n");
        return 1;
    }
    printf("init lifecycle rails ok: dedicated enforcing restore and fixed relabel domains\n");
    if (!bounded_allow_has(pdb, type_value(pdb, "su"),
                           type_value(pdb, "voboost_data_file"), "sock_file", "write") ||
        !effective_allow_has(pdb, "su", "voboost", "unix_stream_socket", "connectto", NULL) ||
        !effective_allow_has(pdb, "su", "init", "unix_stream_socket", "connectto", NULL)) {
        fprintf(stderr, "FAIL: root management owner IPC is not admitted through target bounds\n");
        return 1;
    }
    /* Proc executable links carry the peer domain. Target bounds also
     * require the corresponding parent-domain readlink permission. */
    if (!effective_allow_has(pdb, "su", "voboost", "lnk_file", "read", NULL) ||
        !effective_allow_has(pdb, "su", "init", "lnk_file", "read", NULL) ||
        !effective_allow_has(pdb, "su", "init", "dir", "search", NULL) ||
        !effective_allow_has(pdb, "su", "init", "file", "read", NULL)) {
        fprintf(stderr, "FAIL: management peer readlink is denied by target bounds\n");
        return 1;
    }
    if (!bounded_allow_has(pdb, type_value(pdb, "voboost"),
                           type_value(pdb, "su"), "dir", "search") ||
        !bounded_allow_has(pdb, type_value(pdb, "voboost"),
                           type_value(pdb, "su"), "file", "read") ||
        !bounded_allow_has(pdb, type_value(pdb, "voboost"),
                           type_value(pdb, "su"), "lnk_file", "read") ||
        effective_allow_has(pdb, "voboost", "su", "file", "write", NULL) ||
        effective_allow_has(pdb, "voboost", "su", "process", "ptrace", NULL)) {
        fprintf(stderr, "FAIL: signed management peer inspection must be read-only\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "untrusted_app", "voboost", "fd", "use", NULL) ||
        !effective_allow_has(pdb, "untrusted_app", "voboost_cluster_lease_file", "file", "read", "getattr") ||
        effective_allow_has(pdb, "untrusted_app", "voboost_cluster_lease_file", "file", "open", NULL) ||
        effective_allow_has(pdb, "untrusted_app", "voboost_cluster_lease_file", "file", "write", NULL) ||
        effective_allow_has(pdb, "untrusted_app", "voboost_data_file", "file", "read", NULL) ||
        effective_allow_has(pdb, "untrusted_app", "voboost_generation_file", "file", "read", NULL)) {
        fprintf(stderr, "FAIL: courier descriptor access exceeds readonly lease copies\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost", "untrusted_app", "fd", "use", NULL)) {
        fprintf(stderr, "FAIL: authenticated courier receipt descriptor cannot be received\n");
        return 1;
    }
    if (!resident_target_domain_is_exact(pdb)) {
        fprintf(stderr,
                "FAIL: resident target-process authority is not exact system_app plus system_server plus bluetooth\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "system_app", "voboost_data_file", "dir",
                             "search", "getattr") ||
        !effective_allow_has(pdb, "system_app", "voboost_data_file", "file",
                             "execute", "map") ||
        effective_allow_has(pdb, "untrusted_app", "voboost_data_file", "file",
                            "execute", NULL) ||
        effective_allow_has(pdb, "system", "voboost_data_file", "file",
                            "execute", NULL)) {
        fprintf(stderr,
                "FAIL: target payload access is not exact system_app\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "system_server", "system_server", "process", "execmem", NULL) ||
        !effective_allow_has(pdb, "system_server", "voboost_data_file", "dir", "search", "getattr") ||
        !effective_allow_has(pdb, "system_server", "voboost_data_file", "file", "execute", "map") ||
        !effective_allow_has(pdb, "system_server", "voboost", "unix_stream_socket", "connectto", NULL) ||
        !effective_allow_has(pdb, "voboost", "system_server", "fifo_file", "read", "write") ||
        !effective_allow_has(pdb, "system_server", "voboost", "process", "sigchld", NULL) ||
        effective_allow_has(pdb, "voboost", "system_server", "process", "sigkill", NULL) ||
        effective_allow_has(pdb, "voboost", "system_server", "process", "signal", NULL) ||
        effective_allow_has(pdb, "voboost", "system_server", "file", "write", NULL) ||
        effective_allow_has(pdb, "voboost", "system_server", "dir", "write", NULL) ||
        effective_allow_has(pdb, "system_server", "voboost_data_file", "file", "write", NULL) ||
        domain_is_permissive(pdb, "system_server")) {
        fprintf(stderr, "FAIL: launcher system_server transport or no-kill boundary differs\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "bluetooth", "voboost_data_file", "dir", "search", "getattr") ||
        !effective_allow_has(pdb, "bluetooth", "voboost_data_file", "file", "read", "open") ||
        !effective_allow_has(pdb, "bluetooth", "voboost_data_file", "file", "execute", "map") ||
        !effective_allow_has(pdb, "bluetooth", "voboost_data_file", "file", "getattr", NULL) ||
        !effective_allow_has(pdb, "bluetooth", "voboost_data_file", "sock_file", "write", "open") ||
        !effective_allow_has(pdb, "bluetooth", "voboost_data_file", "sock_file", "getattr", NULL) ||
        !effective_allow_has(pdb, "bluetooth", "voboost", "unix_stream_socket", "connectto", NULL) ||
        !effective_allow_has(pdb, "voboost", "bluetooth", "fifo_file", "read", "write") ||
        !effective_allow_has(pdb, "voboost", "bluetooth", "fifo_file", "open", "getattr") ||
        !effective_allow_has(pdb, "bluetooth", "voboost", "process", "sigchld", NULL) ||
        effective_allow_has(pdb, "voboost", "bluetooth", "process", "sigkill", NULL) ||
        effective_allow_has(pdb, "voboost", "bluetooth", "process", "signal", NULL) ||
        effective_allow_has(pdb, "voboost", "bluetooth", "file", "write", NULL) ||
        effective_allow_has(pdb, "voboost", "bluetooth", "dir", "write", NULL) ||
        effective_allow_has(pdb, "bluetooth", "voboost_data_file", "file", "write", NULL) ||
        domain_is_permissive(pdb, "bluetooth")) {
        fprintf(stderr, "FAIL: bluetooth transport or no-kill boundary differs\n");
        return 1;
    }
    printf("target-process authority ok: exact system_app plus system_server plus bluetooth; no runtime kill or proc write\n");
    if (!type_value(pdb, "system_app") || !type_value(pdb, "untrusted_app") ||
        domain_is_permissive(pdb, "system_app") ||
        domain_is_permissive(pdb, "untrusted_app") ||
        root_zone_rewrite_allowed(pdb, "system_app") ||
        root_zone_rewrite_allowed(pdb, "untrusted_app")) {
        fprintf(stderr,
                "FAIL: OEM/app domain can write the protected root-zone file type\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost", "voboost_data_file", "file",
                             "write", NULL) ||
        !effective_allow_has(pdb, "voboost", "voboost_data_file", "dir",
                             "add_name", NULL)) {
        fprintf(stderr, "FAIL: effective-AV negative control cannot see daemon root-zone grants\n");
        return 1;
    }
    printf("root-zone denial ok: effective conditional AV denies app/OEM rewrite closure and domains are enforcing\n");
    if (!filename_transition_has(pdb, "voboost", "voboost_data_file",
                                 "file", ".operation.json.tmp",
                                 "voboost_operation_file") ||
        !filename_transition_has(pdb, "voboost", "voboost_data_file",
                                 "dir", "install",
                                 "voboost_install_root_dir") ||
        !filename_transition_has(pdb, "voboost_install", "voboost_data_file",
                                 "dir", "install",
                                 "voboost_install_root_dir") ||
        !filename_transition_has(pdb, "voboost", "voboost_install_root_dir",
                                 "file", ".state.json.tmp",
                                 "voboost_installed_state_file") ||
        !filename_transition_has(pdb, "voboost_install", "voboost_install_root_dir",
                                 "file", ".state.json.tmp",
                                 "voboost_installed_state_file") ||
        !filename_transition_has(pdb, "voboost", "voboost_data_file",
                                 "dir", "recovery",
                                 "voboost_recovery_file") ||
        !filename_transition_has(pdb, "voboost",
                                 "voboost_install_staging_file", "dir",
                                 "candidate", "voboost_update_staging_file") ||
        !filename_transition_has(pdb, "voboost",
                                 "voboost_install_staging_file", "file",
                                 ".update-journal.json.tmp",
                                 "voboost_update_staging_file")) {
        fprintf(stderr, "FAIL: runtime transaction filename labels are incomplete\n");
        return 1;
    }
    if (!effective_allow_has(pdb, "voboost",
                             "voboost_update_staging_file", "dir", "create",
                             "remove_name") ||
        !effective_allow_has(pdb, "voboost",
                             "voboost_update_staging_file", "file", "create",
                             "rename") ||
        effective_allow_has(pdb, "voboost_install",
                            "voboost_update_staging_file", "file", "write",
                            NULL) ||
        effective_allow_has(pdb, "voboost",
                            "voboost_uninstall_data_file", "file", "write",
                            NULL)) {
        fprintf(stderr, "FAIL: transaction purpose access is missing or crosses domains\n");
        return 1;
    }
    if (!filename_transition_has(pdb, "voboost_install", "voboost_data_file",
                                 "file", "install-progress.jsonl",
                                 "voboost_operation_file") ||
        !filename_transition_has(pdb, "voboost", "voboost_data_file",
                                 "file", "install-progress.jsonl",
                                 "voboost_operation_file") ||
        !effective_allow_has(pdb, "voboost_install", "voboost_operation_file",
                             "file", "write", "setattr") ||
        !effective_allow_has(pdb, "su", "voboost_operation_file", "file",
                             "open", "read")) {
        fprintf(stderr, "FAIL: install history label/write/read rights are incomplete\n");
        return 1;
    }
    if (created_directory_type(pdb, "voboost_restore", "voboost_data_file",
                               "restore-prepare") !=
            type_value(pdb, "voboost_recovery_file") ||
        created_directory_type(pdb, "voboost_restore", "voboost_data_file",
                               "restore-prepare-other") !=
            type_value(pdb, "voboost_data_file") ||
        created_directory_type(pdb, "voboost", "voboost_data_file",
                               "restore-prepare") !=
            type_value(pdb, "voboost_data_file") ||
        created_directory_type(pdb, "voboost_restore", "system_data_file",
                               "restore-prepare") !=
            type_value(pdb, "system_data_file")) {
        fprintf(stderr, "FAIL: restore preparation label must match exact source/parent/name\n");
        return 1;
    }
    /* Atomic admission moves a protected directory between DATA run/ and
     * RECOVERY recovery/: SELinux checks both parents and the moved inode. */
    const char *restore_rename_matrix[][2] = {
        { "voboost_data_file", "search" },
        { "voboost_data_file", "remove_name" },
        { "voboost_recovery_file", "search" },
        { "voboost_recovery_file", "add_name" },
        { "voboost_recovery_file", "create" },
        { "voboost_recovery_file", "rename" },
        { "voboost_recovery_file", "reparent" },
    };
    for (size_t i = 0; i < sizeof(restore_rename_matrix) /
                            sizeof(restore_rename_matrix[0]); ++i) {
        if (!effective_allow_has(pdb, "voboost_restore",
                                 restore_rename_matrix[i][0], "dir",
                                 restore_rename_matrix[i][1], NULL)) {
            fprintf(stderr, "FAIL: restore atomic admission missing %s:dir %s\n",
                    restore_rename_matrix[i][0], restore_rename_matrix[i][1]);
            return 1;
        }
    }
    if (!effective_allow_has(pdb, "su", "voboost_installed_state_file", "file", "getattr", NULL) ||
        !effective_allow_has(pdb, "su", "voboost_installed_state_file", "file", "open", NULL) ||
        !effective_allow_has(pdb, "su", "voboost_installed_state_file", "file", "read", NULL) ||
        effective_allow_has(pdb, "su", "voboost_installed_state_file", "file", "write", NULL) ||
        effective_allow_has(pdb, "su", "voboost_installed_state_file", "file", "unlink", NULL)) {
        fprintf(stderr, "FAIL: desktop installed-state inspection must be read-only\n");
        return 1;
    }
    printf("transaction labels ok: operation/install/update/recovery transitions and cross-purpose denials hold\n");
    /* filename_trans fields must be 1-based type/class values (kernel
     * convention); a 0-based entry silently never matches. */
    {
        type_datum_t *vd = hashtab_search(pdb->p_types.table, "voboost");
        filename_trans_t *found = NULL;
        for (filename_trans_t *ft = pdb->filename_trans; ft; ft = ft->next) {
            if (ft->stype == vd->s.value || ft->stype == vd->s.value - 1) {
                found = ft; /* ours, whether stored 1- or 0-based */
            }
        }
        if (!found || found->stype != vd->s.value ||
            found->ttype == 0 || found->tclass == 0 || found->otype == 0) {
            fprintf(stderr, "FAIL: injected filename_trans not 1-based "
                    "(stype=%u, voboost=%u, ttype=%u tclass=%u otype=%u)\n",
                    found ? found->stype : 0, vd->s.value,
                    found ? found->ttype : 0, found ? found->tclass : 0,
                    found ? found->otype : 0);
            return 1;
        }
        printf("filename_trans ok: %s stype=%u matches 1-based voboost value\n",
               found->name, found->stype);
    }

    require_cache_directory_permissions(pdb);
    require_uninstall_result_access(pdb);
    require_qnx_tcp_client(pdb);
    require_lifecycle_block_ioctls(pdb);
    require_native_can_and_pid_metadata(pdb);
#ifdef VOBOOST_METADATA_BASELINE
    require_metadata_baseline(pdb, buf, len);
#endif
    require_bounded_target_controls(pdb);
    require_block_ioctl_decision_controls(pdb);
    /* Injected policy must survive write + re-read and report applied. */
    size_t inj_len;
    unsigned char *inj = write_mem(pdb, &inj_len);
    policydb_t *pdb3 = read_mem(inj, inj_len);
    require_cache_directory_permissions(pdb3);
    require_uninstall_result_access(pdb3);
    require_qnx_tcp_client(pdb3);
    require_ota_socket_isolation(pdb3);
    require_lifecycle_block_ioctls(pdb3);
    require_native_can_and_pid_metadata(pdb3);
    if (voboost_policy_applied(pdb3) == 0) {
        fprintf(stderr, "FAIL: injected policy not detected after write+re-read\n");
        return 1;
    }
    printf("inject ok: voboost type present, policy writes (%zu bytes) and re-reads applied\n",
           inj_len);
    policydb_destroy(pdb3);
    policydb_destroy(pdb);
    free(inj);
    free(buf);
    printf("test_real_policy: OK\n");
    return 0;
}
