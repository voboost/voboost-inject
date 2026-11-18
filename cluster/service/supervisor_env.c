#include "supervisor_env.h"

static const char preload_key[] = "LD_PRELOAD=";
static const char boot_key[] = "VOBOOST_CLUSTER_BOOTFILE=";
static const char stamp_key[] = "VOBOOST_CLUSTER_SUPERVISOR=";
static int length(const char *s, size_t bound, size_t *out) {
    size_t n;
    if (!s) return 0;
    for (n = 0; n <= bound; ++n) if (!s[n]) { *out = n; return 1; }
    return 0;
}
static int equal(const char *a, const char *b) {
    size_t n = 0;
    while (a[n] && b[n] && a[n] == b[n]) ++n;
    return a[n] == b[n];
}
static int prefix(const char *value, size_t size, const char *key, size_t key_size) {
    size_t n;
    if (size < key_size) return 0;
    for (n = 0; n < key_size; ++n) if (value[n] != key[n]) return 0;
    return 1;
}
static int target(const char *path) {
    size_t n;
    if (!length(path, 32, &n)) return 0;
    return equal(path, "/usr/bin/sysmgr") || equal(path, "/usr/bin/gauge") ||
        equal(path, "/usr/bin/point") || equal(path, "/usr/bin/light");
}
static int prepared_path(const char *s, size_t *size) {
    size_t n;
    if (!length(s, VBC_SUPERVISOR_ENV_MAX_STRING, size) || !*size || s[0] != '/') return 0;
    for (n = 0; n < *size; ++n)
        if ((unsigned char)s[n] <= 32 || (unsigned char)s[n] > 126 || s[n] == ':') return 0;
    return 1;
}
static int prepared_stamp(const char *s, size_t *size) {
    size_t n;
    if (!length(s, VBC_SUPERVISOR_ENV_MAX_STAMP, size) || !*size) return 0;
    for (n = 0; n < *size; ++n) {
        unsigned char c = (unsigned char)s[n];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}
/* Validate colon tokens and locate an exact existing implant token. */
static int preload_tokens(const char *value, size_t size, const char *implant,
    size_t implant_size, int *present) {
    size_t start = 0, n, matches = 0;
    if (!size) return 0;
    for (n = 0; n <= size; ++n) {
        if (n == size || value[n] == ':') {
            size_t i;
            int same = n - start == implant_size;
            if (n == start) return 0;
            for (i = start; same && i < n; ++i)
                if (value[i] != implant[i - start]) same = 0;
            if (same) ++matches;
            start = n + 1;
        } else if ((unsigned char)value[n] <= 32 || (unsigned char)value[n] > 126) return 0;
    }
    if (matches > 1) return 0;
    *present = matches == 1;
    return 1;
}
static char *entry(VbcSupervisorEnvStorage *s, size_t *used, const char *key,
    size_t key_size, const char *first, size_t first_size,
    const char *second, size_t second_size) {
    size_t n, total = key_size + first_size + second_size + (second ? 1u : 0u);
    char *out;
    if (total > VBC_SUPERVISOR_ENV_MAX_STRING || total + 1 > sizeof(s->bytes) - *used) return NULL;
    out = &s->bytes[*used];
    for (n = 0; n < key_size; ++n) out[n] = key[n];
    for (n = 0; n < first_size; ++n) out[key_size + n] = first[n];
    n = key_size + first_size;
    if (second) {
        size_t i;
        out[n++] = ':';
        for (i = 0; i < second_size; ++i) out[n++] = second[i];
    }
    out[n] = 0;
    *used += total + 1;
    return out;
}
char *const *vbc_supervisor_env_prepare(const char *path, char *const envp[],
    const char *implant, const char *bootfile, const char *stamp,
    VbcSupervisorEnvStorage *storage) {
    size_t count = 0, input_bytes = 0, implant_size, boot_size, stamp_size;
    size_t ld = VBC_SUPERVISOR_ENV_MAX_ENTRIES, boot = ld, supervisor = ld;
    size_t ld_size = 0, used = 0, n;
    int existing_implant = 0;
    char *new_ld = NULL, *new_boot = NULL, *new_stamp = NULL;
    if (!target(path) || !storage || (envp && envp == storage->entries) ||
        !prepared_path(implant, &implant_size) || !prepared_path(bootfile, &boot_size) ||
        !prepared_stamp(stamp, &stamp_size)) return envp;
    if (envp) {
        for (;;) {
            size_t size;
            if (!envp[count]) break;
            if (count == VBC_SUPERVISOR_ENV_MAX_ENTRIES ||
                !length(envp[count], VBC_SUPERVISOR_ENV_MAX_STRING, &size) ||
                size + 1 > VBC_SUPERVISOR_ENV_MAX_BYTES - input_bytes) return envp;
            input_bytes += size + 1;
            if (prefix(envp[count], size, preload_key, sizeof(preload_key)-1)) {
                if (ld != VBC_SUPERVISOR_ENV_MAX_ENTRIES) return envp;
                ld = count;
                ld_size = size - (sizeof(preload_key)-1);
                if (!preload_tokens(envp[count] + sizeof(preload_key)-1, ld_size,
                    implant, implant_size, &existing_implant)) return envp;
            } else if (prefix(envp[count], size, boot_key, sizeof(boot_key)-1)) {
                if (boot != VBC_SUPERVISOR_ENV_MAX_ENTRIES ||
                    !equal(envp[count] + sizeof(boot_key)-1, bootfile)) return envp;
                boot = count;
            } else if (prefix(envp[count], size, stamp_key, sizeof(stamp_key)-1)) {
                if (supervisor != VBC_SUPERVISOR_ENV_MAX_ENTRIES ||
                    !equal(envp[count] + sizeof(stamp_key)-1, stamp)) return envp;
                supervisor = count;
            }
            ++count;
        }
    }
    if (!existing_implant) {
        new_ld = entry(storage, &used, preload_key, sizeof(preload_key)-1,
            ld == VBC_SUPERVISOR_ENV_MAX_ENTRIES ? implant : envp[ld] + sizeof(preload_key)-1,
            ld == VBC_SUPERVISOR_ENV_MAX_ENTRIES ? implant_size : ld_size,
            ld == VBC_SUPERVISOR_ENV_MAX_ENTRIES ? NULL : implant,
            ld == VBC_SUPERVISOR_ENV_MAX_ENTRIES ? 0 : implant_size);
        if (!new_ld) return envp;
    }
    if (boot == VBC_SUPERVISOR_ENV_MAX_ENTRIES &&
        !(new_boot = entry(storage, &used, boot_key, sizeof(boot_key)-1, bootfile, boot_size, NULL, 0))) return envp;
    if (supervisor == VBC_SUPERVISOR_ENV_MAX_ENTRIES &&
        !(new_stamp = entry(storage, &used, stamp_key, sizeof(stamp_key)-1, stamp, stamp_size, NULL, 0))) return envp;
    if (new_ld && ld != VBC_SUPERVISOR_ENV_MAX_ENTRIES)
        input_bytes -= sizeof(preload_key) + ld_size;
    if (used > VBC_SUPERVISOR_ENV_MAX_BYTES - input_bytes) return envp;
    for (n = 0; n < count; ++n) storage->entries[n] = n == ld && new_ld ? new_ld : envp[n];
    if (ld == VBC_SUPERVISOR_ENV_MAX_ENTRIES) storage->entries[n++] = new_ld;
    if (new_boot) storage->entries[n++] = new_boot;
    if (new_stamp) storage->entries[n++] = new_stamp;
    storage->entries[n] = NULL;
    return storage->entries;
}
