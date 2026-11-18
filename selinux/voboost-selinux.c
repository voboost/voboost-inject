/* voboost-selinux — signed SELinux policy transformer.
 *
 * Every operation reads the current root-owned operation document, verifies
 * its correlated WAL and derives only fixed paths. The no-argument legacy
 * mode handles install/restore; fixed product modes install the signed
 * candidate transformer, prepare a policy from the OEM pristine baseline, or
 * check the exact loaded post-reboot policy. No caller-controlled file path,
 * transaction or digest is accepted.
 *
 * Exit codes (contract for init and tests):
 *   0 ok / already applied / disabled
 *   1 signature verification failed
 *   2 usage
 *   3 policydb read error
 *   4 context check failed
 *   5 policy load failed
 *   6 read-back verification failed
 *   7 alarm (stuck)
 *   8 state authority is unsafe or says disabled
 *   9 expected Voboost policy semantics are absent
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include "label_contract.h"
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

#include <sepol/policydb/policydb.h>
#include <yyjson.h>

#include "policy_inject.h"
#include "tweetnacl.h"

#ifndef EMBEDDED_PUBKEY_HEX
#error "build with the 32-byte native-executable public role"
#endif

/* --- constants --------------------------------------------------------- */

static const char POLICY_FILE[] = "/sys/fs/selinux/policy";
static const char LOAD_FILE[] = "/sys/fs/selinux/load";
static const char OPERATION_FILE[] = "/data/voboost/operation.json";
static const char ROOT_DIRECTORY[] = "/data/voboost";
static const char STOCK_POLICY_FILE[] = "/vendor/etc/selinux/precompiled_sepolicy";
static const char SELINUX_EXECUTABLE[] = "/data/voboost/voboost-selinux";
static const char SELINUX_EXECUTABLE_CONTEXT[] =
    "u:object_r:voboost_selinux_exec:s0";
static const char ROOT_ZONE_DIRECTORY[] = "/data/voboost";
static const char ROOT_MARKER_NAME[] = "root.json";
static const char ROOT_MARKER_BYTES[] =
    "{\"schemaVersion\":1,\"owner\":\"voboost\","
    "\"root\":\"/data/voboost\"}\n";
static const char VENDOR_POLICY_FILE[] =
    "/vendor/etc/selinux/precompiled_sepolicy";
static const char POLICY_META_FILE[] =
    "/data/voboost/uninstall/policy.meta.json";
static const char POLICY_BASELINES_DIRECTORY[] =
    "/data/voboost/uninstall/baselines";
static const char SELF_EXE[] = "/proc/self/exe";
static const char SIG_MAGIC[8] = {'V', 'O', 'B', 'O', 'O', 'S', 'T', '\0'};
#define SIG_TRAILER_BYTES 80
#define MAX_POLICY_BYTES ((size_t)64u * 1024u * 1024u)
#define MAX_EXECUTABLE_BYTES ((size_t)8u * 1024u * 1024u)
#define MAX_MANIFEST_BYTES ((size_t)4u * 1024u * 1024u)
#define MAX_META_BYTES (16u * 1024u)
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_len;
};

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

static void sha256_transform(struct sha256_ctx *ctx,
                             const unsigned char block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    uint32_t words[64];
    for (size_t i = 0; i < 16; i++) {
        words[i] = ((uint32_t)block[i * 4] << 24) |
                   ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) |
                   block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = rotate_right(words[i - 15], 7) ^
                      rotate_right(words[i - 15], 18) ^
                      (words[i - 15] >> 3);
        uint32_t s1 = rotate_right(words[i - 2], 17) ^
                      rotate_right(words[i - 2], 19) ^
                      (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                        rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choose + constants[i] + words[i];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                        rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(struct sha256_ctx *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_count = 0;
    ctx->block_len = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const unsigned char *data,
                          size_t length) {
    ctx->bit_count += (uint64_t)length * 8u;
    while (length > 0) {
        size_t room = sizeof(ctx->block) - ctx->block_len;
        size_t take = length < room ? length : room;
        memcpy(ctx->block + ctx->block_len, data, take);
        ctx->block_len += take;
        data += take;
        length -= take;
        if (ctx->block_len == sizeof(ctx->block)) {
            sha256_transform(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *ctx, unsigned char digest[32]) {
    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len > 56) {
        memset(ctx->block + ctx->block_len, 0,
               sizeof(ctx->block) - ctx->block_len);
        sha256_transform(ctx, ctx->block);
        ctx->block_len = 0;
    }
    memset(ctx->block + ctx->block_len, 0, 56 - ctx->block_len);
    for (size_t i = 0; i < 8; i++) {
        ctx->block[63 - i] = (unsigned char)(ctx->bit_count >> (i * 8));
    }
    sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
}

static void sha256_hex(const unsigned char *data, size_t length, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[32];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, length);
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[64] = '\0';
}

/* --- logging ----------------------------------------------------------- */

static void klog(const char *fmt, ...) {
    va_list arguments;
    va_start(arguments, fmt);
    fputs("voboost-selinux: ", stderr);
    vfprintf(stderr, fmt, arguments);
    fputc('\n', stderr);
    va_end(arguments);
}

static volatile sig_atomic_t boot_compiler_pid;

static void on_alarm(int sig) {
    (void)sig;
    if (boot_compiler_pid > 0) {
        kill((pid_t)boot_compiler_pid, SIGKILL);
    }
    _exit(7);
}

#ifndef VOBOOST_WATCHDOG_SECONDS
#define VOBOOST_WATCHDOG_SECONDS 30
#endif

static int install_alarm_watchdog(unsigned int seconds) {
    struct sigaction watchdog = {0};
    watchdog.sa_handler = on_alarm;
    sigemptyset(&watchdog.sa_mask);
    if (sigaction(SIGALRM, &watchdog, NULL) != 0) {
        return -1;
    }
    alarm(seconds);
    return 0;
}

/* --- self-signature verification ---------------------------------------- */

static const unsigned char PUBKEY[] = {EMBEDDED_PUBKEY_HEX};

static int verify_selinux_signature_bytes(const unsigned char *buf,
                                          size_t size) {
    if (!buf || size < SIG_TRAILER_BYTES || size > MAX_EXECUTABLE_BYTES) {
        return 0;
    }
    const unsigned char *trailer = buf + size - SIG_TRAILER_BYTES;
    uint64_t elf_len = 0;
    for (int i = 0; i < 8; i++) {
        elf_len |= (uint64_t)trailer[8 + i] << (8 * i);
    }
    if (memcmp(trailer, SIG_MAGIC, 8) != 0 ||
        elf_len != size - SIG_TRAILER_BYTES) {
        return 0;
    }

    static const unsigned char domain[] = "voboost-native-executable-v1";
    static const unsigned char role[] = "selinux";
    size_t transcript_len = sizeof(domain) + sizeof(role) + 8 + (size_t)elf_len;
    /* tweetnacl crypto_sign_open expects sm = sig(64) || message. */
    unsigned char *sm = malloc(transcript_len + 64);
    if (!sm) {
        return 0;
    }
    memcpy(sm, trailer + 16, 64);
    size_t cursor = 64;
    memcpy(sm + cursor, domain, sizeof(domain));
    cursor += sizeof(domain);
    memcpy(sm + cursor, role, sizeof(role));
    cursor += sizeof(role);
    for (int i = 0; i < 8; i++) {
        sm[cursor + i] = (unsigned char)(elf_len >> (8 * i));
    }
    cursor += 8;
    memcpy(sm + cursor, buf, elf_len);
    unsigned long long mlen = 0;
    unsigned char *m = malloc(transcript_len + 64);
    if (!m) {
        free(sm);
        return 0;
    }
    int ok = crypto_sign_open(m, &mlen, sm, (unsigned long long)transcript_len + 64,
                              PUBKEY) == 0;
    free(m);
    free(sm);
    return ok;
}

static int verify_own_signature(const char *argv0) {
    /* /proc/self/exe is the kernel-owned magic link for the already executing
     * image, so it must be followed. Caller-controlled fallback remains
     * no-follow and exists only for host tests. */
    int fd = open(SELF_EXE, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && argv0 && *argv0) {
        fd = open(argv0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        /* Host-test fallback; /proc/self/exe always resolves on device. */
    }
    if (fd < 0) {
        return 0;
    }
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || before.st_size < (off_t)SIG_TRAILER_BYTES ||
        before.st_size > (off_t)MAX_EXECUTABLE_BYTES) {
        close(fd);
        return 0;
    }
    size_t size = (size_t)before.st_size;
    unsigned char *buf = malloc(size);
    if (!buf) {
        close(fd);
        return 0;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t n = read(fd, buf + off, size - off);
        if (n <= 0) {
            free(buf);
            close(fd);
            return 0;
        }
        off += (size_t)n;
    }
    unsigned char extra;
    int exact = read(fd, &extra, 1) == 0 && fstat(fd, &after) == 0 &&
                before.st_dev == after.st_dev &&
                before.st_ino == after.st_ino &&
                before.st_size == after.st_size &&
                before.st_ctime == after.st_ctime;
    close(fd);
    int ok = exact && verify_selinux_signature_bytes(buf, size);
    free(buf);
    return ok;
}

/* --- post-load relabel ---------------------------------------------------
 * The firmware file_contexts has no entries for /data/voboost, so every
 * boot the SELinux program reapplies the intended labels itself (raw
 * security.selinux xattr; the init domain holds CAP_MAC_ADMIN).
 *   /data/voboost/voboost-daemon            -> voboost_exec
 *   /data/voboost/voboost-uninstall         -> voboost_uninstall_exec
 *   /data/voboost/uninstall                  -> voboost_uninstall_data_file
 *   descendants of /data/voboost/uninstall -> voboost_uninstall_data_file
 *   generations/next (app-owned OTA form)  -> voboost_incoming_file with the
 *                                            app data MLS range, no descent
 *   generations/next (daemon-owned install window)
 *                                          -> voboost_incoming_file, trusted
 *                                            installer content relabeled
 *                                            recursively
 *   descendants of generations             -> voboost_generation_file
 *   other descendants of /data/voboost      -> voboost_data_file
 */
/* Relabel only an already-open inode.  Paths below /data/voboost include an
 * app-writable staging subtree, so pathname xattrs and lstat-then-open walks
 * would permit symlink following or inode substitution. */
static int set_label_fd(int fd, const char *label) {
#ifdef VOBOOST_RELABEL_TEST
    extern int voboost_relabel_test_set_label(int, const char *);
    return voboost_relabel_test_set_label(fd, label);
#else
#ifdef __APPLE__
    return fsetxattr(fd, "security.selinux", label, strlen(label), 0, 0) == 0
#else
    return fsetxattr(fd, "security.selinux", label, strlen(label), 0) == 0
#endif
               ? 0
               : -1;
#endif
}

static int get_label_fd(int fd, char *label, size_t capacity) {
    if (!label || capacity < 2) {
        return -1;
    }
#ifdef VOBOOST_RELABEL_TEST
    extern int voboost_relabel_test_get_label(int, char *, size_t);
    return voboost_relabel_test_get_label(fd, label, capacity);
#else
#ifdef __APPLE__
    ssize_t length = fgetxattr(fd, "security.selinux", NULL, 0, 0, 0);
#else
    ssize_t length = fgetxattr(fd, "security.selinux", NULL, 0);
#endif
    if (length <= 0 || (size_t)length >= capacity) {
        return -1;
    }
#ifdef __APPLE__
    ssize_t read_length =
        fgetxattr(fd, "security.selinux", label, (size_t)length, 0, 0);
#else
    ssize_t read_length =
        fgetxattr(fd, "security.selinux", label, (size_t)length);
#endif
    if (read_length != length) {
        return -1;
    }
    while (length > 0 && label[length - 1] == '\0') {
        length--;
    }
    if (length == 0) {
        return -1;
    }
    label[length] = '\0';
    return 0;
#endif
}

static int context_identifier(const char *begin, const char *end) {
    if (begin == end) {
        return 0;
    }
    for (const char *cursor = begin; cursor < end; cursor++) {
        char ch = *cursor;
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
              || (ch >= '0' && ch <= '9') || ch == '_')) {
            return 0;
        }
    }
    return 1;
}

static int decimal_component(const char **cursor) {
    const char *start = *cursor;
    while (**cursor >= '0' && **cursor <= '9') {
        (*cursor)++;
    }
    return *cursor != start;
}

static int mls_level(const char **cursor) {
    if (**cursor != 's') {
        return 0;
    }
    (*cursor)++;
    if (!decimal_component(cursor)) {
        return 0;
    }
    if (**cursor != ':') {
        return 1;
    }
    (*cursor)++;
    for (;;) {
        if (**cursor != 'c') {
            return 0;
        }
        (*cursor)++;
        if (!decimal_component(cursor)) {
            return 0;
        }
        if (**cursor == '.') {
            (*cursor)++;
            if (**cursor != 'c') {
                return 0;
            }
            (*cursor)++;
            if (!decimal_component(cursor)) {
                return 0;
            }
        }
        if (**cursor != ',') {
            return 1;
        }
        (*cursor)++;
    }
}

static int valid_mls_range(const char *range) {
    const char *cursor = range;
    if (!mls_level(&cursor)) {
        return 0;
    }
    if (*cursor == '-') {
        cursor++;
        if (!mls_level(&cursor)) {
            return 0;
        }
    }
    return *cursor == '\0';
}

static int incoming_label_from_context(const char *current, char *out,
                                       size_t capacity) {
    const char *user_end = strchr(current, ':');
    const char *role_end = user_end ? strchr(user_end + 1, ':') : NULL;
    const char *type_end = role_end ? strchr(role_end + 1, ':') : NULL;
    if (!user_end || !role_end || !type_end
        || !context_identifier(current, user_end)
        || !context_identifier(user_end + 1, role_end)
        || !context_identifier(role_end + 1, type_end)
        || !valid_mls_range(type_end + 1)) {
        return -1;
    }
    int length = snprintf(out, capacity, "%.*s:%.*s:voboost_incoming_file:%s",
                          (int)(user_end - current), current,
                          (int)(role_end - user_end - 1), user_end + 1,
                          type_end + 1);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

#ifndef VOBOOST_APP_DATA_DIRECTORY
#define VOBOOST_APP_DATA_DIRECTORY "/data/user_de/0/ru.voboost"
#endif

static int exact_staging_directory(const struct stat *st);

static int incoming_label_fd(int staging_fd, char *out, size_t capacity) {
    char current[256];
#ifdef VOBOOST_RELABEL_TEST
    if (get_label_fd(staging_fd, current, sizeof(current)) != 0) {
        return -1;
    }
#else
    struct stat staging;
    if (fstat(staging_fd, &staging) != 0 || !exact_staging_directory(&staging)) {
        return -1;
    }
    int app_fd = open(VOBOOST_APP_DATA_DIRECTORY,
                      O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    struct stat app;
    if (app_fd < 0 || fstat(app_fd, &app) != 0 || !S_ISDIR(app.st_mode) ||
        app.st_nlink < 2 || app.st_uid != staging.st_uid ||
        app.st_gid != staging.st_gid || app.st_uid != app.st_gid ||
        app.st_uid < 10000 || app.st_uid > 19999 ||
        get_label_fd(app_fd, current, sizeof(current)) != 0) {
        if (app_fd >= 0) {
            close(app_fd);
        }
        return -1;
    }
    close(app_fd);
#endif
    return incoming_label_from_context(current, out, capacity);
}

static uid_t relabel_trusted_uid(void) {
#ifdef VOBOOST_RELABEL_TEST
    return geteuid();
#else
    return 0;
#endif
}

static gid_t relabel_trusted_gid(void) {
#ifdef VOBOOST_RELABEL_TEST
    return getegid();
#else
    return 0;
#endif
}

/* The installer resolves /data/data/ru.voboost after package installation and
 * commits generations/next as that user-0 Android application identity. */
static int exact_staging_directory(const struct stat *st) {
    return S_ISDIR(st->st_mode) && st->st_nlink >= 2
           && (st->st_mode & 07777) == 0700 && st->st_uid == st->st_gid
           && st->st_uid >= 10000 && st->st_uid <= 19999;
}

/* The initial-install window holds the staging directory daemon-owned: the
 * daemon stages the frozen product closure into generations/next before the
 * relabel gate of the second reboot, and after importing the activated
 * generation restores this exact owner (its recorded staging identity for the
 * install transaction). The terminal install cleanup then hands the consumed
 * empty directory to the installed application. Accept the relabel walking and
 * recursively labeling the trusted installer content in this window; the
 * installer-driven takeover (install/src/runtime.rs prepare_agent_incoming)
 * re-owns the empty directory once the install completes. */
static int install_window_staging_directory(const struct stat *st) {
    return S_ISDIR(st->st_mode) && st->st_nlink >= 2
           && (st->st_mode & 07777) == 0700
           && st->st_uid == 0 && st->st_gid == 0;
}

static int same_relabel_inode(const struct stat *expected,
                              const struct stat *actual) {
    return expected->st_dev == actual->st_dev
           && expected->st_ino == actual->st_ino
           && (expected->st_mode & S_IFMT) == (actual->st_mode & S_IFMT)
           && (expected->st_mode & 07777) == (actual->st_mode & 07777)
           && expected->st_uid == actual->st_uid
           && expected->st_gid == actual->st_gid
           && expected->st_nlink == actual->st_nlink;
}

static int named_inode_matches(int directory_fd, const char *name,
                               const struct stat *opened) {
    struct stat named;
    return fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0
           && same_relabel_inode(opened, &named);
}

static int relabel_tree_fd(int directory_fd, const char *logical_path,
                           const char *label) {
    int scan_fd = dup(directory_fd);
    if (scan_fd < 0) {
        return -1;
    }
    DIR *d = fdopendir(scan_fd);
    if (!d) {
        close(scan_fd);
        return -1;
    }
    int result = 0;
    struct dirent *e;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) {
            if (errno != 0) {
                result = -1;
            }
            break;
        }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) {
            continue;
        }
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", logical_path, e->d_name) >=
            (int)sizeof(child)) {
            result = -1;
            continue;
        }
        struct stat before;
        if (fstatat(directory_fd, e->d_name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
            result = -1;
            continue;
        }
        /* Never label through or recurse through a symlink. Its presence is an
         * unsafe root-zone shape, not an ignorable entry. */
        if (S_ISLNK(before.st_mode)) {
            result = -1;
            continue;
        }
        if (!S_ISREG(before.st_mode) && !S_ISDIR(before.st_mode)) {
            /* The runtime directory holds process-lifetime artifacts (pid
             * files, unix sockets). A dead socket surviving a reboot is
             * expected residue, not an unsafe root-zone shape: the daemon
             * unlinks and rebinds it on its own start, so skip it. */
            if (!strcmp(logical_path, "/data/voboost/run")) {
                continue;
            }
            result = -1;
            continue;
        }
        int prepare_directory = !strcmp(child, VOBOOST_PATH_RESTORE_PREPARE);
        int prepare_member = !strcmp(logical_path, VOBOOST_PATH_RESTORE_PREPARE);
        if (prepare_directory && (!S_ISDIR(before.st_mode) ||
                                  (before.st_mode & 07777) != 0700 ||
                                  before.st_gid != relabel_trusted_gid())) {
            result = -1;
            continue;
        }
        if (prepare_member && strcmp(child, VOBOOST_PATH_RESTORE_PREPARE_JOURNAL) &&
            strcmp(child, VOBOOST_PATH_RESTORE_PREPARE_TEMP)) {
            result = -1;
            continue;
        }
        int private_reply = prepare_member ||
                            !strcmp(child, VOBOOST_PATH_RESTORE_REPLY) ||
                            !strcmp(child, VOBOOST_PATH_UNINSTALL_REPLY);
        if (private_reply && (!S_ISREG(before.st_mode) ||
                              (before.st_mode & 07777) != 0600 ||
                              before.st_gid != relabel_trusted_gid())) {
            result = -1;
            continue;
        }
        int staging_root = !strcmp(child, "/data/voboost/generations/next");
        if (staging_root && !exact_staging_directory(&before)
            && !install_window_staging_directory(&before)) {
            result = -1;
            continue;
        }
        if (!staging_root
            && (before.st_uid != relabel_trusted_uid()
                || (before.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
            result = -1;
            continue;
        }
        /* A regular file with another name is not an exclusive member of the
         * committed Voboost authority.  Refuse it instead of relabeling an
         * inode reachable through a foreign hard link. */
        if (S_ISREG(before.st_mode) && before.st_nlink != 1) {
            result = -1;
            continue;
        }
#ifdef VOBOOST_RELABEL_TEST
        extern void voboost_relabel_test_before_open(int, const char *);
        voboost_relabel_test_before_open(directory_fd, e->d_name);
#endif
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        if (S_ISDIR(before.st_mode)) {
            flags |= O_DIRECTORY;
        }
        int child_fd = openat(directory_fd, e->d_name, flags);
        struct stat opened;
        if (child_fd < 0 || fstat(child_fd, &opened) != 0
            || !same_relabel_inode(&before, &opened)
            || (S_ISREG(opened.st_mode) && opened.st_nlink != 1)) {
            if (child_fd >= 0) {
                close(child_fd);
            }
            result = -1;
            continue;
        }
#ifdef VOBOOST_RELABEL_TEST
        extern void voboost_relabel_test_after_open(int, const char *);
        voboost_relabel_test_after_open(directory_fd, e->d_name);
#endif
        if (!named_inode_matches(directory_fd, e->d_name, &opened)) {
            close(child_fd);
            result = -1;
            continue;
        }
        char incoming_label[256];
        const char *child_label = label;
        if (!strcmp(child, VOBOOST_PATH_RUNTIME)) {
            child_label = VOBOOST_CONTEXT_RUNTIME;
        } else if (!strcmp(child, VOBOOST_PATH_INJECT)) {
            child_label = VOBOOST_CONTEXT_INJECT;
        } else if (!strcmp(child, VOBOOST_PATH_INSTALL)) {
            child_label = VOBOOST_CONTEXT_INSTALL;
        } else if (!strcmp(child, VOBOOST_PATH_RESTORE)) {
            child_label = VOBOOST_CONTEXT_RESTORE;
        } else if (!strcmp(child, VOBOOST_PATH_UNINSTALL)) {
            child_label = VOBOOST_CONTEXT_UNINSTALL;
        } else if (prepare_directory || prepare_member) {
            child_label = VOBOOST_CONTEXT_RESTORE_PREPARE;
        } else if (!strcmp(child, VOBOOST_PATH_RESTORE_REPLY)) {
            child_label = VOBOOST_CONTEXT_RESTORE_REPLY;
        } else if (!strcmp(child, VOBOOST_PATH_UNINSTALL_REPLY)) {
            child_label = VOBOOST_CONTEXT_UNINSTALL_REPLY;
        } else if (!strcmp(child, VOBOOST_PATH_SELINUX)) {
            child_label = VOBOOST_CONTEXT_SELINUX;
        } else if (!strcmp(child, "/data/voboost/operation.json") ||
                   !strcmp(child, "/data/voboost/operation.lock") ||
                   !strcmp(child, "/data/voboost/.operation.json.tmp") ||
                   !strcmp(child, VOBOOST_PATH_INSTALL_PROGRESS)) {
            child_label = VOBOOST_CONTEXT_OPERATION_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(e->d_name, "uninstall")) {
            child_label = VOBOOST_CONTEXT_UNINSTALL_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(child, VOBOOST_PATH_INSTALL_ROOT)) {
            child_label = VOBOOST_CONTEXT_INSTALL_ROOT;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_INSTALL_ROOT)) {
            child_label = VOBOOST_CONTEXT_INSTALL_TREE;
            if (!strcmp(child, VOBOOST_PATH_INSTALLED_STATE) ||
                !strcmp(e->d_name, ".state.json.tmp")) {
                child_label = VOBOOST_CONTEXT_INSTALLED_STATE;
            }
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(e->d_name, "recovery")) {
            child_label = VOBOOST_CONTEXT_RECOVERY_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(child, VOBOOST_PATH_RESOURCE_JOURNAL_TREE)) {
            child_label = VOBOOST_CONTEXT_RESOURCE_JOURNAL_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(e->d_name, "state")) {
            child_label = VOBOOST_CONTEXT_AGENT_STATE_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_ROOT) &&
            !strcmp(e->d_name, "generations")) {
            child_label = VOBOOST_CONTEXT_GENERATION_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_INSTALL_TREE) &&
            (!strcmp(e->d_name, "candidate") ||
             !strcmp(e->d_name, "update-journal.json") ||
             !strcmp(e->d_name, ".update-journal.json.tmp"))) {
            child_label = VOBOOST_CONTEXT_UPDATE_STAGING_TREE;
        }
        if (!strcmp(label, VOBOOST_CONTEXT_GENERATION_TREE) &&
            !strcmp(e->d_name, "next")) {
            if (exact_staging_directory(&opened)) {
                if (incoming_label_fd(child_fd, incoming_label,
                                      sizeof(incoming_label)) != 0) {
                    close(child_fd);
                    result = -1;
                    continue;
                }
                child_label = incoming_label;
            } else {
                /* install-window staging: the daemon-authored frozen product
                 * closure already carries the installer-incoming label; its
                 * content is root-owned and trusted, so relabel it through
                 * the ordinary recursive walk. */
                child_label = VOBOOST_CONTEXT_INCOMING_TREE;
            }
        }
        if (set_label_fd(child_fd, child_label) != 0) {
            close(child_fd);
            result = -1;
            continue;
        }
        if (!named_inode_matches(directory_fd, e->d_name, &opened)) {
            close(child_fd);
            result = -1;
            continue;
        }
        /* App-owned generations/next is the sole app-controlled root-zone
         * entry: label that fixed directory, but never inspect or relabel
         * its descendants. Install-window (daemon-owned) staging is instead
         * trusted installer content and takes the ordinary recursive walk. */
        if (S_ISDIR(opened.st_mode)
            && (!staging_root || install_window_staging_directory(&opened))) {
#ifdef VOBOOST_RELABEL_TEST
            extern void voboost_relabel_test_before_recurse(int, const char *);
            voboost_relabel_test_before_recurse(directory_fd, e->d_name);
#endif
            if (!named_inode_matches(directory_fd, e->d_name, &opened)) {
                close(child_fd);
                result = -1;
                continue;
            }
            if (relabel_tree_fd(child_fd, child, child_label) != 0
                || !named_inode_matches(directory_fd, e->d_name, &opened)) {
                result = -1;
            }
        }
        close(child_fd);
    }
    closedir(d);
    return result;
}

static int relabel_zone_fd(int root_fd, const char *root_path) {
    struct stat root;
    if (fstat(root_fd, &root) != 0 || !S_ISDIR(root.st_mode)
        || root.st_uid != relabel_trusted_uid()
        || (root.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return -1;
    }
    int result = set_label_fd(root_fd, VOBOOST_CONTEXT_ROOT);
    if (result != 0) {
        return -1;
    }
    if (relabel_tree_fd(root_fd, root_path, VOBOOST_CONTEXT_ROOT) != 0) {
        result = -1;
    }
    return result;
}

static int relabel_zone_at(const char *root_path) {
    int root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        return -1;
    }
    int result = relabel_zone_fd(root_fd, root_path);
    close(root_fd);
    return result;
}

static int publish_relabel_ready(void) {
#ifdef __ANDROID__
    return __system_property_set("voboost.relabel.ready", "1") == 0 ? 0 : -1;
#else
    return 0;
#endif
}

struct trusted_file {
    unsigned char *data;
    size_t length;
    struct stat st;
    char context[129];
};

struct backup_metadata {
    uint64_t size;
    char sha256[65];
    uid_t uid;
    gid_t gid;
    mode_t mode;
    char mode_text[5];
    char context[129];
};

static long stat_ctime_nsec(const struct stat *st) {
#if defined(__APPLE__)
    return st->st_ctimespec.tv_nsec;
#else
    return st->st_ctim.tv_nsec;
#endif
}

static int same_file_stamp(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_mode == b->st_mode &&
           a->st_nlink == b->st_nlink && a->st_ctime == b->st_ctime &&
           stat_ctime_nsec(a) == stat_ctime_nsec(b);
}

static int fd_context(int fd, char out[129]) {
#if defined(__APPLE__)
    ssize_t length = fgetxattr(fd, "security.selinux", NULL, 0, 0, 0);
#else
    ssize_t length = fgetxattr(fd, "security.selinux", NULL, 0);
#endif
    if (length <= 0 || length > 128) {
        return -1;
    }
#if defined(__APPLE__)
    ssize_t read_length =
        fgetxattr(fd, "security.selinux", out, (size_t)length, 0, 0);
#else
    ssize_t read_length =
        fgetxattr(fd, "security.selinux", out, (size_t)length);
#endif
    if (read_length != length) {
        return -1;
    }
    while (length > 0 && out[length - 1] == '\0') {
        length--;
    }
    out[length] = '\0';
    return length > 0 ? 0 : -1;
}

static int read_trusted_file(const char *path, size_t maximum,
                             int require_context, struct trusted_file *out) {
    memset(out, 0, sizeof(*out));
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat before;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || before.st_size <= 0 ||
        (uint64_t)before.st_size > maximum) {
        close(fd);
        return -1;
    }
    unsigned char *data = malloc((size_t)before.st_size);
    if (!data) {
        close(fd);
        return -1;
    }
    size_t offset = 0;
    while (offset < (size_t)before.st_size) {
        ssize_t count = read(fd, data + offset,
                             (size_t)before.st_size - offset);
        if (count <= 0) {
            free(data);
            close(fd);
            return -1;
        }
        offset += (size_t)count;
    }
    unsigned char extra;
    struct stat after, final;
    char before_context[129] = {0};
    char after_context[129] = {0};
    if ((require_context && fd_context(fd, before_context) != 0) ||
        read(fd, &extra, 1) != 0 || fstat(fd, &after) != 0 ||
        !same_file_stamp(&before, &after) ||
        (require_context && fd_context(fd, after_context) != 0) ||
        (require_context && strcmp(before_context, after_context) != 0) ||
        fstat(fd, &final) != 0 || !same_file_stamp(&before, &final)) {
        free(data);
        close(fd);
        return -1;
    }
    close(fd);
    out->data = data;
    out->length = offset;
    out->st = before;
    if (require_context) {
        memcpy(out->context, before_context, sizeof(out->context));
    }
    return 0;
}

static void free_trusted_file(struct trusted_file *file) {
    free(file->data);
    memset(file, 0, sizeof(*file));
}

static int inspect_trusted_target(const char *path, size_t maximum) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat before, after;
    char before_context[129] = {0};
    char after_context[129] = {0};
    int result = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
                 before.st_nlink == 1 && before.st_size > 0 &&
                 (uint64_t)before.st_size <= maximum &&
                 fd_context(fd, before_context) == 0 &&
                 fd_context(fd, after_context) == 0 &&
                 strcmp(before_context, after_context) == 0 &&
                 fstat(fd, &after) == 0 &&
                 same_file_stamp(&before, &after)
                     ? 0
                     : -1;
    close(fd);
    return result;
}

static int parse_decimal(const char *text, uint64_t maximum, uint64_t *out) {
    if (!text[0] || (text[0] == '0' && text[1])) {
        return -1;
    }
    for (const char *cursor = text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || value > maximum) {
        return -1;
    }
    char canonical[32];
    if (snprintf(canonical, sizeof(canonical), "%llu", value) <= 0 ||
        strcmp(canonical, text) != 0) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

static const char *metadata_string(yyjson_val *value) {
    const char *text = yyjson_get_str(value);
    return text && strlen(text) == yyjson_get_len(value) ? text : NULL;
}

/* Schema 2 is the committed installer metadata contract.  Validate the
 * complete document before using its pristine-policy identity. */
static int parse_backup_metadata_v2(const unsigned char *bytes, size_t length,
                                    struct backup_metadata *out) {
    yyjson_doc *doc = yyjson_read((const char *)bytes, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *schema = root ? yyjson_obj_get(root, "schemaVersion") : NULL;
    yyjson_val *size = root ? yyjson_obj_get(root, "size") : NULL;
    yyjson_val *uid = root ? yyjson_obj_get(root, "uid") : NULL;
    yyjson_val *gid = root ? yyjson_obj_get(root, "gid") : NULL;
    const char *path = root ? metadata_string(yyjson_obj_get(root, "path")) : NULL;
    const char *sha = root ? metadata_string(yyjson_obj_get(root, "sha256")) : NULL;
    const char *mode = root ? metadata_string(yyjson_obj_get(root, "mode")) : NULL;
    const char *context = root ? metadata_string(yyjson_obj_get(root, "context")) : NULL;
    yyjson_val *sidecars = root ? yyjson_obj_get(root, "sidecars") : NULL;
    int valid = yyjson_is_obj(root) && yyjson_obj_size(root) == 9 &&
                yyjson_is_uint(schema) && yyjson_get_uint(schema) == 2 &&
                yyjson_is_uint(size) && yyjson_get_uint(size) > 0 &&
                yyjson_get_uint(size) <= MAX_POLICY_BYTES && yyjson_is_uint(uid) &&
                yyjson_get_uint(uid) <= UINT32_MAX && yyjson_is_uint(gid) &&
                yyjson_get_uint(gid) <= UINT32_MAX && path &&
                !strcmp(path, VENDOR_POLICY_FILE) && sha && strlen(sha) == 64 &&
                strspn(sha, "0123456789abcdef") == 64 && mode && strlen(mode) == 4 &&
                mode[0] == '0' && strspn(mode, "01234567") == 4 && context &&
                strlen(context) <= 128 && !strncmp(context, "u:object_r:", 11) &&
                strspn(context, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_:,.-") == strlen(context) &&
                yyjson_is_arr(sidecars);
    static const char *paths9[] = {
        "/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256"
    };
    static const char *paths11[] = {
        "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
        "/vendor/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256",
        "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256"
    };
    size_t count = valid ? yyjson_arr_size(sidecars) : 0;
    const char **paths = count == 1 ? paths9 : count == 3 ? paths11 : NULL;
    valid = valid && paths;
    for (size_t i = 0; valid && i < count; i++) {
        yyjson_val *item = yyjson_arr_get(sidecars, i);
        yyjson_val *present = yyjson_obj_get(item, "present");
        yyjson_val *pristine = yyjson_obj_get(item, "pristine");
        yyjson_val *label = yyjson_obj_get(item, "selinuxContext");
        yyjson_val *su = yyjson_obj_get(item, "uid");
        yyjson_val *sg = yyjson_obj_get(item, "gid");
        yyjson_val *sm = yyjson_obj_get(item, "mode");
        const char *sp = metadata_string(yyjson_obj_get(item, "path"));
        const char *sh = metadata_string(yyjson_obj_get(item, "sha256"));
        valid = yyjson_is_obj(item) && yyjson_obj_size(item) == 8 && sp &&
                !strcmp(sp, paths[i]) && sh && strlen(sh) == 64 &&
                strspn(sh, "0123456789abcdef") == 64 && yyjson_is_bool(present) &&
                yyjson_is_arr(pristine) && yyjson_arr_size(pristine) <= 512 &&
                (yyjson_get_bool(present) || yyjson_arr_size(pristine) == 0) &&
                yyjson_is_uint(su) && yyjson_get_uint(su) == 0 &&
                yyjson_is_uint(sg) && yyjson_get_uint(sg) == 0 &&
                yyjson_is_uint(sm) && (yyjson_get_uint(sm) == 0444 || yyjson_get_uint(sm) == 0644) &&
                yyjson_is_arr(label) && yyjson_arr_size(label) <= 129;
        unsigned char data[512], label_bytes[129];
        size_t n = valid ? yyjson_arr_size(pristine) : 0;
        size_t ln = valid ? yyjson_arr_size(label) : 0;
        for (size_t j = 0; valid && j < n; j++) {
            yyjson_val *v = yyjson_arr_get(pristine, j);
            valid = yyjson_is_uint(v) && yyjson_get_uint(v) <= 255;
            if (valid) {
                data[j] = (unsigned char)yyjson_get_uint(v);
            }
        }
        for (size_t j = 0; valid && j < ln; j++) {
            yyjson_val *v = yyjson_arr_get(label, j);
            valid = yyjson_is_uint(v) && yyjson_get_uint(v) <= 255;
            if (valid) {
                label_bytes[j] = (unsigned char)yyjson_get_uint(v);
            }
        }
        if (valid && ln && label_bytes[ln - 1] == 0) {
            ln--;
        }
        if (valid) {
            char actual[65];
            sha256_hex(data, n, actual);
            valid = !strcmp(actual, sh) && ln >= 11 && ln <= 128 &&
                    !memcmp(label_bytes, "u:object_r:", 11);
            for (size_t j = 0; valid && j < ln; j++) {
                valid = strchr("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_:,.-", label_bytes[j]) != NULL && label_bytes[j] != 0;
            }
        }
    }
    if (valid) {
        memset(out, 0, sizeof(*out));
        out->size = yyjson_get_uint(size);
        out->uid = (uid_t)yyjson_get_uint(uid);
        out->gid = (gid_t)yyjson_get_uint(gid);
        memcpy(out->sha256, sha, 65);
        memcpy(out->mode_text, mode, 5);
        for (size_t i = 0; i < 4; i++) {
            out->mode = (out->mode << 3) | (mode[i] - '0');
        }
        memcpy(out->context, context, strlen(context) + 1);
    }
    if (doc) {
        yyjson_doc_free(doc);
    }
    return valid ? 0 : -1;
}

static int parse_backup_metadata(const unsigned char *bytes, size_t length,
                                 struct backup_metadata *out) {
    if (!length || length > MAX_META_BYTES || memchr(bytes, '\0', length)) {
        return -1;
    }
    if (parse_backup_metadata_v2(bytes, length, out) == 0) {
        return 0;
    }
    if (bytes[length - 1] != '\n') {
        return -1;
    }
    char text[MAX_META_BYTES + 1];
    memcpy(text, bytes, length);
    text[length] = '\0';
    unsigned long long size = 0;
    unsigned uid = 0;
    unsigned gid = 0;
    char sha256[65] = {0};
    char mode_text[5] = {0};
    char context[129] = {0};
    int consumed = 0;
    int fields = sscanf(
        text,
        "{\"schemaVersion\":1,\"path\":\"/vendor/etc/selinux/"
        "precompiled_sepolicy\",\"size\":%llu,\"sha256\":\"%64[0-9a-f]\","
        "\"uid\":%u,\"gid\":%u,\"mode\":\"%4[0-7]\","
        "\"context\":\"%128[0-9A-Za-z_:,.-]\"}\n%n",
        &size, sha256, &uid, &gid, mode_text, context, &consumed);
    if (fields != 6 || consumed != (int)length || !size ||
        size > MAX_POLICY_BYTES || strlen(sha256) != 64 ||
        strlen(mode_text) != 4 || mode_text[0] != '0') {
        return -1;
    }
    mode_t mode = 0;
    for (size_t i = 0; i < 4; i++) {
        mode = (mode << 3) | (mode_t)(mode_text[i] - '0');
    }
    size_t context_length = strlen(context);
    if (!context_length || context_length > 128 ||
        strncmp(context, "u:object_r:", 11) != 0) {
        return -1;
    }
    char canonical[MAX_META_BYTES + 1];
    int canonical_length = snprintf(
        canonical, sizeof(canonical),
        "{\"schemaVersion\":1,\"path\":\"/vendor/etc/selinux/"
        "precompiled_sepolicy\",\"size\":%llu,\"sha256\":\"%s\","
        "\"uid\":%u,\"gid\":%u,\"mode\":\"%s\","
        "\"context\":\"%s\"}\n",
        size, sha256, uid, gid, mode_text, context);
    if (canonical_length != (int)length ||
        memcmp(canonical, bytes, length) != 0) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->size = size;
    memcpy(out->sha256, sha256, 65);
    out->uid = (uid_t)uid;
    out->gid = (gid_t)gid;
    out->mode = mode;
    memcpy(out->mode_text, mode_text, 5);
    memcpy(out->context, context, context_length + 1);
    return 0;
}

static int fsync_parent_directory(const char *path) {
    char parent[512];
    size_t length = strlen(path);
    if (!length || length >= sizeof(parent)) {
        return -1;
    }
    memcpy(parent, path, length + 1);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) {
        return -1;
    }
    *slash = '\0';
    int fd = open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    int result = fsync(fd);
    close(fd);
    return result;
}

static int atomic_write(const char *path, const unsigned char *bytes,
                        size_t length, uid_t uid, gid_t gid, mode_t mode,
                        const char *context, int replace) {
    char temporary[640];
    int formatted = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
                             (long)getpid());
    if (formatted <= 0 || (size_t)formatted >= sizeof(temporary)) {
        return -1;
    }
    int fd = open(temporary,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count <= 0) {
            close(fd);
            unlink(temporary);
            return -1;
        }
        offset += (size_t)count;
    }
    int result = 0;
    if (fchown(fd, uid, gid) != 0 || fchmod(fd, mode) != 0) {
        result = -1;
    }
    if (!result && context) {
#if defined(__APPLE__)
        if (fsetxattr(fd, "security.selinux", context, strlen(context), 0, 0) !=
            0)
#else
        if (fsetxattr(fd, "security.selinux", context, strlen(context), 0) != 0)
#endif
        {result = -1;}
    }
    if (!result && fsync(fd) != 0) {
        result = -1;
    }
    if (close(fd) != 0) {
        result = -1;
    }
    if (!result) {
        if (replace) {
            if (rename(temporary, path) != 0) {
                result = -1;
            }
        } else if (link(temporary, path) != 0 || unlink(temporary) != 0) {
            result = -1;
        }
    }
    if (!result && fsync_parent_directory(path) != 0) {
        result = -1;
    }
    if (result) {
        unlink(temporary);
    }
    return result;
}

/* --- retained root-zone authority -------------------------------------- */

struct root_authority {
    int root_fd;
    int fd;
    uid_t uid;
    gid_t gid;
    struct stat directory_st;
    struct stat root_st;
    struct stat marker_st;
    char path[PATH_MAX];
    char root_path[PATH_MAX];
};

static int exact_state_directory(const struct stat *st, uid_t uid, gid_t gid) {
    return S_ISDIR(st->st_mode) && st->st_uid == uid && st->st_gid == gid &&
           (st->st_mode & 07777) == 0755 && st->st_nlink >= 2;
}

static int read_marker_at(int directory_fd, uid_t uid, gid_t gid,
                          struct stat *out_st) {
    int fd = openat(directory_fd, ROOT_MARKER_NAME,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat before, after;
    char bytes[sizeof(ROOT_MARKER_BYTES) - 1];
    size_t offset = 0;
    int valid = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
                before.st_nlink == 1 && before.st_uid == uid &&
                before.st_gid == gid && (before.st_mode & 07777) == 0600 &&
                before.st_size == (off_t)sizeof(bytes);
    while (valid && offset < sizeof(bytes)) {
        ssize_t count = read(fd, bytes + offset, sizeof(bytes) - offset);
        if (count <= 0) {
            valid = 0;
        } else {
            offset += (size_t)count;
        }
    }
    unsigned char extra;
    valid = valid && read(fd, &extra, 1) == 0 &&
            fstat(fd, &after) == 0 && same_file_stamp(&before, &after) &&
            memcmp(bytes, ROOT_MARKER_BYTES, sizeof(bytes)) == 0;
    close(fd);
    if (!valid) {
        return -1;
    }
    *out_st = before;
    return 0;
}

static int root_authority_current(const struct root_authority *authority) {
    struct stat held, current, root_held, root_current, marker;
    if (fstat(authority->fd, &held) != 0 ||
        !exact_state_directory(&held, authority->uid, authority->gid) ||
        held.st_dev != authority->directory_st.st_dev ||
        held.st_ino != authority->directory_st.st_ino ||
        fstat(authority->root_fd, &root_held) != 0 ||
        !exact_state_directory(&root_held, authority->uid, authority->gid) ||
        root_held.st_dev != authority->root_st.st_dev ||
        root_held.st_ino != authority->root_st.st_ino ||
        read_marker_at(authority->root_fd, authority->uid, authority->gid,
                       &marker) != 0 ||
        marker.st_dev != authority->marker_st.st_dev ||
        marker.st_ino != authority->marker_st.st_ino) {
        return 0;
    }
    int current_fd = open(authority->path,
                          O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int root_current_fd = open(authority->root_path,
                               O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int valid = current_fd >= 0 && root_current_fd >= 0 &&
                fstat(current_fd, &current) == 0 &&
                fstat(root_current_fd, &root_current) == 0 &&
                current.st_dev == authority->directory_st.st_dev &&
                current.st_ino == authority->directory_st.st_ino &&
                exact_state_directory(&current, authority->uid,
                                      authority->gid) &&
                root_current.st_dev == authority->root_st.st_dev &&
                root_current.st_ino == authority->root_st.st_ino &&
                exact_state_directory(&root_current, authority->uid,
                                      authority->gid);
    if (current_fd >= 0) {
        close(current_fd);
    }
    if (root_current_fd >= 0) {
        close(root_current_fd);
    }
    return valid;
}

static int open_root_authority_at(const char *path, uid_t uid, gid_t gid,
                                  struct root_authority *out) {
    memset(out, 0, sizeof(*out));
    out->root_fd = -1;
    out->fd = -1;
    size_t path_length = strlen(path);
    if (!path_length || path_length >= sizeof(out->path)) {
        return -1;
    }
    int root_fd = open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int fd = root_fd >= 0 ? dup(root_fd) : -1;
    struct stat directory_st, marker_st;
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 ||
        fstat(fd, &directory_st) != 0 ||
        !exact_state_directory(&directory_st, uid, gid) ||
        read_marker_at(root_fd, uid, gid, &marker_st) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        if (root_fd >= 0) {
            close(root_fd);
        }
        return -1;
    }
    out->root_fd = root_fd;
    out->fd = fd;
    out->uid = uid;
    out->gid = gid;
    out->directory_st = directory_st;
    out->root_st = directory_st;
    out->marker_st = marker_st;
    memcpy(out->path, path, path_length + 1);
    memcpy(out->root_path, path, path_length + 1);
    if (!root_authority_current(out)) {
        close(out->fd);
        close(out->root_fd);
        out->fd = -1;
        out->root_fd = -1;
        return -1;
    }
    return 0;
}

static void close_root_authority(struct root_authority *authority);

static void close_root_authority(struct root_authority *authority) {
    if (authority->fd >= 0) {
        close(authority->fd);
    }
    authority->fd = -1;
    if (authority->root_fd >= 0) {
        close(authority->root_fd);
    }
    authority->root_fd = -1;
}

static int backup_matches_metadata(const struct trusted_file *backup,
                                   const struct backup_metadata *metadata) {
    char sha256[65];
    sha256_hex(backup->data, backup->length, sha256);
    return backup->st.st_uid == 0 && backup->st.st_gid == 0 &&
           (backup->st.st_mode & 07777) == 0600 &&
           backup->length == metadata->size &&
           strcmp(sha256, metadata->sha256) == 0;
}

static int source_matches_metadata(const struct trusted_file *source,
                                   const struct backup_metadata *metadata) {
    char sha256[65];
    sha256_hex(source->data, source->length, sha256);
    return source->length == metadata->size &&
           source->st.st_uid == metadata->uid &&
           source->st.st_gid == metadata->gid &&
           (source->st.st_mode & 07777) == metadata->mode &&
           strcmp(source->context, metadata->context) == 0 &&
           strcmp(sha256, metadata->sha256) == 0;
}

static int policy_backup_path(const char *sha256, char out[PATH_MAX]) {
    if (!sha256 || strlen(sha256) != 64) {
        return -1;
    }
    for (size_t i = 0; i < 64; i++) {
        if (!((sha256[i] >= '0' && sha256[i] <= '9') ||
              (sha256[i] >= 'a' && sha256[i] <= 'f'))) {
            return -1;
        }
    }
    int length = snprintf(
        out, PATH_MAX,
        "/data/voboost/uninstall/baselines/%s/precompiled_sepolicy.orig",
        sha256);
    return length > 0 && length < PATH_MAX ? 0 : -1;
}

static int exact_private_directory(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
           st.st_gid == 0 && (st.st_mode & 07777) == 0700 && st.st_nlink >= 2;
}

static int ensure_private_directory(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    if (!exact_private_directory(path) || fsync_parent_directory(path) != 0) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int result = fd >= 0 && fsync(fd) == 0 ? 0 : -1;
    if (fd >= 0) {
        close(fd);
    }
    return result;
}

static int ensure_policy_baseline_directory(const char *sha256) {
    char directory[PATH_MAX];
    int length = snprintf(directory, sizeof(directory), "%s/%s",
                          POLICY_BASELINES_DIRECTORY, sha256);
    return length > 0 && length < (int)sizeof(directory) &&
           ensure_private_directory(POLICY_BASELINES_DIRECTORY) == 0 &&
           ensure_private_directory(directory) == 0
               ? 0
               : -1;
}

static int load_backup_pair(struct trusted_file *backup,
                            struct backup_metadata *metadata) {
    memset(backup, 0, sizeof(*backup));
    memset(metadata, 0, sizeof(*metadata));
    struct trusted_file meta = {0};
    if (read_trusted_file(POLICY_META_FILE, MAX_META_BYTES, 0, &meta) != 0) {
        return -1;
    }
    int result = -1;
    char backup_path[PATH_MAX];
    if (meta.st.st_uid == 0 && meta.st.st_gid == 0 &&
        (meta.st.st_mode & 07777) == 0600 &&
        parse_backup_metadata(meta.data, meta.length, metadata) == 0 &&
        policy_backup_path(metadata->sha256, backup_path) == 0 &&
        read_trusted_file(backup_path, MAX_POLICY_BYTES, 0, backup) == 0 &&
        backup_matches_metadata(backup, metadata)) {
        result = 0;
    }
    free_trusted_file(&meta);
    if (result) {
        free_trusted_file(backup);
    }
    return result;
}

static int backup_pristine_policy(void) {
    struct trusted_file source;
    if (read_trusted_file(VENDOR_POLICY_FILE, MAX_POLICY_BYTES, 1, &source) != 0) {
        return 3;
    }
    char source_sha256[65];
    sha256_hex(source.data, source.length, source_sha256);
    char backup_path[PATH_MAX];
    if (policy_backup_path(source_sha256, backup_path) != 0) {
        free_trusted_file(&source);
        return 3;
    }
    struct stat backup_stat, meta_stat;
    int backup_exists = lstat(backup_path, &backup_stat) == 0;
    int meta_exists = lstat(POLICY_META_FILE, &meta_stat) == 0;
    if (backup_exists || meta_exists) {
        struct trusted_file backup;
        struct backup_metadata metadata;
        int valid = backup_exists && meta_exists &&
                    load_backup_pair(&backup, &metadata) == 0 &&
                    source_matches_metadata(&source, &metadata);
        if (valid) {
            free_trusted_file(&backup);
        }
        free_trusted_file(&source);
        return valid ? 0 : 3;
    }
    struct backup_metadata metadata = {
        .size = source.length,
        .uid = source.st.st_uid,
        .gid = source.st.st_gid,
        .mode = source.st.st_mode & 07777,
    };
    memcpy(metadata.sha256, source_sha256, sizeof(metadata.sha256));
    snprintf(metadata.mode_text, sizeof(metadata.mode_text), "%04o",
             metadata.mode);
    memcpy(metadata.context, source.context, sizeof(metadata.context));
    char meta[MAX_META_BYTES + 1];
    int meta_length = snprintf(
        meta, sizeof(meta),
        "{\"schemaVersion\":1,\"path\":\"/vendor/etc/selinux/"
        "precompiled_sepolicy\",\"size\":%llu,\"sha256\":\"%s\","
        "\"uid\":%u,\"gid\":%u,\"mode\":\"%s\","
        "\"context\":\"%s\"}\n",
        (unsigned long long)metadata.size, metadata.sha256,
        (unsigned)metadata.uid, (unsigned)metadata.gid, metadata.mode_text,
        metadata.context);
    int result = -1;
    if (meta_length > 0 && meta_length <= (int)MAX_META_BYTES &&
        ensure_policy_baseline_directory(metadata.sha256) == 0 &&
        atomic_write(backup_path, source.data, source.length, 0, 0, 0600,
                     NULL, 0) == 0 &&
        atomic_write(POLICY_META_FILE, (const unsigned char *)meta,
                     (size_t)meta_length, 0, 0, 0600, NULL, 0) == 0) {
        result = 0;
    }
    free_trusted_file(&source);
    return result ? 5 : 0;
}

static int restore_pristine_policy(void) {
    struct trusted_file backup;
    struct backup_metadata metadata;
    if (load_backup_pair(&backup, &metadata) != 0) {
        return 3;
    }
    if (inspect_trusted_target(VENDOR_POLICY_FILE, MAX_POLICY_BYTES) != 0) {
        free_trusted_file(&backup);
        return 3;
    }
    int result = atomic_write(VENDOR_POLICY_FILE, backup.data, backup.length,
                              metadata.uid, metadata.gid, metadata.mode,
                              metadata.context, 1);
    free_trusted_file(&backup);
    if (result) {
        return 5;
    }
    struct trusted_file restored;
    if (read_trusted_file(VENDOR_POLICY_FILE, MAX_POLICY_BYTES, 1, &restored) !=
        0) {
        return 6;
    }
    int exact = source_matches_metadata(&restored, &metadata);
    free_trusted_file(&restored);
    return exact ? 0 : 6;
}

/* --- policy read / load -------------------------------------------------- */

static unsigned char *read_file_bounded(const char *path, size_t maximum,
                                        size_t *out_len) {
    if (maximum == 0) {
        errno = EINVAL;
        return NULL;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return NULL;
    }
    size_t cap = maximum < (1u << 20) ? maximum : (1u << 20);
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }
    for (;;) {
        if (len == cap) {
            if (cap == maximum) {
                unsigned char extra;
                ssize_t count = read(fd, &extra, 1);
                if (count == 0) {
                    break;
                }
                int failure = count < 0 ? errno : EFBIG;
                free(buf);
                close(fd);
                errno = failure;
                return NULL;
            }
            size_t next = cap > maximum / 2 ? maximum : cap * 2;
            unsigned char *nb = realloc(buf, next);
            if (!nb) {
                free(buf);
                close(fd);
                errno = ENOMEM;
                return NULL;
            }
            buf = nb;
            cap = next;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) {
            int saved_errno = errno;
            free(buf);
            close(fd);
            errno = saved_errno;
            return NULL;
        }
        if (n == 0) {
            break;
        }
        len += (size_t)n;
    }
    close(fd);
    *out_len = len;
    return buf;
}

static unsigned char *read_file(const char *path, size_t *out_len) {
    return read_file_bounded(path, MAX_POLICY_BYTES, out_len);
}

static policydb_t *policy_read_current(void) {
    size_t len = 0;
    unsigned char *buf = read_file(POLICY_FILE, &len);
    if (!buf) {
        return NULL;
    }
    struct sepol_policy_file *spf = NULL;
    policydb_t *pdb = calloc(1, sizeof(*pdb));
    if (!pdb || policydb_init(pdb) != 0 || sepol_policy_file_create(&spf) != 0) {
        if (pdb) {
            policydb_destroy(pdb);
        }
        free(pdb);
        free(buf);
        return NULL;
    }
    sepol_policy_file_set_mem(spf, (char *)buf, len);
    if (policydb_read(pdb, (struct policy_file *)spf, 0) != 0) {
        policydb_destroy(pdb);
        free(pdb);
        pdb = NULL;
    }
    sepol_policy_file_free(spf);
    free(buf);
    return pdb;
}

static int policy_context_valid(policydb_t *pdb) {
    /* u:r:voboost:s0 must resolve: role r must hold the type. */
    role_datum_t *role = (role_datum_t *)hashtab_search(
        pdb->symtab[SYM_ROLES].table, (const hashtab_key_t)"r");
    type_datum_t *type = (type_datum_t *)hashtab_search(
        pdb->symtab[SYM_TYPES].table, (const hashtab_key_t)"voboost");
    if (!role || !type) {
        return 0;
    }
    return ebitmap_get_bit(&role->types.types, type->s.value - 1);
}

static int write_buf_to_load(const unsigned char *buf, size_t size) {
    int fd = open(LOAD_FILE, O_WRONLY);
    if (fd < 0) {
        klog("open %s failed: %s", LOAD_FILE, strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, buf + off, size - off);
        if (n <= 0) {
            klog("write to load failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    close(fd);
    return 0;
}

static int policy_load(policydb_t *pdb) {
    /* Serialize into an anonymous in-memory file, then push it to
     * /sys/fs/selinux/load with a single write(2). */
    /* memfd_create syscall numbers (bionic lacks the wrapper below API 30):
     * aarch64 279, arm 385, x86_64 319. */
#if defined(__APPLE__)
#define VOBOOST_SYS_memfd_create 319
#elif defined(__aarch64__)
#define VOBOOST_SYS_memfd_create 279
#elif defined(__arm__)
#define VOBOOST_SYS_memfd_create 385
#elif defined(__x86_64__)
#define VOBOOST_SYS_memfd_create 319
#else
#define VOBOOST_SYS_memfd_create 319
#endif
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    int mfd = (int)syscall(VOBOOST_SYS_memfd_create, "voboost-policy",
                           1 /*CLOEXEC*/);
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#endif
    if (mfd < 0) {
        klog("memfd_create failed: %s", strerror(errno));
        return -1;
    }
    FILE *mf = fdopen(mfd, "w+");
    if (!mf) {
        close(mfd);
        return -1;
    }
    struct sepol_policy_file *spf = NULL;
    if (sepol_policy_file_create(&spf) != 0) {
        fclose(mf);
        return -1;
    }
    sepol_policy_file_set_fp(spf, mf);
    if (policydb_write(pdb, (struct policy_file *)spf) != 0) {
        sepol_policy_file_free(spf);
        fclose(mf);
        klog("policydb_write failed");
        return -1;
    }
    sepol_policy_file_free(spf);
    if (fflush(mf) != 0) {
        fclose(mf);
        return -1;
    }
    long size = ftell(mf);
    if (size <= 0 || (uint64_t)size > MAX_POLICY_BYTES ||
        fseek(mf, 0, SEEK_SET) != 0) {
        fclose(mf);
        return -1;
    }
    unsigned char *buf = malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, mf) != (size_t)size) {
        free(buf);
        fclose(mf);
        return -1;
    }
    fclose(mf);

    int rc = write_buf_to_load(buf, (size_t)size);
    free(buf);
    return rc;
}

/* --- main ---------------------------------------------------------------- */

static int write_file_copy(const char *path, const unsigned char *buf, size_t len);

struct policy_operation_paths {
    char input[PATH_MAX];
    char output[PATH_MAX];
    char rollback[PATH_MAX];
    char candidate_executable[PATH_MAX];
    char prepare_ack[PATH_MAX];
    char transaction_id[65];
    char boot_id[37];
    char executable_sha256[65];
    char manifest_sha256[65];
    char release_identity[129];
    int selinux_changed;
    char input_sha256[65];
    char output_sha256[65];
    char rollback_sha256[65];
};

enum policy_operation_mode {
    POLICY_OPERATION_LEGACY,
    POLICY_OPERATION_PRODUCT_INSTALL,
    POLICY_OPERATION_PRODUCT_PREPARE,
    POLICY_OPERATION_PRODUCT_CHECK,
};

static int canonical_lower_sha256(const char *value) {
    if (!value || strlen(value) != 64) {
        return 0;
    }
    for (const char *cursor = value; *cursor; cursor++) {
        if (!((*cursor >= '0' && *cursor <= '9') ||
              (*cursor >= 'a' && *cursor <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int canonical_boot_id(const char *value) {
    if (!value || strlen(value) != 36) {
        return 0;
    }
    for (size_t index = 0; index < 36; index++) {
        char ch = value[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != '-') {
                return 0;
            }
        } else if (!((ch >= '0' && ch <= '9') ||
                     (ch >= 'a' && ch <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int trusted_document(const char *path, size_t maximum, uid_t uid, gid_t gid,
                            struct trusted_file *out) {
    if (read_trusted_file(path, maximum, 0, out) != 0 ||
        out->st.st_uid != uid || out->st.st_gid != gid ||
        (out->st.st_mode & 07777) != 0600) {
        free_trusted_file(out);
        return -1;
    }
    return 0;
}

static const char *required_string(yyjson_val *object, const char *name) {
    yyjson_val *value = yyjson_obj_get(object, name);
    return yyjson_is_str(value) ? yyjson_get_str(value) : NULL;
}

static int optional_sha256(yyjson_val *object, const char *name,
                           const char **out) {
    yyjson_val *value = yyjson_obj_get(object, name);
    if (yyjson_is_null(value)) {
        *out = NULL;
        return 1;
    }
    if (!yyjson_is_str(value) ||
        !canonical_lower_sha256(yyjson_get_str(value))) {
        return 0;
    }
    *out = yyjson_get_str(value);
    return 1;
}

static int product_activation_classes_valid(yyjson_val *classes,
                                            unsigned *seen_out) {
    if (!yyjson_is_arr(classes) || yyjson_arr_size(classes) == 0 ||
        yyjson_arr_size(classes) > 6) {
        return 0;
    }
    static const char *const admitted[] = {
        "package-installer", "agent-generation", "native-runtime",
        "restore-authority", "init", "metadata-only",
    };
    unsigned seen = 0;
    size_t previous_index = 0;
    int have_previous = 0;
    size_t index, maximum;
    yyjson_val *value;
    yyjson_arr_foreach(classes, index, maximum, value) {
        if (!yyjson_is_str(value)) {
            return 0;
        }
        const char *name = yyjson_get_str(value);
        size_t admitted_index;
        for (admitted_index = 0;
             admitted_index < sizeof(admitted) / sizeof(admitted[0]);
             admitted_index++) {
            if (!strcmp(name, admitted[admitted_index])) {
                break;
            }
        }
        if (admitted_index == sizeof(admitted) / sizeof(admitted[0]) ||
            (seen & (1u << admitted_index)) ||
            (have_previous && admitted_index <= previous_index)) {
            return 0;
        }
        seen |= 1u << admitted_index;
        previous_index = admitted_index;
        have_previous = 1;
    }
    *seen_out = seen;
    return (seen & ((1u << 2) | (1u << 4))) != 0 &&
           (seen & (1u << 5)) == 0;
}

static int product_candidate_valid(yyjson_val *candidate,
                                   const char *transaction,
                                   const char **executable_sha256,
                                   const char **manifest_sha256_out,
                                   const char **release_identity_out,
                                   int *selinux_changed) {
    if (!yyjson_is_obj(candidate) || yyjson_obj_size(candidate) != 4) {
        return 0;
    }
    const char *candidate_transaction =
        required_string(candidate, "transactionId");
    const char *release_identity = required_string(candidate, "releaseIdentity");
    const char *manifest_sha256 = required_string(candidate, "manifestSha256");
    yyjson_val *artifacts = yyjson_obj_get(candidate, "artifacts");
    if (!candidate_transaction || strcmp(candidate_transaction, transaction) != 0 ||
        !release_identity || !release_identity[0] || strlen(release_identity) > 128 ||
        !canonical_lower_sha256(manifest_sha256) ||
        !strcmp(manifest_sha256, transaction) || !yyjson_is_arr(artifacts) ||
        yyjson_arr_size(artifacts) == 0 || yyjson_arr_size(artifacts) > 1024) {
        return 0;
    }
    size_t index, maximum;
    yyjson_val *artifact;
    unsigned selinux_count = 0;
    unsigned init_count = 0;
    yyjson_arr_foreach(artifacts, index, maximum, artifact) {
        if (!yyjson_is_obj(artifact) || yyjson_obj_size(artifact) != 3) {
            return 0;
        }
        const char *file = required_string(artifact, "file");
        const char *sha256 = required_string(artifact, "sha256");
        yyjson_val *size = yyjson_obj_get(artifact, "size");
        if (!file || !file[0] || strlen(file) > 255 || strchr(file, '/') ||
            !yyjson_is_uint(size) || yyjson_get_uint(size) == 0 ||
            !canonical_lower_sha256(sha256)) {
            return 0;
        }
        for (size_t prior = 0; prior < index; prior++) {
            yyjson_val *previous = yyjson_arr_get(artifacts, prior);
            if (!strcmp(file, required_string(previous, "file"))) {
                return 0;
            }
        }
        if (!strcmp(file, "voboost-selinux")) {
            if (yyjson_get_uint(size) < SIG_TRAILER_BYTES ||
                yyjson_get_uint(size) > MAX_EXECUTABLE_BYTES) {
                return 0;
            }
            *executable_sha256 = sha256;
            selinux_count++;
        } else if (!strcmp(file, "voboost.rc")) {
            init_count++;
        }
    }
    if (selinux_count > 1 || init_count > 1 ||
        (selinux_count == 0 && init_count != 1)) {
        return 0;
    }
    *manifest_sha256_out = manifest_sha256;
    *release_identity_out = release_identity;
    *selinux_changed = selinux_count == 1;
    return 1;
}

static int product_origin_valid(yyjson_val *origin) {
    if (!yyjson_is_obj(origin)) {
        return 0;
    }
    const char *kind = required_string(origin, "kind");
    if (!kind) {
        return 0;
    }
    if (!strcmp(kind, "ota")) {
        return yyjson_obj_size(origin) == 1;
    }
    if (!strcmp(kind, "offline-explicit")) {
        return yyjson_obj_size(origin) == 2 &&
               canonical_lower_sha256(required_string(
                                          origin, "expected_active_manifest_sha256"));
    }
    return 0;
}

static int product_journal_valid(yyjson_val *journal,
                                 const char *transaction,
                                 const char *operation_boot_id,
                                 enum policy_operation_mode mode,
                                 struct policy_operation_paths *out) {
    if (!yyjson_is_obj(journal) || yyjson_obj_size(journal) != 21) {
        return 0;
    }
    yyjson_val *schema = yyjson_obj_get(journal, "schemaVersion");
    const char *operation = required_string(journal, "operation");
    yyjson_val *classes = yyjson_obj_get(journal, "activationClasses");
    yyjson_val *generation_only = yyjson_obj_get(journal, "generationOnly");
    yyjson_val *apk_only = yyjson_obj_get(journal, "apkOnly");
    yyjson_val *native_plan = yyjson_obj_get(journal, "nativePlan");
    yyjson_val *system_plan = yyjson_obj_get(journal, "systemPlan");
    const char *phase = required_string(journal, "phase");
    yyjson_val *failure = yyjson_obj_get(journal, "failure");
    const char *previous_generation = NULL;
    const char *next_generation = NULL;
    const char *init_previous = NULL;
    const char *init_candidate = NULL;
    const char *policy_previous = NULL;
    const char *policy_baseline = NULL;
    const char *policy_candidate = NULL;
    const char *executable_sha256 = NULL;
    const char *manifest_sha256 = NULL;
    const char *release_identity = NULL;
    int selinux_changed = 0;
    unsigned classes_seen = 0;
    const char *expected_phase = mode == POLICY_OPERATION_PRODUCT_CHECK
                                     ? "system-post-reboot"
                                     : "system-prepared";
    if (!yyjson_is_uint(schema) || yyjson_get_uint(schema) != 1 ||
        !operation || strcmp(operation, "product-update-proposal") != 0 ||
        !product_origin_valid(yyjson_obj_get(journal, "origin")) ||
        !product_candidate_valid(yyjson_obj_get(journal, "candidate"),
                                 transaction, &executable_sha256,
                                 &manifest_sha256, &release_identity,
                                 &selinux_changed) ||
        !product_activation_classes_valid(classes, &classes_seen) ||
        (selinux_changed ? !(classes_seen & (1u << 2))
                         : !(classes_seen & (1u << 4))) ||
        !yyjson_is_bool(generation_only) || !yyjson_is_bool(apk_only) ||
        !yyjson_is_bool(native_plan) || !yyjson_is_bool(system_plan) ||
        yyjson_get_bool(generation_only) || yyjson_get_bool(apk_only) ||
        yyjson_get_bool(native_plan) || !yyjson_get_bool(system_plan) ||
        !phase || strcmp(phase, expected_phase) != 0 ||
        !yyjson_is_null(failure) ||
        !optional_sha256(journal, "previousGeneration", &previous_generation) ||
        !optional_sha256(journal, "nextGeneration", &next_generation) ||
        !optional_sha256(journal, "systemInitPreviousSha256", &init_previous) ||
        !optional_sha256(journal, "systemInitCandidateSha256", &init_candidate) ||
        !optional_sha256(journal, "policyPreviousSha256", &policy_previous) ||
        !optional_sha256(journal, "policyBaselineSha256", &policy_baseline) ||
        !optional_sha256(journal, "policyCandidateSha256", &policy_candidate) ||
        (init_previous == NULL) != (init_candidate == NULL) ||
        !policy_previous || !policy_baseline ||
        (mode == POLICY_OPERATION_PRODUCT_CHECK ? !policy_candidate
                                                : policy_candidate != NULL)) {
        return 0;
    }
    yyjson_val *pre_boot = yyjson_obj_get(journal, "preRebootBootId");
    yyjson_val *post_boot = yyjson_obj_get(journal, "postRebootBootId");
    yyjson_val *rollback_boot = yyjson_obj_get(journal, "rollbackBootId");
    if (!yyjson_is_str(pre_boot) ||
        !canonical_boot_id(yyjson_get_str(pre_boot)) ||
        !yyjson_is_null(rollback_boot) ||
        (mode == POLICY_OPERATION_PRODUCT_CHECK
             ? !yyjson_is_str(post_boot) ||
         !canonical_boot_id(yyjson_get_str(post_boot)) ||
         !strcmp(yyjson_get_str(pre_boot), yyjson_get_str(post_boot)) ||
         strcmp(operation_boot_id, yyjson_get_str(post_boot)) != 0
             : !yyjson_is_null(post_boot) ||
         strcmp(operation_boot_id, yyjson_get_str(pre_boot)) != 0)) {
        return 0;
    }
    if (executable_sha256) {
        memcpy(out->executable_sha256, executable_sha256, 65);
    }
    memcpy(out->manifest_sha256, manifest_sha256, 65);
    memcpy(out->release_identity, release_identity,
           strlen(release_identity) + 1);
    out->selinux_changed = selinux_changed;
    memcpy(out->input_sha256, policy_baseline, 65);
    if (policy_candidate) {
        memcpy(out->output_sha256, policy_candidate, 65);
    }
    memcpy(out->rollback_sha256, policy_previous, 65);
    return 1;
}

static int reconstructed_selinux_authority(
    const char *root_directory, const char *transaction, uid_t expected_uid,
    gid_t expected_gid, struct policy_operation_paths *out) {
    char manifest_path[PATH_MAX];
    char signature_path[PATH_MAX];
    int manifest_length = snprintf(
        manifest_path, sizeof(manifest_path),
        "%s/install/%s/complete-candidate/voboost.json", root_directory,
        transaction);
    int signature_length = snprintf(
        signature_path, sizeof(signature_path),
        "%s/install/%s/complete-candidate/voboost.json.sig", root_directory,
        transaction);
    if (manifest_length <= 0 || manifest_length >= (int)sizeof(manifest_path) ||
        signature_length <= 0 ||
        signature_length >= (int)sizeof(signature_path)) {
        return 0;
    }
    struct trusted_file manifest_file;
    struct trusted_file signature_file;
    if (trusted_document(manifest_path, MAX_MANIFEST_BYTES, expected_uid,
                         expected_gid, &manifest_file) != 0 ||
        trusted_document(signature_path, 64, expected_uid, expected_gid,
                         &signature_file) != 0) {
        free_trusted_file(&manifest_file);
        return 0;
    }
    char manifest_sha256[65];
    sha256_hex(manifest_file.data, manifest_file.length, manifest_sha256);
    yyjson_doc *document =
        yyjson_read((const char *)manifest_file.data, manifest_file.length, 0);
    yyjson_val *manifest = document ? yyjson_doc_get_root(document) : NULL;
    yyjson_val *schema = manifest ? yyjson_obj_get(manifest, "schemaVersion") : NULL;
    const char *release_identity =
        manifest ? required_string(manifest, "releaseIdentity") : NULL;
    yyjson_val *compatibility =
        manifest ? yyjson_obj_get(manifest, "compatibility") : NULL;
    yyjson_val *artifacts = manifest ? yyjson_obj_get(manifest, "artifacts") : NULL;
    static const char *const compatibility_fields[] = {
        "installerProtocol", "operationProtocol", "appDaemonProtocol",
        "agentCatalogSchema", "agentEntryAbi", "implantAbi",
    };
    int valid = signature_file.length == 64 && yyjson_is_obj(manifest) &&
                yyjson_obj_size(manifest) == 4 && yyjson_is_uint(schema) &&
                yyjson_get_uint(schema) == 1 && release_identity &&
                !strcmp(release_identity, out->release_identity) &&
                !strcmp(manifest_sha256, out->manifest_sha256) &&
                yyjson_is_obj(compatibility) &&
                yyjson_obj_size(compatibility) == 6 && yyjson_is_arr(artifacts) &&
                yyjson_arr_size(artifacts) > 0 &&
                yyjson_arr_size(artifacts) <= 1024;
    for (size_t index = 0;
         valid && index < sizeof(compatibility_fields) /
         sizeof(compatibility_fields[0]);
         index++) {
        yyjson_val *value =
            yyjson_obj_get(compatibility, compatibility_fields[index]);
        const uint64_t expected =
            !strcmp(compatibility_fields[index], "agentCatalogSchema") ? 2u : 1u;
        valid = yyjson_is_uint(value) && yyjson_get_uint(value) == expected;
    }
    unsigned selinux_count = 0;
    size_t index, maximum;
    yyjson_val *artifact;
    if (valid) {
        yyjson_arr_foreach(artifacts, index, maximum, artifact) {
            if (!yyjson_is_obj(artifact)) {
                valid = 0;
                break;
            }
            const char *file = required_string(artifact, "file");
            if (!file) {
                valid = 0;
                break;
            }
            if (strcmp(file, "voboost-selinux") != 0) {
                continue;
            }
            const char *role = required_string(artifact, "role");
            const char *activation = required_string(artifact, "activation");
            const char *sha256 = required_string(artifact, "sha256");
            yyjson_val *size = yyjson_obj_get(artifact, "size");
            if (yyjson_obj_size(artifact) != 5 || !role ||
                strcmp(role, "selinux") != 0 || !activation ||
                strcmp(activation, "native-runtime") != 0 ||
                !canonical_lower_sha256(sha256) || !yyjson_is_uint(size) ||
                yyjson_get_uint(size) < SIG_TRAILER_BYTES ||
                yyjson_get_uint(size) > MAX_EXECUTABLE_BYTES || selinux_count) {
                valid = 0;
                break;
            }
            if (out->executable_sha256[0] &&
                strcmp(out->executable_sha256, sha256) != 0) {
                valid = 0;
                break;
            }
            memcpy(out->executable_sha256, sha256, 65);
            selinux_count++;
        }
    }
    valid = valid && selinux_count == 1;
    yyjson_doc_free(document);
    free_trusted_file(&signature_file);
    free_trusted_file(&manifest_file);
    return valid;
}

static int resolve_policy_operation_mode_at(
    const char *operation_path, const char *root_directory,
    const char *stock_policy_path, uid_t expected_uid, gid_t expected_gid,
    enum policy_operation_mode mode, struct policy_operation_paths *out) {
    memset(out, 0, sizeof(*out));
    struct trusted_file operation_file;
    if (trusted_document(operation_path, 4096, expected_uid, expected_gid,
                         &operation_file) != 0) {
        return -1;
    }
    yyjson_doc *operation_document =
        yyjson_read((const char *)operation_file.data, operation_file.length, 0);
    yyjson_val *operation = operation_document
                                ? yyjson_doc_get_root(operation_document)
                                : NULL;
    yyjson_val *schema = operation ? yyjson_obj_get(operation, "schemaVersion") : NULL;
    yyjson_val *reboot_count = operation ? yyjson_obj_get(operation, "rebootCount") : NULL;
    yyjson_val *status_sequence = operation ? yyjson_obj_get(operation, "statusSequence") : NULL;
    yyjson_val *error = operation ? yyjson_obj_get(operation, "error") : NULL;
    yyjson_val *installed_apk = operation ? yyjson_obj_get(operation, "installedApk") : NULL;
    const char *operation_name = operation ? required_string(operation, "operation") : NULL;
    const char *transaction = operation ? required_string(operation, "transactionId") : NULL;
    const char *journal_claim = operation ? required_string(operation, "journal") : NULL;
    const char *phase = operation ? required_string(operation, "phase") : NULL;
    const char *outcome = operation ? required_string(operation, "outcome") : NULL;
    const char *boot_id = operation ? required_string(operation, "bootId") : NULL;
    const char *journal_sha256 = operation ? required_string(operation, "journalSha256") : NULL;
    int install = mode == POLICY_OPERATION_LEGACY && operation_name &&
                  !strcmp(operation_name, "install");
    int restore = mode == POLICY_OPERATION_LEGACY && operation_name &&
                  !strcmp(operation_name, "restore");
    int product = mode != POLICY_OPERATION_LEGACY && operation_name &&
                  !strcmp(operation_name, "update");
    const char *expected_phase = install ? "install-policy-apply" :
                                 restore ? "restore-policy-backup" :
                                 product && mode == POLICY_OPERATION_PRODUCT_CHECK
                                     ? "update-product-system-post-reboot"
                                     : product
                                         ? "update-product-system-prepared"
                                         : NULL;
    char journal_relative[PATH_MAX];
    char journal_path[PATH_MAX];
    int journal_relative_length = -1;
    if (transaction && expected_phase) {
        journal_relative_length =
            product ? snprintf(journal_relative, sizeof(journal_relative),
                               "recovery/%s/product-proposal.json", transaction)
                    : snprintf(journal_relative, sizeof(journal_relative),
                               "recovery/%s/%s-journal.json", transaction,
                               operation_name);
    }
    int journal_path_length = journal_relative_length > 0
                                  ? snprintf(journal_path, sizeof(journal_path),
                                             "%s/%s", root_directory,
                                             journal_relative)
                                  : -1;
    int valid = yyjson_is_obj(operation) && yyjson_obj_size(operation) == 12 &&
                yyjson_is_uint(schema) && yyjson_get_uint(schema) == 1 &&
                yyjson_is_uint(reboot_count) &&
                (!product || yyjson_get_uint(reboot_count) ==
                 (mode == POLICY_OPERATION_PRODUCT_CHECK ? 1u : 0u)) &&
                yyjson_is_uint(status_sequence) &&
                yyjson_get_uint(status_sequence) > 0 && yyjson_is_null(error) &&
                yyjson_is_null(installed_apk) && transaction &&
                canonical_lower_sha256(transaction) && boot_id &&
                canonical_boot_id(boot_id) && journal_claim && phase &&
                outcome && !strcmp(outcome, "running") && expected_phase &&
                !strcmp(phase, expected_phase) && journal_sha256 &&
                canonical_lower_sha256(journal_sha256) &&
                journal_relative_length > 0 &&
                journal_relative_length < (int)sizeof(journal_relative) &&
                journal_path_length > 0 && journal_path_length < (int)sizeof(journal_path) &&
                !strcmp(journal_claim, journal_relative);
    if (!valid) {
        yyjson_doc_free(operation_document);
        free_trusted_file(&operation_file);
        return -1;
    }
    struct trusted_file journal_file;
    if (trusted_document(journal_path, (size_t)1024 * 1024, expected_uid, expected_gid,
                         &journal_file) != 0) {
        yyjson_doc_free(operation_document);
        free_trusted_file(&operation_file);
        return -1;
    }
    char actual_journal_sha256[65];
    sha256_hex(journal_file.data, journal_file.length, actual_journal_sha256);
    yyjson_doc *journal_document =
        yyjson_read((const char *)journal_file.data, journal_file.length, 0);
    yyjson_val *journal = journal_document ? yyjson_doc_get_root(journal_document) : NULL;
    yyjson_val *journal_schema = journal ? yyjson_obj_get(journal, "schemaVersion") : NULL;
    const char *journal_transaction =
        journal ? required_string(journal, "transactionId") : NULL;
    const char *journal_phase = journal ? required_string(journal, "phase") : NULL;
    valid = !strcmp(actual_journal_sha256, journal_sha256) &&
            (product
                 ? product_journal_valid(journal, transaction, boot_id, mode,
                                         out)
                 : yyjson_is_obj(journal) && yyjson_is_uint(journal_schema) &&
             yyjson_get_uint(journal_schema) == 1 &&
             journal_transaction && journal_phase &&
             !strcmp(journal_transaction, transaction) &&
             !strcmp(journal_phase, phase));
    if (valid && product) {
        int input_length = snprintf(
            out->input, sizeof(out->input),
            "%s/recovery/%s/product-previous/policy-baseline",
            root_directory, transaction);
        int output_length = snprintf(
            out->output, sizeof(out->output),
            "%s/recovery/%s/product-previous/policy-candidate",
            root_directory, transaction);
        int rollback_length = snprintf(
            out->rollback, sizeof(out->rollback),
            "%s/recovery/%s/product-previous/policy-previous",
            root_directory, transaction);
        int executable_length = snprintf(
            out->candidate_executable, sizeof(out->candidate_executable),
            "%s/install/%s/complete-candidate/voboost-selinux",
            root_directory, transaction);
        int ack_length = snprintf(
            out->prepare_ack, sizeof(out->prepare_ack),
            "%s/recovery/%s/policy-prepare-ack.json", root_directory,
            transaction);
        valid = input_length > 0 && input_length < (int)sizeof(out->input) &&
                output_length > 0 && output_length < (int)sizeof(out->output) &&
                rollback_length > 0 &&
                rollback_length < (int)sizeof(out->rollback) &&
                executable_length > 0 &&
                executable_length < (int)sizeof(out->candidate_executable) &&
                ack_length > 0 && ack_length < (int)sizeof(out->prepare_ack);
        if (valid) {
            memcpy(out->transaction_id, transaction, 65);
            memcpy(out->boot_id, boot_id, 37);
            valid = reconstructed_selinux_authority(
                root_directory, transaction, expected_uid, expected_gid, out);
        }
    } else if (valid) {
        /* Legacy install patches the LOADED kernel policy, not the pristine
         * vendor blob: firmwares whose plat CIL is patched at build time
         * (voyemu free-09: canbus/oem service types) rebuild their policy
         * from CIL on boot, so the loaded policy is the only copy that
         * carries those rules. Patching precompiled_sepolicy.orig and
         * publishing it with a matching sidecar would silently displace the
         * firmware's CIL-level policy for as long as voboost is installed.
         * The pristine blob stays the rollback target (restore writes it
         * back and restores the stock sidecar, so init returns to its own
         * load decision). */
        int input_length = install
                               ? snprintf(out->input, sizeof(out->input),
                                          "%s", POLICY_FILE)
                               : snprintf(out->input, sizeof(out->input), "%s",
                                          stock_policy_path);
        int output_length = install
                                ? snprintf(out->output, sizeof(out->output),
                                           "%s/recovery/%s/precompiled_sepolicy.patched",
                                           root_directory, transaction)
                                : snprintf(out->output, sizeof(out->output),
                                           "%s/recovery/%s/voboost-policy.patched",
                                           root_directory, transaction);
        valid = input_length > 0 && input_length < (int)sizeof(out->input) &&
                output_length > 0 && output_length < (int)sizeof(out->output);
    }
    yyjson_doc_free(journal_document);
    free_trusted_file(&journal_file);
    yyjson_doc_free(operation_document);
    free_trusted_file(&operation_file);
    return valid ? 0 : -1;
}

static int resolve_policy_operation_at(const char *operation_path,
                                       const char *root_directory,
                                       const char *stock_policy_path,
                                       uid_t expected_uid,
                                       gid_t expected_gid,
                                       struct policy_operation_paths *out) {
    return resolve_policy_operation_mode_at(
        operation_path, root_directory, stock_policy_path, expected_uid,
        expected_gid, POLICY_OPERATION_LEGACY, out);
}

#include "boot_policy.h"

/* Transform the on-disk policy selected by the verified active operation.
* The public entrypoint accepts no file path. This internal function receives
* only paths derived from operation.json and its hash-bound journal.
* Exit codes mirror the runtime mode (0 ok/already, 3 read, 4 context). */
static int policy_file_operation(int check_only, const char *in, const char *out) {
    struct trusted_file input;
    memset(&input, 0, sizeof(input));
    if (strcmp(in, POLICY_FILE) == 0) {
        /* The selinuxfs policy dump reports st_size = 0, so the trusted-file
         * stat fence cannot apply. It is a kernel-generated image of the
         * loaded policy — the strongest possible source of trust — read to
         * EOF instead. */
        size_t loaded_len = 0;
        unsigned char *loaded = read_file_bounded(in, MAX_POLICY_BYTES, &loaded_len);
        if (!loaded && (errno == EACCES || errno == EPERM)) {
#ifdef __ANDROID__
            char sdk[PROP_VALUE_MAX] = {0};
            __system_property_get("ro.build.version.sdk", sdk);
            unsigned api = !strcmp(sdk, "28") ? 28u : !strcmp(sdk, "30") ? 30u : 0u;
            loaded = boot_policy_at("", api, 0, &loaded_len);
#else
            klog("stock boot reconstruction is unavailable outside Android");
#endif
        }
        if (!loaded || loaded_len == 0) {
            klog("cannot read or reconstruct %s: %s", in, strerror(errno));
            free(loaded);
            return 3;
        }
        input.data = loaded;
        input.length = loaded_len;
    } else if (read_trusted_file(in, MAX_POLICY_BYTES, 0, &input) != 0) {
        klog("cannot read %s", in);
        return 3;
    }
    size_t in_len = input.length;
    unsigned char *in_buf = input.data;
    struct sepol_policy_file *spf = NULL;
    policydb_t *pdb = calloc(1, sizeof(*pdb));
    if (!pdb) {
        free(in_buf);
        return 3;
    }
    if (policydb_init(pdb) != 0) {
        klog("policydb init failed");
        free(pdb);
        free(in_buf);
        return 3;
    }
    if (sepol_policy_file_create(&spf) != 0) {
        klog("policy file init failed");
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 3;
    }
    sepol_policy_file_set_mem(spf, (char *)in_buf, in_len);
    if (policydb_read(pdb, (struct policy_file *)spf, 0) != 0) {
        klog("policydb_read failed for %s", in);
        sepol_policy_file_free(spf);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 3;
    }
    sepol_policy_file_free(spf);

    if (check_only) {
        int applied = voboost_policy_applied(pdb);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return applied ? 0 : 9;
    }

    if (voboost_policy_applied(pdb)) {
        klog("policy already patched; copying input unchanged");
        policydb_destroy(pdb);
        free(pdb);
        int rc = write_file_copy(out, in_buf, in_len) == 0 ? 0 : 5;
        free(in_buf);
        return rc;
    }
    if (voboost_policy_inject(pdb) != 0) {
        klog("inject failed");
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 3;
    }
    if (!policy_context_valid(pdb)) {
        klog("u:r:voboost:s0 does not resolve in patched policy");
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 4;
    }
    char output_temporary[PATH_MAX];
    if (snprintf(output_temporary, sizeof(output_temporary), "%s.tmp", out) < 0 ||
        strlen(output_temporary) >= sizeof(output_temporary) - 1) {
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    struct stat temporary_stat;
    if (lstat(output_temporary, &temporary_stat) == 0) {
        if (!S_ISREG(temporary_stat.st_mode) || temporary_stat.st_nlink != 1 ||
            temporary_stat.st_uid != geteuid() ||
            (temporary_stat.st_mode & 07777) != 0600 ||
            unlink(output_temporary) != 0) {
            policydb_destroy(pdb);
            free(pdb);
            free(in_buf);
            return 5;
        }
    } else if (errno != ENOENT) {
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    int output_fd = open(output_temporary,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
    FILE *of = output_fd >= 0 ? fdopen(output_fd, "wb") : NULL;
    if (!of) {
        if (output_fd >= 0) {
            close(output_fd);
        }
        klog("cannot open %s for writing", output_temporary);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    struct sepol_policy_file *ospf = NULL;
    if (sepol_policy_file_create(&ospf) != 0) {
        fclose(of);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    sepol_policy_file_set_fp(ospf, of);
    if (policydb_write(pdb, (struct policy_file *)ospf) != 0) {
        klog("policydb_write failed for %s", output_temporary);
        sepol_policy_file_free(ospf);
        fclose(of);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    if (fflush(of) != 0 || fsync(fileno(of)) != 0) {
        klog("flush failed for %s", output_temporary);
        sepol_policy_file_free(ospf);
        fclose(of);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    sepol_policy_file_free(ospf);
    if (fclose(of) != 0 || rename(output_temporary, out) != 0) {
        unlink(output_temporary);
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    char output_parent[PATH_MAX];
    if (snprintf(output_parent, sizeof(output_parent), "%s", out) < 0) {
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    char *slash = strrchr(output_parent, '/');
    if (!slash) {
        strcpy(output_parent, ".");
    } else if (slash == output_parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    int output_parent_fd = open(output_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (output_parent_fd < 0 || fsync(output_parent_fd) != 0) {
        if (output_parent_fd >= 0) {
            close(output_parent_fd);
        }
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    if (close(output_parent_fd) != 0) {
        policydb_destroy(pdb);
        free(pdb);
        free(in_buf);
        return 5;
    }
    policydb_destroy(pdb);
    free(pdb);
    free(in_buf);
    klog("policy file patched: %s -> %s", in, out);
    return 0;
}

static int write_file_copy(const char *path, const unsigned char *buf, size_t len) {
    int fd = open(path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;
    if (!f) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int trusted_file_matches(const char *path, size_t maximum, uid_t uid,
                                gid_t gid, mode_t mode,
                                const char *expected_sha256,
                                int require_context,
                                const char *expected_context,
                                struct trusted_file *out) {
    if (read_trusted_file(path, maximum, require_context, out) != 0) {
        return 0;
    }
    char actual_sha256[65];
    sha256_hex(out->data, out->length, actual_sha256);
    int valid = out->st.st_uid == uid && out->st.st_gid == gid &&
                (out->st.st_mode & 07777) == mode &&
                !strcmp(actual_sha256, expected_sha256) &&
                (!expected_context || !strcmp(out->context, expected_context));
    if (!valid) {
        free_trusted_file(out);
    }
    return valid;
}

static int product_executable_matches(const char *path, mode_t mode,
                                      const char *expected_sha256,
                                      int require_context,
                                      struct trusted_file *out) {
    if (!trusted_file_matches(
            path, MAX_EXECUTABLE_BYTES, 0, 0, mode, expected_sha256,
            require_context,
            require_context ? SELINUX_EXECUTABLE_CONTEXT : NULL, out)) {
        return 0;
    }
    if (!verify_selinux_signature_bytes(out->data, out->length)) {
        free_trusted_file(out);
        return 0;
    }
    return 1;
}

static int resolve_product_operation(enum policy_operation_mode mode,
                                     struct policy_operation_paths *paths) {
    return resolve_policy_operation_mode_at(
        OPERATION_FILE, ROOT_DIRECTORY, STOCK_POLICY_FILE, 0, 0, mode, paths);
}

/* Compare the actual new transform in memory. Do not copy previous grants
 * into the pristine baseline or publish a policy that drops existing types. */
static int product_policies_preserve_types(const struct trusted_file *baseline,
                                           const struct trusted_file *previous) {
    policydb_t candidate_policy, previous_policy;
    if (policydb_init(&candidate_policy) != 0) {
        return 0;
    }
    if (policydb_init(&previous_policy) != 0) {
        policydb_destroy(&candidate_policy);
        return 0;
    }
    struct sepol_policy_file *file = NULL;
    int valid = sepol_policy_file_create(&file) == 0;
    if (valid) {
        sepol_policy_file_set_mem(file, (char *)baseline->data, baseline->length);
        valid = policydb_read(&candidate_policy, (struct policy_file *)file, 0) == 0;
    }
    if (valid) {
        sepol_policy_file_set_mem(file, (char *)previous->data, previous->length);
        valid = policydb_read(&previous_policy, (struct policy_file *)file, 0) == 0;
    }
    if (valid) {
        valid = voboost_policy_inject(&candidate_policy) == 0 &&
                voboost_policy_preserves_types(&candidate_policy, &previous_policy);
    }
    if (file) {
        sepol_policy_file_free(file);
    }
    policydb_destroy(&previous_policy);
    policydb_destroy(&candidate_policy);
    return valid;
}

static int validate_product_policy_inputs(
    const struct policy_operation_paths *paths) {
    struct trusted_file baseline;
    struct trusted_file rollback;
    if (!trusted_file_matches(paths->input, MAX_POLICY_BYTES, 0, 0, 0600,
                              paths->input_sha256, 0, NULL, &baseline)) {
        return 0;
    }
    if (!trusted_file_matches(paths->rollback, MAX_POLICY_BYTES, 0, 0, 0600,
                              paths->rollback_sha256, 0, NULL, &rollback)) {
        free_trusted_file(&baseline);
        return 0;
    }
    struct trusted_file pristine;
    struct backup_metadata pristine_metadata;
    if (load_backup_pair(&pristine, &pristine_metadata) != 0 ||
        strcmp(pristine_metadata.sha256, paths->input_sha256) != 0 ||
        pristine.length != baseline.length ||
        memcmp(pristine.data, baseline.data, baseline.length) != 0) {
        free_trusted_file(&pristine);
        free_trusted_file(&rollback);
        free_trusted_file(&baseline);
        return 0;
    }
    int separate = baseline.st.st_dev != rollback.st.st_dev ||
                   baseline.st.st_ino != rollback.st.st_ino;
    int compatible = separate && product_policies_preserve_types(&baseline, &rollback);
    free_trusted_file(&pristine);
    free_trusted_file(&rollback);
    free_trusted_file(&baseline);
    return compatible;
}

static int format_prepare_ack(const struct policy_operation_paths *paths,
                              const char candidate_sha256[65], char ack[512]) {
    int length = snprintf(
        ack, 512,
        "{\"schemaVersion\":1,\"transactionId\":\"%s\","
        "\"bootId\":\"%s\",\"policyBaselineSha256\":\"%s\","
        "\"policyCandidateSha256\":\"%s\"}\n",
        paths->transaction_id, paths->boot_id, paths->input_sha256,
        candidate_sha256);
    return length > 0 && length < 512 ? length : -1;
}

static int publish_or_verify_prepare_ack(
    const struct policy_operation_paths *paths,
    const char candidate_sha256[65]) {
    char ack[512];
    int length = format_prepare_ack(paths, candidate_sha256, ack);
    if (length < 0) {
        return -1;
    }
    struct trusted_file existing;
    if (trusted_document(paths->prepare_ack, sizeof(ack), 0, 0, &existing) ==
        0) {
        int exact = existing.length == (size_t)length &&
                    !memcmp(existing.data, ack, (size_t)length);
        free_trusted_file(&existing);
        return exact ? 0 : -1;
    }
    struct stat existing_stat;
    if (lstat(paths->prepare_ack, &existing_stat) == 0 || errno != ENOENT) {
        return -1;
    }
    if (atomic_write(paths->prepare_ack, (const unsigned char *)ack,
                     (size_t)length, 0, 0, 0600, NULL, 0) != 0 ||
        trusted_document(paths->prepare_ack, sizeof(ack), 0, 0, &existing) !=
        0) {
        return -1;
    }
    int exact = existing.length == (size_t)length &&
                !memcmp(existing.data, ack, (size_t)length);
    free_trusted_file(&existing);
    return exact ? 0 : -1;
}

static int install_product_candidate(void) {
    struct policy_operation_paths paths;
    if (resolve_product_operation(POLICY_OPERATION_PRODUCT_INSTALL, &paths) != 0) {
        klog("product candidate install: operation/WAL authority rejected");
        return 8;
    }
    if (!validate_product_policy_inputs(&paths)) {
        klog("product candidate install: pristine or rollback policy identity rejected");
        return 8;
    }
    struct trusted_file candidate;
    if (!product_executable_matches(paths.candidate_executable, 0600,
                                    paths.executable_sha256, 0, &candidate)) {
        return 8;
    }
    struct trusted_file current;
    if (product_executable_matches(SELINUX_EXECUTABLE, 0700,
                                   paths.executable_sha256, 1, &current)) {
        free_trusted_file(&current);
        free_trusted_file(&candidate);
        return 0;
    }
    struct root_authority authority;
    if (open_root_authority_at(ROOT_ZONE_DIRECTORY, 0, 0, &authority) != 0) {
        free_trusted_file(&candidate);
        return 8;
    }
    int write_ok = root_authority_current(&authority) &&
                   atomic_write(SELINUX_EXECUTABLE, candidate.data,
                                candidate.length, 0, 0, 0700,
                                SELINUX_EXECUTABLE_CONTEXT, 1) == 0 &&
                   root_authority_current(&authority);
    /* On emulator profiles the stock policy lacks voboost_selinux_exec, so
     * fsetxattr for the production context fails. Retry without a context
     * so the candidate binary installs with its existing label; the policy
     * is loaded in the subsequent --prepare-product-policy step. */
    if (!write_ok) {
        write_ok = root_authority_current(&authority) &&
                   atomic_write(SELINUX_EXECUTABLE, candidate.data,
                                candidate.length, 0, 0, 0700,
                                NULL, 1) == 0 &&
                   root_authority_current(&authority);
    }
    int result = write_ok ? 0 : 8;
    free_trusted_file(&candidate);
    if (result == 0 &&
        !product_executable_matches(SELINUX_EXECUTABLE, 0700,
                                    paths.executable_sha256, 1, &current)) {
        result = 8;
    } else if (result == 0) {
        free_trusted_file(&current);
    }
    close_root_authority(&authority);
    return result;
}

static int prepare_product_policy(void) {
    struct policy_operation_paths paths;
    if (resolve_product_operation(POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0) {
        klog("product policy prepare: operation/WAL authority rejected");
        return 8;
    }
    if (!validate_product_policy_inputs(&paths)) {
        klog("product policy prepare: pristine or rollback policy identity rejected");
        return 8;
    }
    struct trusted_file executable;
    if (!product_executable_matches(SELINUX_EXECUTABLE, 0700,
                                    paths.executable_sha256, 1, &executable)) {
        return 8;
    }
    free_trusted_file(&executable);
    int baseline_state = policy_file_operation(1, paths.input, paths.input);
    if (baseline_state != 9) {
        return baseline_state == 0 ? 8 : baseline_state;
    }
    int result = policy_file_operation(0, paths.input, paths.output);
    if (result != 0) {
        return result;
    }
    struct trusted_file output;
    if (read_trusted_file(paths.output, MAX_POLICY_BYTES, 0, &output) != 0 ||
        output.st.st_uid != 0 || output.st.st_gid != 0 ||
        (output.st.st_mode & 07777) != 0600) {
        free_trusted_file(&output);
        return 8;
    }
    char candidate_sha256[65];
    sha256_hex(output.data, output.length, candidate_sha256);
    free_trusted_file(&output);
    result = policy_file_operation(1, paths.output, paths.output);
    if (result != 0) {
        return result;
    }
    return publish_or_verify_prepare_ack(&paths, candidate_sha256) == 0 ? 0 : 8;
}

/* The kernel writes a new binary image when userspace reads its loaded policy.
 * Compare the parsed table and the rest of the policy separately for diagnostics.
 * A different binary image still fails the post-reboot check. */
static int policy_image_read(policydb_t *policy, const unsigned char *bytes, size_t length) {
    if (policydb_init(policy) != 0) {
        return 0;
    }
    struct policy_file file;
    policy_file_init(&file);
    file.type = PF_USE_MEMORY;
    file.data = (char *)bytes;
    file.len = length;
    if (policydb_read(policy, &file, 0) == 0 && file.len == 0) {
        return 1;
    }
    policydb_destroy(policy);
    return 0;
}

static int policy_rule_order(const void *left, const void *right) {
    const struct avtab_node *a = *(const avtab_ptr_t *)left;
    const struct avtab_node *b = *(const avtab_ptr_t *)right;
    const uint16_t a_key[] = {a->key.source_type, a->key.target_type,
                              a->key.target_class, a->key.specified};
    const uint16_t b_key[] = {b->key.source_type, b->key.target_type,
                              b->key.target_class, b->key.specified};
    for (size_t i = 0; i < sizeof(a_key) / sizeof(a_key[0]); i++) {
        if (a_key[i] != b_key[i]) {
            return a_key[i] < b_key[i] ? -1 : 1;
        }
    }
    if (a->key.specified & AVTAB_OP) {
        if (a->datum.ops->specified != b->datum.ops->specified) {
            return (int)a->datum.ops->specified - b->datum.ops->specified;
        }
        if (a->datum.ops->driver != b->datum.ops->driver) {
            return (int)a->datum.ops->driver - b->datum.ops->driver;
        }
        return memcmp(a->datum.ops->perms, b->datum.ops->perms, sizeof(a->datum.ops->perms));
    }
    return a->datum.data < b->datum.data ? -1 : a->datum.data > b->datum.data;
}

static int policy_rules_collect(const avtab_t *table, avtab_ptr_t *rules) {
    size_t count = 0;
    for (uint32_t i = 0; i < table->nslot; i++) {
        for (avtab_ptr_t rule = table->htable[i]; rule; rule = rule->next) {
            if (count >= table->nel || ((rule->key.specified & AVTAB_OP) && !rule->datum.ops)) {
                return 0;
            }
            rules[count++] = rule;
        }
    }
    if (count != table->nel) {
        return 0;
    }
    qsort(rules, count, sizeof(*rules), policy_rule_order);
    return 1;
}

static int policy_rules_equal(const avtab_t *active, const avtab_t *candidate) {
    size_t count = active->nel;
    if (count != candidate->nel) {
        return 0;
    }
    if (count == 0) {
        return 1;
    }
    avtab_ptr_t *left = calloc(count, sizeof(*left));
    avtab_ptr_t *right = calloc(count, sizeof(*right));
    int equal = left && right && policy_rules_collect(active, left) &&
                policy_rules_collect(candidate, right);
    for (size_t i = 0; equal && i < count; i++) {
        equal = policy_rule_order(&left[i], &right[i]) == 0;
    }
    free(right);
    free(left);
    return equal;
}

static int filename_rule_order(const void *left, const void *right) {
    const filename_trans_t *a = *(const filename_trans_t *const *)left;
    const filename_trans_t *b = *(const filename_trans_t *const *)right;
    const uint32_t x[] = {a->stype, a->ttype, a->tclass, a->otype};
    const uint32_t y[] = {b->stype, b->ttype, b->tclass, b->otype};
    for (size_t i = 0; i < sizeof(x) / sizeof(x[0]); i++) {
        if (x[i] != y[i]) {
            return x[i] < y[i] ? -1 : 1;
        }
    }
    return strcmp(a->name, b->name);
}

static int filename_rules_equal(const filename_trans_t *left, const filename_trans_t *right) {
    size_t n = 0, m = 0;
    for (const filename_trans_t *r = left; r; r = r->next) {
        if (!r->name) {
            return 0;
        }
        n++;
    }
    for (const filename_trans_t *r = right; r; r = r->next) {
        if (!r->name) {
            return 0;
        }
        m++;
    }
    if (n != m) {
        return 0;
    }
    if (!n) {
        return 1;
    }
    const filename_trans_t **a = calloc(n, sizeof(*a));
    const filename_trans_t **b = calloc(n, sizeof(*b));
    if (!a || !b) {
        free(a); free(b); return 0;
    }
    size_t i = 0;
    for (const filename_trans_t *r = left; r; r = r->next) {
        a[i++] = r;
    }
    i = 0;
    for (const filename_trans_t *r = right; r; r = r->next) {
        b[i++] = r;
    }
    qsort(a, n, sizeof(*a), filename_rule_order);
    qsort(b, n, sizeof(*b), filename_rule_order);
    int equal = 1;
    for (i = 0; equal && i < n; i++) {
        equal = filename_rule_order(&a[i], &b[i]) == 0;
    }
    free(a);
    free(b);
    return equal;
}

static const char *policy_mismatch(const unsigned char *bytes, size_t length,
                                   const struct trusted_file *candidate,
                                   size_t *remaining_first) {
    if (remaining_first) {
        *remaining_first = SIZE_MAX;
    }
    policydb_t active, expected;
    if (!policy_image_read(&active, bytes, length)) {
        return "active-image";
    }
    if (!policy_image_read(&expected, candidate->data, candidate->length)) {
        policydb_destroy(&active);
        return "candidate-image";
    }
    const char *difference;
    if (active.policy_type != POLICY_KERN || expected.policy_type != POLICY_KERN ||
        active.policyvers != expected.policyvers) {
        difference = "policy-format";
    } else if (active.te_avtab.nel != expected.te_avtab.nel) {
        difference = "access-vector-count";
    } else if (!policy_rules_equal(&active.te_avtab, &expected.te_avtab)) {
        difference = "access-vector-data";
    } else {
        policydb_t aligned = active;
        if (!filename_rules_equal(active.filename_trans, expected.filename_trans)) {
            policydb_destroy(&expected);
            policydb_destroy(&active);
            return "filename-transition-data";
        }
        aligned.filename_trans = expected.filename_trans;
        aligned.te_avtab = expected.te_avtab;
        void *left = NULL, *right = NULL;
        size_t n = 0, m = 0;
        if (policydb_to_image(NULL, &aligned, &left, &n) != 0 ||
            policydb_to_image(NULL, &expected, &right, &m) != 0) {
            difference = "policy-serialization";
        } else if (n != m || memcmp(left, right, n) != 0) {
            difference = "remaining-policy";
            if (remaining_first) {
                const unsigned char *a = left, *b = right;
                size_t common = n < m ? n : m;
                size_t offset = 0;
                while (offset < common && a[offset] == b[offset]) {
                    offset++;
                }
                *remaining_first = offset;
            }
        } else {
            difference = "encoding-only";
        }
        free(right);
        free(left);
    }
    policydb_destroy(&expected);
    policydb_destroy(&active);
    return difference;
}

static int loaded_product_policy_matches(const char *path,
                                         const struct trusted_file *candidate,
                                         const struct policy_operation_paths *paths) {
    size_t length = 0;
    unsigned char *bytes = read_file(path, &length);
    if (!bytes) {
        klog("product policy check: read active policy failed: %s", strerror(errno));
        return 0;
    }
    if (!length) {
        klog("product policy check: active policy is empty");
        free(bytes);
        return 0;
    }
    if (length != candidate->length || memcmp(bytes, candidate->data, length) != 0) {
        size_t shared = length < candidate->length ? length : candidate->length;
        size_t first = shared;
        size_t differences = 0;
        for (size_t offset = 0; offset < shared; offset++) {
            if (bytes[offset] != candidate->data[offset]) {
                if (first == shared) {
                    first = offset;
                }
                differences++;
            }
        }
        const char *previous_difference = "unavailable";
        struct trusted_file previous = {0};
        if (paths && trusted_file_matches(paths->rollback, MAX_POLICY_BYTES, 0, 0, 0600,
                                          paths->rollback_sha256, 0, NULL, &previous)) {
            previous_difference = length == previous.length &&
                                  memcmp(bytes, previous.data, length) == 0
                                      ? "exact" : policy_mismatch(bytes, length, &previous, NULL);
            free_trusted_file(&previous);
        }
        size_t remaining_first;
        const char *difference = policy_mismatch(bytes, length, candidate, &remaining_first);
        if (strcmp(difference, "encoding-only") != 0) {
            if (remaining_first != SIZE_MAX) {
                klog("product policy check: active policy differs "
                     "(active=%zu candidate=%zu first=%zu changed=%zu difference=%s "
                     "remaining_first=%zu previous=%s)",
                     length, candidate->length, first, differences, difference,
                     remaining_first, previous_difference);
            } else {
                klog("product policy check: active policy differs "
                     "(active=%zu candidate=%zu first=%zu changed=%zu difference=%s previous=%s)",
                     length, candidate->length, first, differences, difference, previous_difference);
            }
            free(bytes);
            return 0;
        }
    }
    struct sepol_policy_file *file = NULL;
    policydb_t *policy = calloc(1, sizeof(*policy));
    int valid = policy && policydb_init(policy) == 0 &&
                sepol_policy_file_create(&file) == 0;
    if (valid) {
        sepol_policy_file_set_mem(file, (char *)bytes, length);
        valid = policydb_read(policy, (struct policy_file *)file, 0) == 0 &&
                voboost_policy_applied(policy) && policy_context_valid(policy);
    }
    if (!valid) {
        klog("product policy check: active policy structure or required rules invalid");
    }
    if (file) {
        sepol_policy_file_free(file);
    }
    if (policy) {
        policydb_destroy(policy);
        free(policy);
    }
    free(bytes);
    return valid;
}

static int check_product_policy(void) {
    struct policy_operation_paths paths;
    if (resolve_product_operation(POLICY_OPERATION_PRODUCT_CHECK, &paths) != 0) {
        klog("product policy check: operation/WAL authority rejected");
        return 8;
    }
    if (!validate_product_policy_inputs(&paths)) {
        klog("product policy check: pristine or rollback policy identity rejected");
        return 8;
    }
    struct trusted_file executable;
    struct trusted_file candidate;
    if (!product_executable_matches(SELINUX_EXECUTABLE, 0700,
                                    paths.executable_sha256, 1, &executable) ||
        !trusted_file_matches(paths.output, MAX_POLICY_BYTES, 0, 0, 0600,
                              paths.output_sha256, 0, NULL, &candidate)) {
        free_trusted_file(&executable);
        return 8;
    }
    int matches = loaded_product_policy_matches(POLICY_FILE, &candidate, &paths);
    free_trusted_file(&candidate);
    free_trusted_file(&executable);
    return matches ? 0 : 6;
}

static int patch_active_operation(void) {
    struct policy_operation_paths paths;
    if (resolve_policy_operation_at(OPERATION_FILE, ROOT_DIRECTORY,
                                    STOCK_POLICY_FILE, 0, 0, &paths) != 0) {
        klog("active operation or correlated journal has unsafe authority");
        return 8;
    }
    int result = policy_file_operation(0, paths.input, paths.output);
    return result == 0 ? policy_file_operation(1, paths.output, paths.output)
                       : result;
}

#ifndef VOBOOST_SELINUX_LIBRARY
int main(int argc, char **argv) {
    if (install_alarm_watchdog(VOBOOST_WATCHDOG_SECONDS) != 0) {
        klog("failed to install alarm watchdog");
        return 7;
    }

    if (!verify_own_signature(argv[0])) {
        klog("signature verification failed");
        return 1;
    }

    if (argc == 1) {
        return patch_active_operation();
    }
    if (argc == 2 && !strcmp(argv[1], "--relabel")) {
        struct root_authority root_authority;
        if (open_root_authority_at(ROOT_ZONE_DIRECTORY, 0, 0, &root_authority) != 0) {
            return 8;
        }
        int result = root_authority_current(&root_authority) &&
                     relabel_zone_fd(root_authority.fd, ROOT_ZONE_DIRECTORY) == 0 &&
                     root_authority_current(&root_authority) &&
                     publish_relabel_ready() == 0
                         ? 0
                         : 8;
        close_root_authority(&root_authority);
        return result;
    }
    if (argc == 2 && !strcmp(argv[1], "--install-product-candidate")) {
        return install_product_candidate();
    }
    if (argc == 2 && !strcmp(argv[1], "--prepare-product-policy")) {
        return prepare_product_policy();
    }
    if (argc == 2 && !strcmp(argv[1], "--check-product-policy")) {
        return check_product_policy();
    }

    return 2;
}
#endif
