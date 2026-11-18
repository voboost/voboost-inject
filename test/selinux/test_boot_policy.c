#define EMBEDDED_PUBKEY_HEX \
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
#define main voboost_selinux_embedded_main
#include "../../selinux/voboost-selinux.c"
#undef main
#include <assert.h>

static void fixture_file(const char *root, const char *relative,
                         const char *bytes, mode_t mode) {
    char path[PATH_MAX];
    assert(boot_path(path, root, relative) == 0);
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            assert(mkdir(path, 0700) == 0 || errno == EEXIST);
            *p = '/';
        }
    }
    assert(unlink(path) == 0 || errno == ENOENT);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    assert(fd >= 0);
    assert(write(fd, bytes, strlen(bytes)) == (ssize_t)strlen(bytes));
    assert(fchmod(fd, mode) == 0);
    close(fd);
}

static void compile_fixture(const char *root, unsigned api) {
    fixture_file(root, "/sys/fs/selinux/policyvers", "30\n", 0444);
    fixture_file(root, "/vendor/etc/selinux/plat_sepolicy_vers.txt", "28.0\n", 0644);
    fixture_file(root, "/system/etc/selinux/plat_sepolicy.cil", "platform\n", 0644);
    fixture_file(root, "/system/etc/selinux/mapping/28.0.cil", "mapping\n", 0644);
    fixture_file(root, "/vendor/etc/selinux/nonplat_sepolicy.cil", "vendor\n", 0644);
    fixture_file(root, "/odm/etc/selinux/odm_sepolicy.cil", "odm\n", 0644);
    if (api == 30) {
        fixture_file(root, "/system/etc/selinux/mapping/28.0.compat.cil", "compat\n", 0644);
        fixture_file(root, "/system_ext/etc/selinux/system_ext_sepolicy.cil", "system_ext\n", 0644);
        fixture_file(root, "/system_ext/etc/selinux/mapping/28.0.cil", "system_ext_mapping\n", 0644);
        fixture_file(root, "/product/etc/selinux/product_sepolicy.cil", "product\n", 0644);
        fixture_file(root, "/product/etc/selinux/mapping/28.0.cil", "product_mapping\n", 0644);
    }
    fixture_file(root, "/system/bin/secilc",
                 "#!/bin/sh\nset -eu\nsources=\noutput=\nwhile test $# -gt 0; do\n"
                 "case \"$1\" in\n-o) output=$2; shift 2;;\n"
                 "-M|-c|-f) shift 2;;\n-m|-G|-N) shift;;\n"
                 "/dev/fd/*|/proc/self/fd/*) sources=\"$sources $1\"; shift;;\n"
                 "*) exit 99;;\nesac\ndone\n"
                 "test -n \"$output\"\n: >\"$output\"\n"
                 "for source in $sources; do cat \"$source\" >>\"$output\"; done\n", 0755);
}

static size_t descriptor_count(void) {
#if defined(__APPLE__)
    DIR *directory = opendir("/dev/fd");
#else
    DIR *directory = opendir("/proc/self/fd");
#endif
    assert(directory);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    closedir(directory);
    return count;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *root = argv[1];
    assert(mkdir(root, 0700) == 0);
    uid_t uid = getuid();
    for (unsigned api = 28; api <= 30; api += 2) {
        char current[PATH_MAX];
        snprintf(current, sizeof(current), "%s/api%u", root, api);
        assert(mkdir(current, 0700) == 0);
        compile_fixture(current, api);
        size_t descriptors = descriptor_count();
        size_t length = 0;
        unsigned char *bytes = boot_compile_at(current, api, uid, &length);
        assert(bytes && length);
        const char *expected = api == 28 ? "platform\nmapping\nvendor\nodm\n" :
                               "platform\nmapping\ncompat\nsystem_ext\nsystem_ext_mapping\nproduct\nproduct_mapping\nvendor\nodm\n";
        assert(length == strlen(expected) && !memcmp(bytes, expected, length));
        free(bytes);
        char private_compiler[PATH_MAX];
        assert(boot_path(private_compiler, current, "/system/bin/secilc") == 0);
        assert(chmod(private_compiler, 0700) == 0);
        bytes = boot_compile_at(current, api, uid, &length);
        assert(bytes && length);
        free(bytes);
        fixture_file(current, "/vendor/etc/selinux/vendor_sepolicy.cil", "modern_vendor\n", 0644);
        fixture_file(current, "/vendor/etc/selinux/plat_pub_versioned.cil", "public_mapping\n", 0644);
        bytes = boot_compile_at(current, api, uid, &length);
        assert(bytes && memmem(bytes, length, "modern_vendor\n", 14) &&
               memmem(bytes, length, "public_mapping\n", 15));
        assert(!memmem(bytes, length, "\nvendor\n", 8));
        free(bytes);
        assert(!boot_compile_at(current, api, uid + 1, &length));
        if (api == 28) {
            fixture_file(current, "/sys/fs/selinux/policyvers", "31\n", 0444);
            assert(!boot_compile_at(current, api, uid, &length));
            fixture_file(current, "/sys/fs/selinux/policyvers", "30\n", 0444);
        }
        fixture_file(current, "/vendor/etc/selinux/plat_sepolicy_vers.txt", "../../escape\n", 0644);
        errno = EACCES;
        assert(!boot_compile_at(current, api, uid, &length));
        assert(errno == EINVAL);
        assert(descriptor_count() == descriptors);
        fixture_file(current, "/vendor/etc/selinux/plat_sepolicy_vers.txt", "28.0\n", 0644);
        fixture_file(current, "/system/bin/secilc", "#!/bin/sh\nexit 9\n", 0755);
        assert(!boot_compile_at(current, api, uid, &length));
        char path[PATH_MAX];
        assert(boot_path(path, current, "/system/etc/selinux/plat_sepolicy.cil") == 0);
        assert(unlink(path) == 0);
        assert(symlink("/etc/passwd", path) == 0);
        assert(!boot_compile_at(current, api, uid, &length));
    }
    char pre[PATH_MAX];
    snprintf(pre, sizeof(pre), "%s/precompiled", root);
    assert(mkdir(pre, 0700) == 0);
    fixture_file(pre, "/vendor/etc/selinux/precompiled_sepolicy", "vendor policy", 0644);
    fixture_file(pre, "/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256", "matching\n", 0644);
    fixture_file(pre, "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256", "matching\n", 0644);
    struct trusted_file file;
    assert(boot_precompiled(pre, 28, uid, &file) == 1);
    assert(file.length == strlen("vendor policy"));
    free_trusted_file(&file);
    size_t selected_length = 0;
    unsigned char *selected = boot_policy_at(pre, 28, uid, &selected_length);
    assert(selected && selected_length == strlen("vendor policy"));
    assert(memcmp(selected, "vendor policy", selected_length) == 0);
    free(selected);
    fixture_file(pre, "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256", "different\n", 0644);
    assert(boot_precompiled(pre, 28, uid, &file) == 0);
    fixture_file(pre, "/odm/etc/selinux/precompiled_sepolicy", "odm policy", 0644);
    assert(boot_precompiled(pre, 28, uid, &file) == 0);
    fixture_file(pre, "/odm/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256", "different\n", 0644);
    assert(boot_precompiled(pre, 28, uid, &file) == 1);
    assert(file.length == strlen("odm policy"));
    free_trusted_file(&file);
    fixture_file(pre, "/system/etc/selinux/plat_sepolicy_and_mapping.sha256", "plat\n", 0644);
    fixture_file(pre, "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256", "ext\n", 0644);
    fixture_file(pre, "/product/etc/selinux/product_sepolicy_and_mapping.sha256", "product\n", 0644);
    fixture_file(pre, "/odm/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256", "plat\n", 0644);
    fixture_file(pre, "/odm/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256", "ext\n", 0644);
    fixture_file(pre, "/odm/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256", "product\n", 0644);
    assert(boot_precompiled(pre, 30, uid, &file) == 1);
    free_trusted_file(&file);
    fixture_file(pre, "/product/etc/selinux/product_sepolicy_and_mapping.sha256", "other\n", 0644);
    assert(boot_precompiled(pre, 30, uid, &file) == 0);
    char unsafe[PATH_MAX];
    assert(boot_path(unsafe, pre, "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256") == 0);
    assert(unlink(unsafe) == 0 && symlink("/etc/passwd", unsafe) == 0);
    assert(boot_precompiled(pre, 30, uid, &file) == -1);

    struct boot_input frozen;
    assert(boot_snapshot(&frozen, (const unsigned char *)"frozen", 6) == 0);
    assert(boot_snapshot_unchanged(&frozen) == 0);
#if !defined(__APPLE__)
    assert(pwrite(frozen.fd, "changed", 7, 0) == -1 && errno == EPERM);
#else
    assert(pwrite(frozen.fd, "broken", 6, 0) == 6);
    assert(boot_snapshot_unchanged(&frozen) == -1);
    assert(pwrite(frozen.fd, "frozen", 6, 0) == 6);
#endif
    char observed[7] = {0};
    assert(read(frozen.fd, observed, 6) == 6 && !strcmp(observed, "frozen"));
    close(frozen.fd);
    char timeout_root[PATH_MAX];
    snprintf(timeout_root, sizeof(timeout_root), "%s/timeout", root);
    assert(mkdir(timeout_root, 0700) == 0);
    compile_fixture(timeout_root, 28);
    char script[PATH_MAX + 128];
    snprintf(script, sizeof(script), "#!/bin/sh\nprintf '%%s' \"$$\" > '%s/compiler.pid'\nexec /bin/sleep 60\n", timeout_root);
    fixture_file(timeout_root, "/system/bin/secilc", script, 0755);
    pid_t helper = fork();
    assert(helper >= 0);
    if (!helper) {
        assert(install_alarm_watchdog(1) == 0);
        size_t length = 0;
        unsigned char *bytes = boot_compile_at(timeout_root, 28, uid, &length);
        free(bytes);
        _exit(99);
    }
    int status;
    assert(waitpid(helper, &status, 0) == helper);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
    char pid_path[PATH_MAX];
    snprintf(pid_path, sizeof(pid_path), "%s/compiler.pid", timeout_root);
    FILE *pid_file = fopen(pid_path, "r");
    assert(pid_file);
    long compiler_pid = 0;
    assert(fscanf(pid_file, "%ld", &compiler_pid) == 1 && compiler_pid > 0);
    fclose(pid_file);
    for (int attempt = 0; attempt < 250 && kill((pid_t)compiler_pid, 0) == 0; attempt++) {
        usleep(20000);
    }
    assert(kill((pid_t)compiler_pid, 0) == -1 && errno == ESRCH);
    puts("boot policy source and immutable compiler fixtures: OK");
    return 0;
}
