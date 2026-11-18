/* Fixed stock boot-policy sources for Enforcing initial installation.
 * Included after the trusted-file helpers; no caller paths or compiler args
 * are exposed by the signed program. */
#ifndef VOBOOST_BOOT_POLICY_H
#define VOBOOST_BOOT_POLICY_H

#define BOOT_MAX_CIL ((size_t)16u * 1024u * 1024u)
#define BOOT_MAX_INPUTS 10

struct boot_input {
    int fd;
    char argument[48];
    size_t length;
    char sha256[65];
    struct stat stamp;
};

static int boot_path(char out[PATH_MAX], const char *root, const char *path) {
    int length = snprintf(out, PATH_MAX, "%s%s", root, path);
    return length > 0 && length < PATH_MAX ? 0 : -1;
}

static int boot_stock_file(const char *path, size_t maximum, uid_t uid,
                           struct trusted_file *out) {
    if (read_trusted_file(path, maximum, 0, out) != 0) {
        if (!errno) {
            errno = EINVAL;
        }
        return -1;
    }
    mode_t mode = out->st.st_mode & 07777;
    if (out->st.st_uid != uid || (mode != 0644 && mode != 0444)) {
        free_trusted_file(out);
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int boot_exists(const char *root, const char *relative) {
    char path[PATH_MAX];
    struct stat stamp;
    if (boot_path(path, root, relative) != 0) {
        return -1;
    }
    if (lstat(path, &stamp) == 0) {
        return S_ISREG(stamp.st_mode) ? 1 : -1;
    }
    return errno == ENOENT ? 0 : -1;
}

static int boot_first_line(const char *root, const char *relative, uid_t uid,
                           char *out, size_t capacity) {
    char path[PATH_MAX];
    struct trusted_file file;
    if (boot_path(path, root, relative) != 0 ||
        boot_stock_file(path, 4096, uid, &file) != 0) {
        return -1;
    }
    size_t length = 0;
    while (length < file.length && file.data[length] != '\n') {
        length++;
    }
    int valid = length > 0 && length < capacity &&
                !memchr(file.data, '\0', length);
    if (valid) {
        memcpy(out, file.data, length);
        out[length] = '\0';
    }
    free_trusted_file(&file);
    if (!valid) {
        errno = EINVAL;
    }
    return valid ? 0 : -1;
}

static int boot_hash_pair(const char *root, const char *actual,
                          const char *precompiled, const char *suffix,
                          uid_t uid) {
    char claimed_path[PATH_MAX];
    char actual_hash[256], claimed_hash[256];
    int length = snprintf(claimed_path, sizeof(claimed_path), "%s%s",
                          precompiled, suffix);
    if (length <= 0 || length >= (int)sizeof(claimed_path)) {
        return -1;
    }
    if (boot_first_line(root, actual, uid, actual_hash, sizeof(actual_hash)) != 0 ||
        boot_first_line(root, claimed_path, uid, claimed_hash, sizeof(claimed_hash)) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    return strcmp(actual_hash, claimed_hash) == 0;
}

static int boot_precompiled(const char *root, unsigned api, uid_t uid,
                            struct trusted_file *out) {
    const char *selected = "/odm/etc/selinux/precompiled_sepolicy";
    int present = boot_exists(root, selected);
    if (present < 0) {
        return -1;
    }
    if (!present) {
        selected = "/vendor/etc/selinux/precompiled_sepolicy";
        present = boot_exists(root, selected);
        if (present < 0) {
            return -1;
        }
        if (!present) {
            return 0;
        }
    }
    const char *actual = api == 28
                             ? "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256"
                             : "/system/etc/selinux/plat_sepolicy_and_mapping.sha256";
    const char *suffix = api == 28 ? ".plat_and_mapping.sha256"
                                   : ".plat_sepolicy_and_mapping.sha256";
    int pair = boot_hash_pair(root, actual, selected, suffix, uid);
    if (pair != 1) {
        return pair;
    }
    if (api == 30) {
        pair = boot_hash_pair(root, "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
                              selected, ".system_ext_sepolicy_and_mapping.sha256", uid);
        if (pair != 1) {
            return pair;
        }
        pair = boot_hash_pair(root, "/product/etc/selinux/product_sepolicy_and_mapping.sha256",
                              selected, ".product_sepolicy_and_mapping.sha256", uid);
        if (pair != 1) {
            return pair;
        }
    }
    char path[PATH_MAX];
    if (boot_path(path, root, selected) != 0 ||
        boot_stock_file(path, MAX_POLICY_BYTES, uid, out) != 0) {
        return -1;
    }
    return 1;
}

static int boot_anonymous(void) {
#if defined(__APPLE__)
    FILE *file = tmpfile();
    if (!file) {
        return -1;
    }
    int fd = fcntl(fileno(file), F_DUPFD_CLOEXEC, 3);
    fclose(file);
#else
    int fd = (int)syscall(VOBOOST_SYS_memfd_create, "voboost-policy-source", 3);
#endif
    if (fd >= 0 && fchmod(fd, 0600) != 0) {
        int failure = errno;
        close(fd);
        fd = -1;
        errno = failure;
    }
#ifdef __ANDROID__
    /* The bounded OEM su policy may deny su_tmpfs creation/setattr while
     * permitting its root-owned system_data_file staging. No named file is
     * retained, and inputs are re-hashed after the trusted compiler exits. */
    if (fd < 0 && (errno == EACCES || errno == EPERM || errno == ENOSYS)) {
        char temporary[] = "/data/voboost/.policy-source.XXXXXX";
        fd = mkstemp(temporary);
        if (fd >= 0) {
            if (unlink(temporary) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
                int failure = errno;
                close(fd);
                unlink(temporary);
                fd = -1;
                errno = failure;
            }
        }
    }
#endif
    if (fd < 0) {
        klog("cannot allocate private policy snapshot: %s", strerror(errno));
    }
    return fd;
}

static int boot_seal(int fd) {
#if defined(__APPLE__)
    (void)fd;
    return 0;
#else
    int result = fcntl(fd, F_ADD_SEALS,
                       F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
#ifdef __ANDROID__
    if (result != 0 && errno == EINVAL) {
        struct stat owned;
        return fstat(fd, &owned) == 0 && S_ISREG(owned.st_mode) &&
               owned.st_nlink == 0 && owned.st_uid == 0 &&
               (owned.st_mode & 07777) == 0600 ? 0 : -1;
    }
#endif
    return result;
#endif
}

static int boot_snapshot(struct boot_input *input, const unsigned char *bytes,
                         size_t length) {
    input->length = length;
    sha256_hex(bytes, length, input->sha256);
    input->fd = boot_anonymous();
    if (input->fd < 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(input->fd, bytes + offset, length - offset);
        if (written <= 0) {
            close(input->fd);
            input->fd = -1;
            return -1;
        }
        offset += (size_t)written;
    }
    if (lseek(input->fd, 0, SEEK_SET) < 0 || boot_seal(input->fd) != 0) {
        klog("cannot retain private policy snapshot: %s", strerror(errno));
        close(input->fd);
        input->fd = -1;
        return -1;
    }
#if defined(__APPLE__)
    const char *prefix = "/dev/fd";
#else
    const char *prefix = "/proc/self/fd";
#endif
    snprintf(input->argument, sizeof(input->argument), "%s/%d", prefix, input->fd);
    if (fstat(input->fd, &input->stamp) != 0) {
        close(input->fd);
        input->fd = -1;
        return -1;
    }
    return 0;
}

static int boot_snapshot_unchanged(const struct boot_input *input) {
    struct stat before, after;
    if (fstat(input->fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 0 || before.st_size != (off_t)input->length ||
        !same_file_stamp(&before, &input->stamp)) {
        return -1;
    }
    struct sha256_ctx digest;
    sha256_init(&digest);
    unsigned char buffer[16384];
    size_t offset = 0;
    while (offset < input->length) {
        size_t remaining = input->length - offset;
        ssize_t amount = pread(input->fd, buffer,
                               remaining < sizeof(buffer) ? remaining : sizeof(buffer), (off_t)offset);
        if (amount <= 0) {
            return -1;
        }
        sha256_update(&digest, buffer, (size_t)amount);
        offset += (size_t)amount;
    }
    unsigned char hash[32];
    char hex[65];
    sha256_final(&digest, hash);
    for (size_t i = 0; i < sizeof(hash); i++) {
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    return !strcmp(hex, input->sha256) && fstat(input->fd, &after) == 0 &&
           same_file_stamp(&before, &after) ? 0 : -1;
}

static int boot_add_input(struct boot_input *inputs, size_t *count,
                          const char *root, const char *relative, uid_t uid,
                          int optional) {
    int present = boot_exists(root, relative);
    if (!present && optional) {
        return 0;
    }
    char path[PATH_MAX];
    struct trusted_file file;
    if (present != 1 || *count >= BOOT_MAX_INPUTS ||
        boot_path(path, root, relative) != 0 ||
        boot_stock_file(path, BOOT_MAX_CIL, uid, &file) != 0) {
        klog("unsafe or unavailable boot-policy input: %s", relative);
        return -1;
    }
    int result = boot_snapshot(&inputs[*count], file.data, file.length);
    free_trusted_file(&file);
    if (result == 0) {
        (*count)++;
    }
    return result;
}

static int boot_mapping(const char *root, uid_t uid, char version[16]) {
    if (boot_first_line(root, "/vendor/etc/selinux/plat_sepolicy_vers.txt",
                        uid, version, 16) != 0) {
        return -1;
    }
    /* Only the vendor mapping generations applicable to Android 9 and 11. */
    return !strcmp(version, "26.0") || !strcmp(version, "27.0") ||
           !strcmp(version, "28.0") || !strcmp(version, "29.0") ||
           !strcmp(version, "30.0") ? 0 : -1;
}

static int boot_inherit(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return flags < 0 ? -1 : fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
}

static int boot_run_compiler(int compiler, const char *compiler_path, struct boot_input *inputs,
                             size_t count, unsigned version, int output) {
    if (!count || count > BOOT_MAX_INPUTS) {
        errno = EINVAL;
        return -1;
    }
    char program[48], destination[48], version_text[16];
#if defined(__APPLE__)
    const char *prefix = "/dev/fd";
#else
    const char *prefix = "/proc/self/fd";
#endif
    snprintf(program, sizeof(program), "%s/%d", prefix, compiler);
#if defined(__APPLE__)
    /* Darwin cannot execute a script via /dev/fd; this is a host fixture
     * seam only. Production Android always executes the retained inode. */
    const char *executable = compiler_path;
#else
    (void)compiler_path;
    const char *executable = program;
#endif
    snprintf(destination, sizeof(destination), "%s/%d", prefix, output);
    snprintf(version_text, sizeof(version_text), "%u", version);
    char *arguments[32] = {"secilc", inputs[0].argument, "-m", "-M", "true",
                           "-G", "-N", "-c", version_text, "-o", destination,
                           "-f", "/dev/null"};
    size_t next = 13;
    for (size_t i = 1; i < count; i++) {
        arguments[next++] = inputs[i].argument;
    }
    arguments[next] = NULL;
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        sigprocmask(SIG_SETMASK, &previous, NULL);
        return -1;
    }
    if (!child) {
        sigprocmask(SIG_SETMASK, &previous, NULL);
        if (boot_inherit(compiler) != 0 || boot_inherit(output) != 0) {
            _exit(126);
        }
        for (size_t i = 0; i < count; i++) {
            if (boot_inherit(inputs[i].fd) != 0) {
                _exit(126);
            }
        }
        execv(executable, arguments);
        klog("stock compiler exec failed: %s", strerror(errno));
        _exit(126);
    }
    boot_compiler_pid = child;
    sigprocmask(SIG_SETMASK, &previous, NULL);
    int status = 0;
    for (;;) {
        if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            boot_compiler_pid = 0;
            return -1;
        }
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child || (observed < 0 && errno != EINTR)) {
            boot_compiler_pid = 0;
        }
        sigprocmask(SIG_SETMASK, &previous, NULL);
        if (observed == child) {
            break;
        }
        if (observed < 0 && errno != EINTR) {
            return -1;
        }
        usleep(20000);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        klog("stock policy compiler failed: status=%d", status);
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static unsigned char *boot_compile_at(const char *root, unsigned api,
                                      uid_t uid, size_t *length) {
    struct boot_input inputs[BOOT_MAX_INPUTS];
    memset(inputs, 0, sizeof(inputs));
    size_t count = 0;
    int compiler = -1, output = -1, failure = EINVAL;
    unsigned char *result = NULL;
    char version[16], path[PATH_MAX], relative[PATH_MAX];
    unsigned policy_version = POLICYDB_VERSION_MAX;
    if (api == 28) {
        size_t version_length = 0;
        if (boot_path(path, root, "/sys/fs/selinux/policyvers") != 0) {
            goto done;
        }
        unsigned char *raw_version = read_file_bounded(path, 16, &version_length);
        uint64_t parsed = 0;
        char text[17] = {0};
        if (!raw_version || !version_length || version_length > 16) {
            failure = !raw_version ? errno : EINVAL;
            klog("cannot read kernel policy version: %s", strerror(failure));
            free(raw_version);
            goto done;
        }
        memcpy(text, raw_version, version_length);
        free(raw_version);
        if (text[version_length - 1] == '\n') {
            text[version_length - 1] = '\0';
        }
        if (parse_decimal(text, POLICYDB_VERSION_MAX, &parsed) != 0 || parsed < 15) {
            klog("unsupported kernel policy version");
            goto done;
        }
        policy_version = (unsigned)parsed;
    }
    if (boot_mapping(root, uid, version) != 0) {
        klog("cannot read vendor mapping version: %s", strerror(errno));
        goto done;
    }
    if (boot_add_input(inputs, &count, root,
                       "/system/etc/selinux/plat_sepolicy.cil", uid, 0) != 0) {
        klog("cannot freeze platform CIL: %s", strerror(errno));
        goto done;
    }
    snprintf(relative, sizeof(relative), "/system/etc/selinux/mapping/%s.cil", version);
    if (boot_add_input(inputs, &count, root, relative, uid, 0) != 0) {
        goto done;
    }
    if (api == 30) {
        snprintf(relative, sizeof(relative), "/system/etc/selinux/mapping/%s.compat.cil", version);
        if (boot_add_input(inputs, &count, root, relative, uid, 1) != 0 ||
            boot_add_input(inputs, &count, root,
                           "/system_ext/etc/selinux/system_ext_sepolicy.cil", uid, 1) != 0) {
            goto done;
        }
        snprintf(relative, sizeof(relative), "/system_ext/etc/selinux/mapping/%s.cil", version);
        if (boot_add_input(inputs, &count, root, relative, uid, 1) != 0 ||
            boot_add_input(inputs, &count, root,
                           "/product/etc/selinux/product_sepolicy.cil", uid, 1) != 0) {
            goto done;
        }
        snprintf(relative, sizeof(relative), "/product/etc/selinux/mapping/%s.cil", version);
        if (boot_add_input(inputs, &count, root, relative, uid, 1) != 0) {
            goto done;
        }
    }
    int vendor = boot_exists(root, "/vendor/etc/selinux/vendor_sepolicy.cil");
    if (vendor < 0) {
        goto done;
    }
    if (vendor) {
        if (boot_add_input(inputs, &count, root,
                           "/vendor/etc/selinux/plat_pub_versioned.cil", uid, 0) != 0 ||
            boot_add_input(inputs, &count, root,
                           "/vendor/etc/selinux/vendor_sepolicy.cil", uid, 0) != 0) {
            goto done;
        }
    } else if (boot_add_input(inputs, &count, root,
                              "/vendor/etc/selinux/nonplat_sepolicy.cil", uid, 0) != 0) {
        goto done;
    }
    if (boot_add_input(inputs, &count, root,
                       "/odm/etc/selinux/odm_sepolicy.cil", uid, 1) != 0 ||
        boot_path(path, root, "/system/bin/secilc") != 0) {
        goto done;
    }
    compiler = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat before, after;
    if (compiler < 0 || fstat(compiler, &before) != 0) {
        failure = errno;
        goto done;
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != uid ||
        ((before.st_mode & 07777) != 0755 && (before.st_mode & 07777) != 0700) || before.st_nlink != 1 ||
        before.st_size <= 0 || before.st_size > (off_t)BOOT_MAX_CIL) {
        klog("unsafe or unavailable stock policy compiler");
        goto done;
    }
    output = boot_anonymous();
    if (output < 0 || boot_run_compiler(compiler, path, inputs, count,
                                        policy_version, output) != 0 ||
        fstat(compiler, &after) != 0 || !same_file_stamp(&before, &after) ||
        fstat(output, &after) != 0 || after.st_size <= 0 ||
        after.st_size > (off_t)MAX_POLICY_BYTES || boot_seal(output) != 0 ||
        lseek(output, 0, SEEK_SET) < 0) {
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        if (boot_snapshot_unchanged(&inputs[i]) != 0) {
            klog("compiler input snapshot changed");
            goto done;
        }
    }
    result = malloc((size_t)after.st_size);
    if (!result) {
        failure = ENOMEM;
        goto done;
    }
    size_t received = 0;
    while (received < (size_t)after.st_size) {
        ssize_t amount = read(output, result + received,
                              (size_t)after.st_size - received);
        if (amount <= 0) {
            failure = amount < 0 ? errno : EIO;
            free(result);
            result = NULL;
            goto done;
        }
        received += (size_t)amount;
    }
    *length = received;
done:
    for (size_t i = 0; i < count; i++) {
        close(inputs[i].fd);
    }
    if (compiler >= 0) {
        close(compiler);
    }
    if (output >= 0) {
        close(output);
    }
    if (!result) {
        errno = failure;
    }
    return result;
}

static unsigned char *boot_policy_at(const char *root, unsigned api,
                                     uid_t uid, size_t *length) {
    if (api != 28 && api != 30) {
        klog("unsupported stock policy platform");
        return NULL;
    }
    /* Android 11 can select a debug-ramdisk platform policy at first stage.
     * Do not infer that boot source from the ordinary system/vendor sidecars. */
    if (api == 30 && boot_exists(root, "/debug_ramdisk/userdebug_plat_sepolicy.cil") != 0) {
        klog("debug-ramdisk boot policy requires an explicit supported origin");
        return NULL;
    }
    struct trusted_file precompiled = {0};
    int selected = boot_precompiled(root, api, uid, &precompiled);
    if (selected < 0) {
        klog("unsafe stock precompiled policy");
        return NULL;
    }
    if (selected == 1 && precompiled.data && precompiled.length > 0) {
        *length = precompiled.length;
        return precompiled.data;
    }
    if (selected != 0) {
        free_trusted_file(&precompiled);
        errno = EINVAL;
        return NULL;
    }
    klog("reconstructing stock boot policy from fixed CIL snapshots");
    return boot_compile_at(root, api, uid, length);
}

#endif
