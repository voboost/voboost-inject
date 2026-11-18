#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static int fail_allocation, clobber_close_errno;
static void *fixture_malloc(size_t size) {
    if (fail_allocation) {
        errno = ENOMEM;
        return NULL;
    }
    return malloc(size);
}
static int fixture_close(int fd) {
    int result = close(fd);
    if (clobber_close_errno) {
        errno = EACCES;
    }
    return result;
}
#define malloc fixture_malloc
#define close fixture_close
#define EMBEDDED_PUBKEY_HEX                                                   \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0
#define main voboost_selinux_embedded_main
#include "../../selinux/voboost-selinux.c"
#undef main
#undef malloc
#undef close

#include <assert.h>

static void write_exact(const char *path, const char *bytes) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(fchown(fd, getuid(), getgid()) == 0);
    size_t length = strlen(bytes);
    assert(write(fd, bytes, length) == (ssize_t)length);
    assert(close(fd) == 0);
}

static void write_product_operation(const char *path, const char *transaction,
                                    const char *journal_sha256,
                                    const char *journal_claim,
                                    const char *phase) {
    char operation[2048];
    int length = snprintf(
        operation, sizeof(operation),
        "{\"schemaVersion\":1,\"operation\":\"update\","
        "\"transactionId\":\"%s\",\"journal\":\"%s\","
        "\"phase\":\"%s\",\"outcome\":\"running\","
        "\"rebootCount\":%u,\"bootId\":\"%s\","
        "\"statusSequence\":31,\"journalSha256\":\"%s\","
        "\"error\":null,\"installedApk\":null}\n",
        transaction, journal_claim, phase,
        !strcmp(phase, "update-product-system-post-reboot") ? 1u : 0u,
        !strcmp(phase, "update-product-system-post-reboot")
            ? "00000000-0000-0000-0000-000000000002"
            : "00000000-0000-0000-0000-000000000001",
        journal_sha256);
    assert(length > 0 && length < (int)sizeof(operation));
    write_exact(path, operation);
}

static int product_journal(char *out, size_t capacity, const char *transaction,
                           const char *manifest_sha256, const char *phase,
                           int extra_field, int selinux_changed) {
    const char hash_b[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char hash_c[] =
        "cccccccccccccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccc";
    const char hash_d[] =
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd";
    return snprintf(
        out, capacity,
        "{\"schemaVersion\":1,\"operation\":\"product-update-proposal\","
        "\"origin\":{\"kind\":\"ota\"},"
        "\"candidate\":{\"transactionId\":\"%s\","
        "\"releaseIdentity\":\"1.0.0-beta2\",\"manifestSha256\":\"%s\","
        "\"artifacts\":[{\"file\":\"%s\",\"size\":%u,"
        "\"sha256\":\"%s\"},{\"file\":\"restore.json\",\"size\":1,"
        "\"sha256\":\"%s\"},{\"file\":\"restore.json.sig\",\"size\":1,"
        "\"sha256\":\"%s\"}]},\"activationClasses\":%s,"
        "\"generationOnly\":false,\"apkOnly\":false,"
        "\"nativePlan\":false,\"systemPlan\":true,\"phase\":\"%s\","
        "\"previousGeneration\":null,\"nextGeneration\":null,"
        "\"failure\":null,\"preRebootBootId\":"
        "\"00000000-0000-0000-0000-000000000001\","
        "\"postRebootBootId\":%s,\"rollbackBootId\":null,"
        "\"systemInitPreviousSha256\":null,"
        "\"systemInitCandidateSha256\":null,\"policyPreviousSha256\":\"%s\","
        "\"policyBaselineSha256\":\"%s\",\"policyCandidateSha256\":%s%s}\n",
        transaction, manifest_sha256,
        selinux_changed ? "voboost-selinux" : "voboost.rc",
        selinux_changed ? 80u : 1u, hash_b, hash_c, hash_d,
        selinux_changed ? "[\"native-runtime\",\"restore-authority\"]"
                        : "[\"restore-authority\",\"init\"]",
        phase,
        !strcmp(phase, "system-post-reboot")
            ? "\"00000000-0000-0000-0000-000000000002\""
            : "null",
        hash_b, hash_c,
        !strcmp(phase, "system-post-reboot")
            ? "\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\""
            : "null",
        extra_field ? ",\"extra\":true" : "");
}

static void write_reconstructed_manifest(const char *path,
                                         const char *selinux_role,
                                         const char *selinux_sha256,
                                         char out_sha256[65]) {
    char manifest[2048];
    int length = snprintf(
        manifest, sizeof(manifest),
        "{\"schemaVersion\":1,\"releaseIdentity\":\"1.0.0-beta2\","
        "\"compatibility\":{\"installerProtocol\":1,\"operationProtocol\":1,"
        "\"appDaemonProtocol\":1,\"agentCatalogSchema\":2,"
        "\"agentEntryAbi\":1,\"implantAbi\":1},\"artifacts\":[{"
        "\"role\":\"%s\",\"file\":\"voboost-selinux\",\"size\":80,"
        "\"sha256\":\"%s\",\"activation\":\"native-runtime\"}]}\n",
        selinux_role, selinux_sha256);
    assert(length > 0 && length < (int)sizeof(manifest));
    write_exact(path, manifest);
    sha256_hex((const unsigned char *)manifest, (size_t)length, out_sha256);
}

int main(void) {
    const char *origins[] = {
        "{\"kind\":\"ota\"}",
        "{\"kind\":\"offline-explicit\",\"expected_active_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        "{\"kind\":\"unknown\"}", "{\"kind\":\"ota\",\"extra\":true}",
        "{\"kind\":\"offline-explicit\"}",
        "{\"kind\":\"offline-explicit\",\"expected_active_manifest_sha256\":\"BAD\"}",
        "null"
    };
    for (size_t i = 0; i < sizeof(origins) / sizeof(origins[0]); i++) {
        yyjson_doc *doc = yyjson_read(origins[i], strlen(origins[i]), 0);
        assert(doc);
        assert(product_origin_valid(yyjson_doc_get_root(doc)) == (i < 2));
        yyjson_doc_free(doc);
    }
    char backup_path[PATH_MAX];
    const char baseline_sha[] =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";
    assert(policy_backup_path(baseline_sha, backup_path) == 0);
    assert(strcmp(backup_path,
                  "/data/voboost/uninstall/baselines/"
                  "ba7816bf8f01cfea414140de5dae2223"
                  "b00361a396177a9cb410ff61f20015ad/"
                  "precompiled_sepolicy.orig") == 0);
    assert(policy_backup_path(
               "BA7816BF8F01CFEA414140DE5DAE2223"
               "B00361A396177A9CB410FF61F20015AD",
               backup_path) != 0);

    char digest[65];
    sha256_hex((const unsigned char *)"", 0, digest);
    assert(strcmp(digest,
                  "e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855") == 0);
    sha256_hex((const unsigned char *)"abc", 3, digest);
    assert(strcmp(digest,
                  "ba7816bf8f01cfea414140de5dae2223"
                  "b00361a396177a9cb410ff61f20015ad") == 0);

    const char canonical[] =
        "{\"schemaVersion\":1,\"path\":\"/vendor/etc/selinux/"
        "precompiled_sepolicy\",\"size\":3,\"sha256\":\""
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad\",\"uid\":0,\"gid\":0,"
        "\"mode\":\"0644\",\"context\":\"u:object_r:vendor_file:s0\"}\n";
    struct backup_metadata metadata;
    assert(parse_backup_metadata((const unsigned char *)canonical,
                                 strlen(canonical), &metadata) == 0);
    assert(metadata.size == 3 && metadata.mode == 0644);

    const char schema2[] =
        "{\"context\":\"u:object_r:vendor_file:s0\",\"gid\":0,\"mode\":\"0644\","
        "\"path\":\"/vendor/etc/selinux/precompiled_sepolicy\",\"schemaVersion\":2,"
        "\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"sidecars\":[{\"gid\":0,\"mode\":420,\"path\":\"/vendor/etc/selinux/"
        "precompiled_sepolicy.plat_and_mapping.sha256\",\"present\":false,\"pristine\":[],"
        "\"selinuxContext\":[117,58,111,98,106,101,99,116,95,114,58,120],"
        "\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\","
        "\"uid\":0}],\"size\":3,\"uid\":0}";
    assert(parse_backup_metadata((const unsigned char *)schema2,
                                 strlen(schema2), &metadata) == 0);
    assert(metadata.size == 3 && metadata.mode == 0644);
    char invalid2[sizeof(schema2)];
    memcpy(invalid2, schema2, sizeof(schema2));
    char *bad_sidecar = strstr(invalid2, "plat_and_mapping");
    assert(bad_sidecar);
    *bad_sidecar = 'x';
    assert(parse_backup_metadata((const unsigned char *)invalid2,
                                 strlen(invalid2), &metadata) != 0);

    memcpy(invalid2, schema2, sizeof(schema2));
    char *bad_label = strstr(invalid2, "[117,58,111");
    assert(bad_label);
    memcpy(bad_label, "[999,58,111", 11);
    assert(parse_backup_metadata((const unsigned char *)invalid2,
                                 strlen(invalid2), &metadata) != 0);

    char malformed[sizeof(canonical) + 32];
    snprintf(malformed, sizeof(malformed), "%s{}\n", canonical);
    assert(parse_backup_metadata((const unsigned char *)malformed,
                                 strlen(malformed), &metadata) != 0);
    memcpy(malformed, canonical, sizeof(canonical));
    char *size = strstr(malformed, "\"size\":3");
    assert(size);
    memcpy(size, "\"size\":03", 10);
    assert(parse_backup_metadata((const unsigned char *)malformed,
                                 strlen(malformed), &metadata) != 0);

    char directory[] = "build/host/voboost-policy-backup.XXXXXX";
    assert(mkdtemp(directory));
    char regular[512], linked[512], symbolic[512], published[512];
    snprintf(regular, sizeof(regular), "%s/regular", directory);
    snprintf(linked, sizeof(linked), "%s/linked", directory);
    snprintf(symbolic, sizeof(symbolic), "%s/symbolic", directory);
    snprintf(published, sizeof(published), "%s/published", directory);
    write_exact(regular, "abc");

    struct trusted_file trusted;
    assert(read_trusted_file(regular, 3, 0, &trusted) == 0);
    assert(trusted.length == 3 && memcmp(trusted.data, "abc", 3) == 0);
    free_trusted_file(&trusted);
    assert(symlink(regular, symbolic) == 0);
    assert(read_trusted_file(symbolic, 3, 0, &trusted) != 0);
    size_t bounded_length = 0;
    unsigned char *bounded = read_file_bounded(regular, 3, &bounded_length);
    assert(bounded && bounded_length == 3 && memcmp(bounded, "abc", 3) == 0);
    free(bounded);
    errno = 0;
    assert(read_file_bounded(regular, 0, &bounded_length) == NULL && errno == EINVAL);
    errno = 0;
    assert(read_file_bounded(regular, 2, &bounded_length) == NULL && errno == EFBIG);
    fail_allocation = 1;
    clobber_close_errno = 1;
    assert(read_file_bounded(regular, 3, &bounded_length) == NULL && errno == ENOMEM);
    fail_allocation = 0;
    clobber_close_errno = 0;
    assert(read_file_bounded(regular, 2, &bounded_length) == NULL);
    assert(read_file_bounded(symbolic, 3, &bounded_length) == NULL);
    assert(inspect_trusted_target(symbolic, 3) != 0);
    assert(link(regular, linked) == 0);
    assert(read_trusted_file(regular, 3, 0, &trusted) != 0);
    assert(inspect_trusted_target(regular, 3) != 0);
    assert(unlink(linked) == 0);
    assert(read_trusted_file(regular, 2, 0, &trusted) != 0);
    assert(trusted_file_matches(regular, 3, getuid(), getgid(), 0600,
                                baseline_sha, 0, NULL, &trusted));
    free_trusted_file(&trusted);
    assert(!trusted_file_matches(
               regular, 3, getuid(), getgid(), 0600,
               "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
               "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
               0, NULL, &trusted));

    assert(atomic_write(published, (const unsigned char *)"policy", 6,
                        getuid(), getgid(), 0600, NULL, 0) == 0);
    assert(read_trusted_file(published, 6, 0, &trusted) == 0);
    assert(trusted.length == 6 && (trusted.st.st_mode & 07777) == 0600);
    free_trusted_file(&trusted);
    assert(atomic_write(published, (const unsigned char *)"changed", 7,
                        getuid(), getgid(), 0600, NULL, 0) != 0);
    assert(read_trusted_file(published, 6, 0, &trusted) == 0);
    assert(memcmp(trusted.data, "policy", 6) == 0);
    free_trusted_file(&trusted);

    const char transaction[] =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    char recovery[512], transaction_directory[640], journal_path[768],
         operation_path[512], stock_policy[512];
    snprintf(recovery, sizeof(recovery), "%s/recovery", directory);
    snprintf(transaction_directory, sizeof(transaction_directory), "%s/%s",
             recovery, transaction);
    snprintf(journal_path, sizeof(journal_path), "%s/install-journal.json",
             transaction_directory);
    snprintf(operation_path, sizeof(operation_path), "%s/operation.json",
             directory);
    snprintf(stock_policy, sizeof(stock_policy), "%s/stock-policy", directory);
    assert(mkdir(recovery, 0700) == 0);
    assert(mkdir(transaction_directory, 0700) == 0);
    char journal[8192];
    snprintf(journal, sizeof(journal),
             "{\"schemaVersion\":1,\"transactionId\":\"%s\","
             "\"descriptorSha256\":\"%s\",\"phase\":"
             "\"install-policy-apply\",\"bootIds\":[]}\n",
             transaction, baseline_sha);
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    char operation[2048];
    snprintf(operation, sizeof(operation),
             "{\"schemaVersion\":1,\"operation\":\"install\","
             "\"transactionId\":\"%s\",\"journal\":"
             "\"recovery/%s/install-journal.json\",\"phase\":"
             "\"install-policy-apply\",\"outcome\":\"running\","
             "\"rebootCount\":0,\"bootId\":"
             "\"00000000-0000-0000-0000-000000000001\","
             "\"statusSequence\":3,\"journalSha256\":\"%s\","
             "\"error\":null,\"installedApk\":null}\n",
             transaction, transaction, digest);
    write_exact(operation_path, operation);
    struct policy_operation_paths paths;
    assert(resolve_policy_operation_at(operation_path, directory, stock_policy,
                                       getuid(), getgid(), &paths) == 0);
    char expected_output[768];
    /* Legacy install patches the LOADED kernel policy so firmware CIL-level
    * patches (voyemu free-09 canbus/oem service types) survive the voboost
    * install; see resolve_policy_operation_mode_at in voboost-selinux.c. */
    assert(strcmp(paths.input, "/sys/fs/selinux/policy") == 0);
    snprintf(expected_output, sizeof(expected_output),
             "%s/precompiled_sepolicy.patched", transaction_directory);
    assert(strcmp(paths.output, expected_output) == 0);
    assert(unlink(operation_path) == 0);
    char *phase = strstr(operation, "install-policy-apply");
    assert(phase);
    memcpy(phase, "install-policy-wrong", strlen("install-policy-wrong"));
    write_exact(operation_path, operation);
    assert(resolve_policy_operation_at(operation_path, directory, stock_policy,
                                       getuid(), getgid(), &paths) != 0);

    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    char install_directory[512], install_transaction[640], complete[768];
    char manifest_path[896], signature_path[896], manifest_digest[65];
    snprintf(install_directory, sizeof(install_directory), "%s/install",
             directory);
    snprintf(install_transaction, sizeof(install_transaction), "%s/%s",
             install_directory, transaction);
    snprintf(complete, sizeof(complete), "%s/complete-candidate",
             install_transaction);
    snprintf(manifest_path, sizeof(manifest_path), "%s/voboost.json", complete);
    snprintf(signature_path, sizeof(signature_path), "%s/voboost.json.sig",
             complete);
    assert(mkdir(install_directory, 0700) == 0);
    assert(mkdir(install_transaction, 0700) == 0);
    assert(mkdir(complete, 0700) == 0);
    write_reconstructed_manifest(
        manifest_path, "selinux",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        manifest_digest);
    write_exact(signature_path,
                "ssssssssssssssssssssssssssssssss"
                "ssssssssssssssssssssssssssssssss");
    snprintf(journal_path, sizeof(journal_path), "%s/product-proposal.json",
             transaction_directory);
    int product_length = product_journal(journal, sizeof(journal), transaction,
                                         manifest_digest, "system-prepared", 0,
                                         1);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    char product_relative[768];
    char expected_input[768];
    snprintf(product_relative, sizeof(product_relative),
             "recovery/%s/product-proposal.json", transaction);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) == 0);
    snprintf(expected_input, sizeof(expected_input),
             "%s/product-previous/policy-baseline", transaction_directory);
    snprintf(expected_output, sizeof(expected_output),
             "%s/product-previous/policy-candidate", transaction_directory);
    char expected_rollback[768], expected_executable[768], expected_ack[768];
    snprintf(expected_rollback, sizeof(expected_rollback),
             "%s/product-previous/policy-previous", transaction_directory);
    snprintf(expected_executable, sizeof(expected_executable),
             "%s/install/%s/complete-candidate/voboost-selinux", directory,
             transaction);
    snprintf(expected_ack, sizeof(expected_ack),
             "%s/policy-prepare-ack.json", transaction_directory);
    assert(strcmp(paths.input, expected_input) == 0);
    assert(strcmp(paths.output, expected_output) == 0);
    assert(strcmp(paths.rollback, expected_rollback) == 0);
    assert(strcmp(paths.candidate_executable, expected_executable) == 0);
    assert(strcmp(paths.prepare_ack, expected_ack) == 0);
    assert(strcmp(paths.input_sha256,
                  "cccccccccccccccccccccccccccccccc"
                  "cccccccccccccccccccccccccccccccc") == 0);
    assert(strcmp(paths.rollback_sha256,
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
    assert(paths.output_sha256[0] == '\0');
    char ack[512];
    int ack_length = format_prepare_ack(
        &paths,
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd",
        ack);
    assert(ack_length > 0);
    char expected_ack_bytes[512];
    int expected_ack_length = snprintf(
        expected_ack_bytes, sizeof(expected_ack_bytes),
        "{\"schemaVersion\":1,\"transactionId\":\"%s\","
        "\"bootId\":\"00000000-0000-0000-0000-000000000001\","
        "\"policyBaselineSha256\":"
        "\"cccccccccccccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccc\","
        "\"policyCandidateSha256\":"
        "\"dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd\"}\n",
        transaction);
    assert(ack_length == expected_ack_length);
    assert(memcmp(ack, expected_ack_bytes, (size_t)ack_length) == 0);

    /* An init-only system update derives the unchanged transformer identity
     * from the exact reconstructed manifest digest, not changed artifacts. */
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-prepared", 0, 0);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) == 0);
    assert(!paths.selinux_changed);
    assert(strcmp(paths.executable_sha256,
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);

    /* Wrong reconstructed-manifest digest and hostile SELinux role fail
     * closed even though operation.json and product WAL are correlated. */
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(
        journal, sizeof(journal), transaction,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "system-prepared", 0, 0);
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);

    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    assert(unlink(manifest_path) == 0);
    write_reconstructed_manifest(
        manifest_path, "daemon",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        manifest_digest);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-prepared", 0, 0);
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);

    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    assert(unlink(manifest_path) == 0);
    write_reconstructed_manifest(
        manifest_path, "selinux",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        manifest_digest);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-prepared", 0, 1);
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");

    /* Wrong operation phase, journal path and journal hash are rejected. */
    assert(unlink(operation_path) == 0);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-post-reboot");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);
    assert(unlink(operation_path) == 0);
    write_product_operation(operation_path, transaction, digest,
                            "recovery/alias/product-proposal.json",
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);
    assert(unlink(operation_path) == 0);
    write_product_operation(
        operation_path, transaction,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        product_relative, "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);

    /* Wrong WAL phase, transaction binding and unknown fields are rejected. */
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-post-reboot", 0,
                                     1);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    char wrong_transaction[65];
    memset(wrong_transaction, 'f', 64);
    wrong_transaction[64] = '\0';
    product_length = product_journal(journal, sizeof(journal), wrong_transaction,
                                     manifest_digest, "system-prepared", 0, 1);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-prepared", 1, 1);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);

    /* A forward-policy helper cannot consume a journal that claims a rollback
     * boot epoch. */
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-prepared", 0, 1);
    const char rollback_field[] = "\"rollbackBootId\":null";
    char *rollback = strstr(journal, rollback_field);
    assert(rollback);
    char rollback_journal[8192];
    int rollback_length = snprintf(
        rollback_journal, sizeof(rollback_journal), "%.*s\"rollbackBootId\":"
        "\"00000000-0000-0000-0000-000000000003\"%s",
        (int)(rollback - journal), journal, rollback + strlen(rollback_field));
    assert(rollback_length > 0 && rollback_length < (int)sizeof(rollback_journal));
    write_exact(journal_path, rollback_journal);
    sha256_hex((const unsigned char *)rollback_journal,
               strlen(rollback_journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-prepared");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_PREPARE, &paths) != 0);

    /* Loaded-policy mode admits only the post-reboot phase and distinct boot. */
    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    product_length = product_journal(journal, sizeof(journal), transaction,
                                     manifest_digest, "system-post-reboot", 0,
                                     1);
    assert(product_length > 0 && product_length < (int)sizeof(journal));
    write_exact(journal_path, journal);
    sha256_hex((const unsigned char *)journal, strlen(journal), digest);
    write_product_operation(operation_path, transaction, digest,
                            product_relative,
                            "update-product-system-post-reboot");
    assert(resolve_policy_operation_mode_at(
               operation_path, directory, stock_policy, getuid(), getgid(),
               POLICY_OPERATION_PRODUCT_CHECK, &paths) == 0);
    assert(strcmp(paths.output_sha256,
                  "dddddddddddddddddddddddddddddddd"
                  "dddddddddddddddddddddddddddddddd") == 0);

    /* The fixed loaded-policy verifier checks both exact bytes and semantics
     * against the real f0506h 6.0.3 policy when the fixture is present. */
    const char real_policy[] =
        "test/selinux/fixtures/f0506h-free-09-chinese-6.0.3-policy-v30.bin";
    char real_candidate[512];
    snprintf(real_candidate, sizeof(real_candidate), "%s/real-policy-candidate",
             directory);
    if (access(real_policy, R_OK) == 0) {
        assert(policy_file_operation(0, real_policy, real_candidate) == 0);
        struct trusted_file generated;
        assert(read_trusted_file(real_candidate, MAX_POLICY_BYTES, 0,
                                 &generated) == 0);
        struct trusted_file original;
        assert(read_trusted_file(real_policy, MAX_POLICY_BYTES, 0, &original) == 0);
        assert(product_policies_preserve_types(&original, &generated));
        struct trusted_file malformed = {0};
        malformed.data = (unsigned char *)"invalid";
        malformed.length = 7;
        assert(!product_policies_preserve_types(&malformed, &generated));
        assert(!product_policies_preserve_types(&original, &malformed));
        assert(loaded_product_policy_matches(real_candidate, &generated, NULL));
        policydb_t parsed;
        assert(policy_image_read(&parsed, generated.data, generated.length));
        void *serialized = NULL;
        size_t serialized_length = 0;
        assert(policydb_to_image(NULL, &parsed, &serialized, &serialized_length) == 0);
        assert(serialized_length == generated.length);
        assert(memcmp(serialized, generated.data, serialized_length) != 0);
        assert(strcmp(policy_mismatch(serialized, serialized_length, &generated, NULL),
                      "encoding-only") == 0);
        int active_fd = open(real_candidate, O_WRONLY | O_TRUNC);
        assert(active_fd >= 0);
        assert(write(active_fd, serialized, serialized_length) == (ssize_t)serialized_length);
        assert(close(active_fd) == 0);
        assert(loaded_product_policy_matches(real_candidate, &generated, NULL));
        free(serialized);
        serialized = NULL;
        filename_trans_t *reverse = NULL, *item = parsed.filename_trans;
        assert(item && item->next);
        while (item) {
            filename_trans_t *next = item->next;
            item->next = reverse;
            reverse = item;
            item = next;
        }
        parsed.filename_trans = reverse;
        assert(policydb_to_image(NULL, &parsed, &serialized, &serialized_length) == 0);
        assert(strcmp(policy_mismatch(serialized, serialized_length, &generated, NULL), "encoding-only") == 0);
        active_fd = open(real_candidate, O_WRONLY | O_TRUNC);
        assert(active_fd >= 0);
        assert(write(active_fd, serialized, serialized_length) == (ssize_t)serialized_length);
        assert(close(active_fd) == 0);
        assert(loaded_product_policy_matches(real_candidate, &generated, NULL));
        free(serialized);
        serialized = NULL;
        parsed.filename_trans->otype ^= 1;
        assert(policydb_to_image(NULL, &parsed, &serialized, &serialized_length) == 0);
        assert(strcmp(policy_mismatch(serialized, serialized_length, &generated, NULL), "filename-transition-data") == 0);
        free(serialized);
        serialized = NULL;
        parsed.filename_trans->otype ^= 1;
        avtab_ptr_t changed_rule = NULL;
        for (uint32_t slot = 0; slot < parsed.te_avtab.nslot && !changed_rule; slot++) {
            for (avtab_ptr_t rule = parsed.te_avtab.htable[slot]; rule; rule = rule->next) {
                if (!(rule->key.specified & AVTAB_OP)) {
                    changed_rule = rule; break;
                }
            }
        }
        assert(changed_rule);
        changed_rule->datum.data ^= 1;
        assert(policydb_to_image(NULL, &parsed, &serialized, &serialized_length) == 0);
        assert(strcmp(policy_mismatch(serialized, serialized_length, &generated, NULL), "access-vector-data") == 0);
        free(serialized);
        serialized = NULL;
        changed_rule->datum.data ^= 1;
        parsed.handle_unknown ^= 2;
        assert(policydb_to_image(NULL, &parsed, &serialized, &serialized_length) == 0);
        size_t remaining_first = SIZE_MAX;
        assert(strcmp(policy_mismatch(serialized, serialized_length, &generated, &remaining_first),
                      "remaining-policy") == 0);
        assert(remaining_first < serialized_length);
        free(serialized);
        policydb_destroy(&parsed);
        generated.data[0] ^= 1;
        assert(!loaded_product_policy_matches(real_candidate, &generated, NULL));
        assert(!loaded_product_policy_matches(real_policy, &original, NULL));
        free_trusted_file(&original);
        free_trusted_file(&generated);
        assert(unlink(real_candidate) == 0);
    }

    assert(unlink(operation_path) == 0);
    assert(unlink(journal_path) == 0);
    assert(unlink(signature_path) == 0);
    assert(unlink(manifest_path) == 0);
    assert(rmdir(complete) == 0);
    assert(rmdir(install_transaction) == 0);
    assert(rmdir(install_directory) == 0);
    assert(rmdir(transaction_directory) == 0);
    assert(rmdir(recovery) == 0);
    assert(unlink(symbolic) == 0);
    assert(unlink(regular) == 0);
    assert(unlink(published) == 0);
    assert(rmdir(directory) == 0);
    puts("test_policy_backup: OK");
    return 0;
}
