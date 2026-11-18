#define VOBOOST_RELABEL_TEST 1
#define EMBEDDED_PUBKEY_HEX                                                   \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0
#define main voboost_selinux_embedded_main
#include "../../selinux/voboost-selinux.c"
#undef main

#include <assert.h>

static dev_t victim_device;
static ino_t victim_inode;
static const char *victim_path;
static int victim_was_labeled;
static int labeled_count;
static int swap_enabled;
static const char *after_escape_path;
static const char *tree_escape_path;
static ino_t after_inode;
static ino_t tree_leaf_inode;
static ino_t staging_leaf_inode;
static ino_t trusted_leaf_inode;
static ino_t committed_body_inode;
static ino_t nested_body_inode;
static ino_t selinux_inode;
static int after_was_labeled;
static int tree_leaf_was_labeled;
static int staging_leaf_was_labeled;
static int trusted_leaf_was_labeled;
static char committed_body_label[256];
static char nested_body_label[256];
static char selinux_label[256];
static ino_t repair_inode;
static ino_t repair_descriptor_inode;
static ino_t repair_signature_inode;
static char repair_label[256];
static char repair_descriptor_label[256];
static char repair_signature_label[256];
static const char *current_test_label = "u:object_r:system_data_file:s0";
static char applied_test_label[256];

int voboost_relabel_test_get_label(int fd, char *label, size_t capacity) {
    struct stat st;
    assert(fstat(fd, &st) == 0);
    if (!current_test_label) {
        return -1;
    }
    size_t length = strlen(current_test_label);
    if (length >= capacity) {
        return -1;
    }
    memcpy(label, current_test_label, length + 1);
    return 0;
}

int voboost_relabel_test_set_label(int fd, const char *label) {
    struct stat st;
    assert(label && fstat(fd, &st) == 0);
    if (st.st_dev == victim_device && st.st_ino == victim_inode) {
        victim_was_labeled = 1;
    }
    after_was_labeled |= st.st_ino == after_inode;
    tree_leaf_was_labeled |= st.st_ino == tree_leaf_inode;
    staging_leaf_was_labeled |= st.st_ino == staging_leaf_inode;
    trusted_leaf_was_labeled |= st.st_ino == trusted_leaf_inode;
    if (st.st_ino == committed_body_inode) {
        assert(strlen(label) < sizeof(committed_body_label));
        strcpy(committed_body_label, label);
    }
    if (st.st_ino == nested_body_inode) {
        assert(strlen(label) < sizeof(nested_body_label));
        strcpy(nested_body_label, label);
    }
    if (st.st_ino == selinux_inode) {
        assert(strlen(label) < sizeof(selinux_label));
        strcpy(selinux_label, label);
    }
    if (st.st_ino == repair_inode) strcpy(repair_label, label);
    if (st.st_ino == repair_descriptor_inode)
        strcpy(repair_descriptor_label, label);
    if (st.st_ino == repair_signature_inode)
        strcpy(repair_signature_label, label);
    assert(strlen(label) < sizeof(applied_test_label));
    strcpy(applied_test_label, label);
    labeled_count++;
    return 0;
}

static void test_incoming_context_preserves_authority(void) {
    char path[] = "./voboost-relabel-context.XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    char label[256];

    current_test_label = "u:object_r:untrusted_app_data_file:s0:c55,c256";
    assert(incoming_label_fd(fd, label, sizeof(label)) == 0);
    assert(!strcmp(label,
                   "u:object_r:voboost_incoming_file:s0:c55,c256"));

    current_test_label = "staff_u:object_r:untrusted_app_data_file:s0-s0:c0.c1023";
    assert(incoming_label_fd(fd, label, sizeof(label)) == 0);
    assert(!strcmp(label,
                   "staff_u:object_r:voboost_incoming_file:s0-s0:c0.c1023"));

    const char *invalid[] = {
        "u:object_r:untrusted_app_data_file",
        "u:object_r:untrusted_app_data_file:",
        "u:object_r:untrusted_app_data_file:s0:",
        "u:object_r:untrusted_app_data_file:s0:c",
        "u:object_r:untrusted_app_data_file:s0:c1,",
        "u:object_r:untrusted_app_data_file:s0-c1",
        "u:object-r:untrusted_app_data_file:s0",
        "u:object_r:untrusted app data:s0",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        current_test_label = invalid[i];
        assert(incoming_label_fd(fd, label, sizeof(label)) != 0);
    }
    current_test_label = NULL;
    assert(incoming_label_fd(fd, label, sizeof(label)) != 0);
    current_test_label = "u:object_r:untrusted_app_data_file:s0:c55,c256";
    assert(incoming_label_fd(fd, label, 16) != 0);
    current_test_label = "u:object_r:system_data_file:s0";
    assert(close(fd) == 0);
    assert(unlink(path) == 0);
}

void voboost_relabel_test_after_open(int directory_fd, const char *name) {
    if (!strcmp(name, "after")) {
        assert(renameat(directory_fd, name, AT_FDCWD, after_escape_path) == 0);
    }
}

void voboost_relabel_test_before_recurse(int directory_fd, const char *name) {
    if (!strcmp(name, "tree")) {
        assert(renameat(directory_fd, name, AT_FDCWD, tree_escape_path) == 0);
    }
}

void voboost_relabel_test_before_open(int directory_fd, const char *name) {
    if (!swap_enabled || strcmp(name, "swap") != 0) {
        return;
    }
    swap_enabled = 0;
    assert(renameat(directory_fd, "swap", directory_fd, "swap.original") == 0);
    assert(symlinkat(victim_path, directory_fd, "swap") == 0);
}

static void write_file(const char *path, const char *bytes) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(write(fd, bytes, strlen(bytes)) == (ssize_t)strlen(bytes));
    assert(close(fd) == 0);
}

static void set_test_xattr(const char *path, const char *value) {
#ifdef __APPLE__
    assert(setxattr(path, "user.voboost_relabel", value, strlen(value), 0, 0) == 0);
#else
    assert(setxattr(path, "user.voboost_relabel", value, strlen(value), 0) == 0);
#endif
}

static ino_t inode_of(const char *path) {
    struct stat st;
    assert(stat(path, &st) == 0);
    return st.st_ino;
}

static void assert_test_xattr(const char *path, const char *expected) {
    char value[32] = {0};
#ifdef __APPLE__
    ssize_t length = getxattr(path, "user.voboost_relabel", value,
                              sizeof(value), 0, 0);
#else
    ssize_t length = getxattr(path, "user.voboost_relabel", value, sizeof(value));
#endif
    assert(length == (ssize_t)strlen(expected));
    assert(memcmp(value, expected, (size_t)length) == 0);
}

static void test_staging_shape_contract(void) {
    struct stat st = {0};
    st.st_mode = S_IFDIR | 0700;
    st.st_nlink = 2;
    st.st_uid = 10000;
    st.st_gid = 10000;
    assert(exact_staging_directory(&st));
    st.st_uid = 0;
    st.st_gid = 0;
    assert(!exact_staging_directory(&st));
    st.st_uid = 9999;
    st.st_gid = 9999;
    assert(!exact_staging_directory(&st));
    st.st_uid = 10000;
    st.st_gid = 10001;
    assert(!exact_staging_directory(&st));
    st.st_gid = 10000;
    st.st_mode = S_IFDIR | 0777;
    assert(!exact_staging_directory(&st));
    st.st_mode = S_IFDIR | 0700;
    st.st_nlink = 1;
    assert(!exact_staging_directory(&st));
}

static void test_isolated_symlink_fails(void) {
    char parent[] = "./voboost-relabel-link.XXXXXX";
    assert(mkdtemp(parent));
    char root[PATH_MAX], victim[PATH_MAX], planted[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/root", parent) > 0);
    assert(snprintf(victim, sizeof(victim), "%s/victim", parent) > 0);
    assert(snprintf(planted, sizeof(planted), "%s/planted", root) > 0);
    assert(mkdir(root, 0700) == 0);
    write_file(victim, "victim");
    assert(symlink(victim, planted) == 0);
    struct stat before;
    assert(stat(victim, &before) == 0);
    victim_device = before.st_dev;
    victim_inode = before.st_ino;
    victim_was_labeled = 0;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(root_fd >= 0);
    assert(relabel_zone_fd(root_fd, "/data/voboost") != 0);
    assert(close(root_fd) == 0);
    assert(!victim_was_labeled);
    assert(unlink(planted) == 0);
    assert(unlink(victim) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(parent) == 0);
}

static void test_committed_uninstall_tree_remains_protected_after_relabel(void) {
    char parent[] = "./voboost-relabel-body.XXXXXX";
    assert(mkdtemp(parent));
    char root[PATH_MAX], uninstall[PATH_MAX], system[PATH_MAX];
    char body[PATH_MAX], nested[PATH_MAX], nested_body[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/root", parent) > 0);
    assert(snprintf(uninstall, sizeof(uninstall), "%s/uninstall", root) > 0);
    assert(snprintf(system, sizeof(system), "%s/system", uninstall) > 0);
    assert(snprintf(body, sizeof(body), "%s/voboost.rc", system) > 0);
    assert(snprintf(nested, sizeof(nested), "%s/nested", root) > 0);
    assert(snprintf(nested_body, sizeof(nested_body), "%s/voboost.rc", nested) > 0);
    assert(mkdir(root, 0700) == 0);
    assert(mkdir(uninstall, 0700) == 0);
    assert(mkdir(system, 0700) == 0);
    assert(mkdir(nested, 0700) == 0);
    write_file(body, "committed-body");
    write_file(nested_body, "not-authority");
    committed_body_inode = inode_of(body);
    nested_body_inode = inode_of(nested_body);

    for (int pass = 0; pass < 2; pass++) {
        committed_body_label[0] = '\0';
        nested_body_label[0] = '\0';
        int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(root_fd >= 0);
        assert(relabel_zone_fd(root_fd, "/data/voboost") == 0);
        assert(close(root_fd) == 0);
        assert(!strcmp(committed_body_label,
                       "u:object_r:voboost_uninstall_data_file:s0"));
        assert(!strcmp(nested_body_label,
                       "u:object_r:voboost_data_file:s0"));
    }

    committed_body_inode = 0;
    nested_body_inode = 0;
    assert(unlink(nested_body) == 0);
    assert(unlink(body) == 0);
    assert(rmdir(system) == 0);
    assert(rmdir(uninstall) == 0);
    assert(rmdir(nested) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(parent) == 0);
}

static void test_selinux_program_receives_its_exec_type(void) {
    char parent[] = "./voboost-relabel-selinux.XXXXXX";
    assert(mkdtemp(parent));
    char root[PATH_MAX], selinux[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/root", parent) > 0);
    assert(snprintf(selinux, sizeof(selinux), "%s/voboost-selinux", root) > 0);
    assert(mkdir(root, 0700) == 0);
    write_file(selinux, "signed-selinux");
    selinux_inode = inode_of(selinux);
    selinux_label[0] = '\0';
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(root_fd >= 0);
    assert(relabel_zone_fd(root_fd, "/data/voboost") == 0);
    assert(close(root_fd) == 0);
    assert(!strcmp(selinux_label, "u:object_r:voboost_selinux_exec:s0"));
    selinux_inode = 0;
    assert(unlink(selinux) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(parent) == 0);
}

static void test_stock_recovery_files_escape_root_catch_all(void) {
    char parent[] = "./voboost-relabel-repair.XXXXXX";
    assert(mkdtemp(parent));
    char root[PATH_MAX], repair[PATH_MAX], descriptor[PATH_MAX], signature[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/root", parent) > 0);
    assert(snprintf(repair, sizeof(repair), "%s/voboost-restore", root) > 0);
    assert(snprintf(descriptor, sizeof(descriptor), "%s/restore.json", root) > 0);
    assert(snprintf(signature, sizeof(signature), "%s/restore.json.sig", root) > 0);
    assert(mkdir(root, 0700) == 0);
    write_file(repair, "repair");
    write_file(descriptor, "descriptor");
    write_file(signature, "signature");
    repair_inode = inode_of(repair);
    repair_descriptor_inode = inode_of(descriptor);
    repair_signature_inode = inode_of(signature);
    repair_label[0] = repair_descriptor_label[0] = repair_signature_label[0] = '\0';
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(root_fd >= 0);
    assert(relabel_zone_fd(root_fd, "/data/voboost") == 0);
    assert(close(root_fd) == 0);
    assert(!strcmp(repair_label, VOBOOST_CONTEXT_RESTORE));
    assert(!strcmp(repair_descriptor_label, VOBOOST_CONTEXT_ROOT));
    assert(!strcmp(repair_signature_label, VOBOOST_CONTEXT_ROOT));
    assert(strcmp(repair_label, VOBOOST_CONTEXT_ROOT));
    assert(unlink(signature) == 0);
    assert(unlink(descriptor) == 0);
    assert(unlink(repair) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(parent) == 0);
}

static void test_restore_prepare_labels(void) {
    char parent[] = "./voboost-relabel-prepare.XXXXXX";
    assert(mkdtemp(parent));
    char stage[PATH_MAX], journal[PATH_MAX], temporary[PATH_MAX], foreign[PATH_MAX];
    assert(snprintf(stage, sizeof(stage), "%s/restore-prepare", parent) > 0);
    assert(snprintf(journal, sizeof(journal), "%s/restore-journal.json", stage) > 0);
    assert(snprintf(temporary, sizeof(temporary), "%s/.restore-journal.json.tmp", stage) > 0);
    assert(snprintf(foreign, sizeof(foreign), "%s/unknown.json", stage) > 0);
    assert(mkdir(stage, 0700) == 0);
    write_file(journal, "journal");
    write_file(temporary, "temporary");
    repair_inode = inode_of(stage);
    repair_descriptor_inode = inode_of(journal);
    repair_signature_inode = inode_of(temporary);
    for (int pass = 0; pass < 2; pass++) {
        int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") == 0);
        assert(close(fd) == 0);
        assert(!strcmp(repair_label, VOBOOST_CONTEXT_RECOVERY_TREE));
        assert(!strcmp(repair_descriptor_label, VOBOOST_CONTEXT_RECOVERY_TREE));
        assert(!strcmp(repair_signature_label, VOBOOST_CONTEXT_RECOVERY_TREE));
    }
    write_file(foreign, "foreign");
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
    assert(close(fd) == 0);
    assert(unlink(foreign) == 0);
    assert(chmod(stage, 0755) == 0);
    repair_label[0] = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
    assert(close(fd) == 0 && !repair_label[0]);
    assert(chmod(stage, 0700) == 0);
    assert(chmod(journal, 0644) == 0);
    repair_descriptor_label[0] = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
    assert(close(fd) == 0 && !repair_descriptor_label[0]);
    assert(unlink(journal) == 0);
    assert(symlink(".restore-journal.json.tmp", journal) == 0);
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
    assert(close(fd) == 0);
    assert(unlink(journal) == 0);
    assert(unlink(temporary) == 0);
    assert(rmdir(stage) == 0);
    assert(rmdir(parent) == 0);
    repair_inode = repair_descriptor_inode = repair_signature_inode = 0;
}

static void test_private_run_reply_labels(void) {
    char parent[] = "./voboost-relabel-replies.XXXXXX";
    assert(mkdtemp(parent));
    char paths[3][PATH_MAX];
    const char *names[] = {"restore-reply.json", "desktop-uninstall-result.json", "unknown.json"};
    for (int i = 0; i < 3; i++) {
        assert(snprintf(paths[i], sizeof(paths[i]), "%s/%s", parent, names[i]) > 0);
        write_file(paths[i], "reply");
    }
    repair_inode = inode_of(paths[0]);
    repair_descriptor_inode = inode_of(paths[1]);
    repair_signature_inode = inode_of(paths[2]);
    for (int pass = 0; pass < 2; pass++) {
        int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") == 0);
        assert(close(fd) == 0);
        assert(!strcmp(repair_label, VOBOOST_CONTEXT_RESTORE_REPLY));
        assert(!strcmp(repair_descriptor_label, VOBOOST_CONTEXT_UNINSTALL_REPLY));
        assert(!strcmp(repair_signature_label, VOBOOST_CONTEXT_ROOT));
    }
    for (int i = 0; i < 2; i++) {
        assert(chmod(paths[i], 0644) == 0);
        repair_label[0] = repair_descriptor_label[0] = '\0';
        int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
        assert(close(fd) == 0);
        assert(i == 0 ? !repair_label[0] : !repair_descriptor_label[0]);
        assert(chmod(paths[i], 0600) == 0);
        assert(unlink(paths[i]) == 0);
        assert(symlink("unknown.json", paths[i]) == 0);
        fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && relabel_zone_fd(fd, "/data/voboost/run") != 0);
        assert(close(fd) == 0);
        assert(unlink(paths[i]) == 0);
        write_file(paths[i], "reply");
        if (i == 0) repair_inode = inode_of(paths[i]);
        else repair_descriptor_inode = inode_of(paths[i]);
    }
    for (int i = 0; i < 3; i++) assert(unlink(paths[i]) == 0);
    assert(rmdir(parent) == 0);
    repair_inode = repair_descriptor_inode = repair_signature_inode = 0;
}

static void test_resource_journal_labels(void) {
    char root[] = "./voboost-journal-label.XXXXXX";
    assert(mkdtemp(root));
    char journal[PATH_MAX], slot[PATH_MAX], member[PATH_MAX];
    snprintf(journal,sizeof(journal),"%s/i18n-resource-transaction",root);
    snprintf(slot,sizeof(slot),"%s/authority-test",journal);
    snprintf(member,sizeof(member),"%s/.product-manifest.json.tmp",slot);
    assert(mkdir(journal,0700)==0 && mkdir(slot,0700)==0);
    write_file(member,"signed-authority");
    repair_inode=inode_of(journal); repair_descriptor_inode=inode_of(slot);
    repair_signature_inode=inode_of(member);
    for(int pass=0;pass<2;pass++) {
        int fd=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        assert(fd>=0 && relabel_zone_fd(fd,"/data/voboost")==0); close(fd);
        assert(!strcmp(repair_label,VOBOOST_CONTEXT_RESOURCE_JOURNAL_TREE));
        assert(!strcmp(repair_descriptor_label,VOBOOST_CONTEXT_RESOURCE_JOURNAL_TREE));
        assert(!strcmp(repair_signature_label,VOBOOST_CONTEXT_RESOURCE_JOURNAL_TREE));
    }
    assert(unlink(member)==0 && rmdir(slot)==0 && rmdir(journal)==0 && rmdir(root)==0);
}

int main(void) {
    test_resource_journal_labels();
    test_restore_prepare_labels();
    test_private_run_reply_labels();
    test_incoming_context_preserves_authority();
    test_staging_shape_contract();
    test_isolated_symlink_fails();
    test_committed_uninstall_tree_remains_protected_after_relabel();
    test_selinux_program_receives_its_exec_type();
    test_stock_recovery_files_escape_root_catch_all();
    char parent[] = "./voboost-relabel.XXXXXX";
    assert(mkdtemp(parent));
    char root[PATH_MAX], victim[PATH_MAX], ordinary[PATH_MAX], after[PATH_MAX];
    char planted[PATH_MAX], hardlink[PATH_MAX], swap[PATH_MAX], original[PATH_MAX];
    char escaped_after[PATH_MAX], tree[PATH_MAX], tree_leaf[PATH_MAX];
    char escaped_tree[PATH_MAX], escaped_tree_leaf[PATH_MAX];
    char generations[PATH_MAX], staging[PATH_MAX], staging_leaf[PATH_MAX];
    char trusted[PATH_MAX], trusted_leaf[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/root", parent) > 0);
    assert(snprintf(victim, sizeof(victim), "%s/victim", parent) > 0);
    assert(snprintf(ordinary, sizeof(ordinary), "%s/ordinary", root) > 0);
    assert(snprintf(planted, sizeof(planted), "%s/planted", root) > 0);
    assert(snprintf(hardlink, sizeof(hardlink), "%s/hardlink", root) > 0);
    assert(snprintf(swap, sizeof(swap), "%s/swap", root) > 0);
    assert(snprintf(original, sizeof(original), "%s/swap.original", root) > 0);
    assert(snprintf(after, sizeof(after), "%s/after", root) > 0);
    assert(snprintf(escaped_after, sizeof(escaped_after), "%s/escaped-after", parent) > 0);
    assert(snprintf(tree, sizeof(tree), "%s/tree", root) > 0);
    assert(snprintf(tree_leaf, sizeof(tree_leaf), "%s/leaf", tree) > 0);
    assert(snprintf(escaped_tree, sizeof(escaped_tree), "%s/escaped-tree", parent) > 0);
    assert(snprintf(escaped_tree_leaf, sizeof(escaped_tree_leaf), "%s/leaf", escaped_tree) > 0);
    assert(snprintf(generations, sizeof(generations), "%s/generations", root) > 0);
    assert(snprintf(staging, sizeof(staging), "%s/next", generations) > 0);
    assert(snprintf(staging_leaf, sizeof(staging_leaf), "%s/untrusted", staging) > 0);
    assert(snprintf(trusted, sizeof(trusted), "%s/trusted", root) > 0);
    assert(snprintf(trusted_leaf, sizeof(trusted_leaf), "%s/leaf", trusted) > 0);
    assert(mkdir(root, 0700) == 0);
    write_file(victim, "victim");
    write_file(ordinary, "ordinary");
    write_file(swap, "swap");
    write_file(after, "after");
    assert(mkdir(tree, 0700) == 0);
    write_file(tree_leaf, "tree-leaf");
    assert(mkdir(generations, 0700) == 0);
    assert(mkdir(staging, 0777) == 0);
    assert(chmod(staging, 0777) == 0);
    write_file(staging_leaf, "staging-leaf");
    assert(mkdir(trusted, 0700) == 0);
    write_file(trusted_leaf, "trusted-leaf");
    assert(symlink(victim, planted) == 0);
    assert(link(victim, hardlink) == 0);
    set_test_xattr(victim, "untouched");
    struct stat before;
    assert(stat(victim, &before) == 0);
    victim_device = before.st_dev;
    victim_inode = before.st_ino;
    victim_path = victim;
    after_escape_path = escaped_after;
    tree_escape_path = escaped_tree;
    after_inode = inode_of(after);
    tree_leaf_inode = inode_of(tree_leaf);
    staging_leaf_inode = inode_of(staging_leaf);
    trusted_leaf_inode = inode_of(trusted_leaf);
    swap_enabled = 1;

    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(root_fd >= 0);
    assert(relabel_zone_fd(root_fd, "/data/voboost") != 0);
    assert(close(root_fd) == 0);
    assert(labeled_count >= 2); /* root plus the ordinary stable inode */
    assert(!victim_was_labeled);
    struct stat victim_after;
    assert(stat(victim, &victim_after) == 0);
    assert(victim_after.st_dev == before.st_dev && victim_after.st_ino == before.st_ino);
    assert_test_xattr(victim, "untouched");
    assert(!after_was_labeled);
    assert(!tree_leaf_was_labeled);
    assert(!staging_leaf_was_labeled);
    assert(trusted_leaf_was_labeled);

    assert(unlink(planted) == 0);
    assert(unlink(hardlink) == 0);
    assert(unlink(swap) == 0);
    assert(unlink(original) == 0);
    assert(unlink(ordinary) == 0);
    assert(unlink(escaped_after) == 0);
    assert(unlink(escaped_tree_leaf) == 0);
    assert(rmdir(escaped_tree) == 0);
    assert(unlink(staging_leaf) == 0);
    assert(rmdir(staging) == 0);
    assert(rmdir(generations) == 0);
    assert(unlink(trusted_leaf) == 0);
    assert(rmdir(trusted) == 0);
    assert(unlink(victim) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(parent) == 0);
    puts("test_relabel_walk: OK");
    return 0;
}
