using Voboost;

const string FIX = "test/fixtures";

uint8[] read_bytes_or_fail(string path) {
    uint8[] data;
    try {
        FileUtils.get_data(path, out data);
    } catch (FileError e) {
        error("read %s: %s", path, e.message);
    }
    return data;
}

void copy_file(string src, string dst) {
    uint8[] data = read_bytes_or_fail(src);
    try {
        FileUtils.set_contents(dst, (string) data, data.length);
    } catch (FileError e) {
        error("write %s: %s", dst, e.message);
    }
}

// Best-effort recursive delete of a directory tree (host tests leave no temp
// behind on success).
void rm_rf(string path) {
    try {
        var en = File.new_for_path(path).enumerate_children(
            FileAttribute.STANDARD_NAME + "," +
            FileAttribute.STANDARD_TYPE,
            FileQueryInfoFlags.NOFOLLOW_SYMLINKS);
        FileInfo info;
        while ((info = en.next_file()) != null) {
            string child = Path.build_filename(path, info.get_name());
            if (info.get_file_type() == FileType.DIRECTORY) {
                rm_rf(child);
            } else {
                FileUtils.unlink(child);
            }
        }
    } catch (Error e) {
    }
    DirUtils.remove(path);
}

static int dirseq = 0;

string fresh_dir(string role) {
    string d = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-ota-%s-%d-%d".printf(role, (int) Posix.getpid(), dirseq++));
    DirUtils.create_with_parents(d, 0700);
    return d;
}

// A temp root_zone with a run/ subdir (the core-switch marker lives there).
string fresh_root() {
    string d = fresh_dir("root");
    DirUtils.create(Path.build_filename(d, "run"), 0700);
    return d;
}

string fresh_staging() {
    string d = fresh_dir("stage");
    DirUtils.create(Path.build_filename(d, "agents"), 0700);
    return d;
}

string? link_target(string path) {
    try {
        var info = File.new_for_path(path).query_info(
            "standard::symlink-target",
            FileQueryInfoFlags.NOFOLLOW_SYMLINKS);
        if (!info.has_attribute("standard::symlink-target")) {
            return null;
        }
        return info.get_symlink_target();
    } catch (Error e) {
        return null;
    }
}

bool manifest_verifies_at(string root, TrustStore trust) {
    var m = new Manifest();
    uint8[] j = read_bytes_or_fail(Path.build_filename(root, "manifest.json"));
    uint8[] s = read_bytes_or_fail(Path.build_filename(root, "manifest.sig"));
    return m.load_verified(j, s, trust);
}

ReleaseManifest load_release_manifest(Ota ota) {
    var rm = ota.verify_release_manifest(
        read_bytes_or_fail(FIX + "/release-manifest.json"),
        read_bytes_or_fail(FIX + "/release-manifest.json.sig"));
    assert(rm != null);
    return rm;
}

// --- release-manifest verify ----------------------------------------------

void test_release_manifest_verify() {
    var ota = new Ota("/data/voboost", new TrustStore());
    var rm = load_release_manifest(ota);
    assert(rm.version == "1.0.0-beta1");
    assert(rm.channel == "core");
    assert(rm.files.length == 1);
    assert(rm.files[0].path == "voboost-inject");
    assert(rm.files[0].channel == "core");
    assert(rm.files[0].size > 0);
}

void test_release_manifest_bad_sig() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest.json");
    uint8[] bad = read_bytes_or_fail(FIX + "/release-manifest-bad.sig");
    assert(ota.verify_release_manifest(rm, bad) == null);
}

void test_release_manifest_tampered() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest.json");
    uint8[] sig = read_bytes_or_fail(FIX + "/release-manifest.json.sig");
    rm[0] = (uint8) (rm[0] ^ 0x01);
    assert(ota.verify_release_manifest(rm, sig) == null);
}

// --- agent manifest-swap --------------------------------------------------

void test_agent_apply_installs_into_root() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    copy_file(FIX + "/manifest.json",
              Path.build_filename(staging, "manifest.json"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(staging, "manifest.sig"));
    copy_file(FIX + "/agents/wm-viewport.js",
              Path.build_filename(staging, "agents/wm-viewport.js"));
    assert(ota.apply_agent_update(staging));
    assert(FileUtils.test(
               Path.build_filename(root, "manifest.json"), FileTest.EXISTS));
    assert(FileUtils.test(
               Path.build_filename(root, "agents/wm-viewport.js"), FileTest.EXISTS));
    assert(manifest_verifies_at(root, new TrustStore()));
    rm_rf(root);
    rm_rf(staging);
}

void test_agent_apply_rejects_bad_sig_and_keeps_active() {
    string root = fresh_root();
    string staging = fresh_staging();
    var trust = new TrustStore();
    var ota = new Ota(root, trust);
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig"));
    copy_file(FIX + "/manifest.json",
              Path.build_filename(staging, "manifest.json"));
    copy_file(FIX + "/manifest-bad.sig",
              Path.build_filename(staging, "manifest.sig"));
    copy_file(FIX + "/agents/wm-viewport.js",
              Path.build_filename(staging, "agents/wm-viewport.js"));
    assert(ota.apply_agent_update(staging) == false);
    assert(manifest_verifies_at(root, trust));
    assert(!FileUtils.test(
               Path.build_filename(root, "manifest.json.prev"), FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

void test_boot_recovery_restores_prev() {
    string root = fresh_root();
    var trust = new TrustStore();
    var ota = new Ota(root, trust);
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json.prev"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig.prev"));
    assert(ota.recover_manifest());
    assert(FileUtils.test(
               Path.build_filename(root, "manifest.json"), FileTest.EXISTS));
    assert(!FileUtils.test(
               Path.build_filename(root, "manifest.json.prev"), FileTest.EXISTS));
    assert(manifest_verifies_at(root, trust));
    rm_rf(root);
}

void test_boot_recovery_noop_when_active_ok() {
    string root = fresh_root();
    var ota = new Ota(root, new TrustStore());
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig"));
    assert(ota.recover_manifest() == false);
    rm_rf(root);
}

// --- core apply / rollback ------------------------------------------------

string write_old_binary(string root) {
    string stable = Path.build_filename(root, "voboost-inject");
    try {
        FileUtils.set_contents(stable, "old-core-binary\n");
    } catch (FileError e) {
        assert_not_reached();
    }
    return Checksum.compute_for_data(
        ChecksumType.SHA256, "old-core-binary\n".data);
}

void test_core_apply_success() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    string oldsha = write_old_binary(root);
    copy_file(FIX + "/voboost-inject",
              Path.build_filename(staging, "voboost-inject"));
    var rm = load_release_manifest(ota);
    string newsha = rm.files[0].sha256;
    assert(ota.apply_core_update(
               Path.build_filename(staging, "voboost-inject"), rm)
           == CoreApplyOutcome.APPLIED);
    assert(FileUtils.test(
               Path.build_filename(root, "voboost-inject-" + newsha),
               FileTest.EXISTS));
    assert(FileUtils.test(
               Path.build_filename(root, "voboost-inject-" + oldsha),
               FileTest.EXISTS));
    assert(link_target(
               Path.build_filename(root, "voboost-inject")) == "voboost-inject-" + newsha);
    assert(ota.core_switch_pending());
    rm_rf(root);
    rm_rf(staging);
}

void test_core_apply_bad_sha_rejected() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    try {
        FileUtils.set_contents(
            Path.build_filename(staging, "voboost-inject"),
            "totally-different-bytes\n");
    } catch (FileError e) {
        assert_not_reached();
    }
    var rm = load_release_manifest(ota);
    assert(ota.apply_core_update(
               Path.build_filename(staging, "voboost-inject"), rm)
           == CoreApplyOutcome.REJECTED_BAD_HASH);
    assert(!ota.core_switch_pending());
    rm_rf(root);
    rm_rf(staging);
}

void test_core_rollback_repoints_to_previous() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    string oldsha = write_old_binary(root);
    copy_file(FIX + "/voboost-inject",
              Path.build_filename(staging, "voboost-inject"));
    var rm = load_release_manifest(ota);
    string newsha = rm.files[0].sha256;
    ota.apply_core_update(
        Path.build_filename(staging, "voboost-inject"), rm);
    assert(ota.core_switch_pending());
    ota.rollback_core_switch();
    assert(!ota.core_switch_pending());
    assert(link_target(
               Path.build_filename(root, "voboost-inject")) == "voboost-inject-" + oldsha);
    assert(link_target(
               Path.build_filename(root, "voboost-inject")) != "voboost-inject-" + newsha);
    rm_rf(root);
    rm_rf(staging);
}

void test_core_confirm_clears_marker_and_gcs_previous() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    string oldsha = write_old_binary(root);
    copy_file(FIX + "/voboost-inject",
              Path.build_filename(staging, "voboost-inject"));
    var rm = load_release_manifest(ota);
    ota.apply_core_update(
        Path.build_filename(staging, "voboost-inject"), rm);
    assert(ota.core_switch_pending());
    ota.confirm_core_switch();
    assert(!ota.core_switch_pending());
    assert(!FileUtils.test(
               Path.build_filename(root, "voboost-inject-" + oldsha),
               FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// --- release-manifest bounds & malformed entries --------------------------

void test_release_manifest_oversize_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] sig = read_bytes_or_fail(FIX + "/release-manifest.json.sig");
    // A pathologically large manifest is rejected before the signature check
    // (the size bound is enforced first) — DoS guard, release-manifest spec.
    uint8[] big = new uint8[Ota.MAX_RELEASE_MANIFEST_BYTES + 1];
    assert(ota.verify_release_manifest(big, sig) == null);
}

void test_release_manifest_bad_entry_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest-bad-entry.json");
    uint8[] sig = read_bytes_or_fail(
        FIX + "/release-manifest-bad-entry.json.sig");
    // A signed manifest whose entry omits a required field is rejected whole.
    assert(ota.verify_release_manifest(rm, sig) == null);
}

void test_release_manifest_bad_channel_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest-bad-channel.json");
    uint8[] sig = read_bytes_or_fail(
        FIX + "/release-manifest-bad-channel.json.sig");
    // A signed manifest with an invalid channel value is rejected whole.
    assert(ota.verify_release_manifest(rm, sig) == null);
}

// --- agent apply: stay-on-old on a partial failure ------------------------
// Relies on the normative content-addressed contract (a changed/new agent
// ships at a fresh path, so a failed sibling never corrupts the active set).

void test_agent_apply_partial_failure_stays_on_old() {
    string root = fresh_root();
    string staging = fresh_staging();
    var trust = new TrustStore();
    var ota = new Ota(root, trust);
    DirUtils.create(Path.build_filename(root, "agents"), 0700);
    // Active set: the single-agent fixture manifest + its payload.
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig"));
    copy_file(FIX + "/agents/wm-viewport.js",
              Path.build_filename(root, "agents/wm-viewport.js"));
    // Staged set: two fresh agents; agent-y is staged tampered so its sha
    // mismatches the manifest -> the apply aborts mid-loop.
    copy_file(FIX + "/manifest-multi.json",
              Path.build_filename(staging, "manifest.json"));
    copy_file(FIX + "/manifest-multi.sig",
              Path.build_filename(staging, "manifest.sig"));
    copy_file(FIX + "/agents/agent-x.js",
              Path.build_filename(staging, "agents/agent-x.js"));
    copy_file(FIX + "/agents/agent-y-bad.js",
              Path.build_filename(staging, "agents/agent-y.js"));
    assert(ota.apply_agent_update(staging) == false);
    // The active manifest is untouched (no swap) and still verifies; its payload
    // is intact. (The orphan agent-x install is harmless: not referenced.)
    assert(!FileUtils.test(
               Path.build_filename(root, "manifest.json.prev"), FileTest.EXISTS));
    assert(manifest_verifies_at(root, trust));
    assert(FileUtils.test(
               Path.build_filename(root, "agents/wm-viewport.js"), FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// --- boot recovery: active present but bad -------------------------------

void test_boot_recovery_restores_when_active_bad() {
    string root = fresh_root();
    var trust = new TrustStore();
    var ota = new Ota(root, trust);
    DirUtils.create(Path.build_filename(root, "agents"), 0700);
    // Active manifest present but its signature does not verify.
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json"));
    copy_file(FIX + "/manifest-bad.sig",
              Path.build_filename(root, "manifest.sig"));
    copy_file(FIX + "/agents/wm-viewport.js",
              Path.build_filename(root, "agents/wm-viewport.js"));
    // A verifying .prev pair exists.
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json.prev"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig.prev"));
    assert(ota.recover_manifest());
    assert(manifest_verifies_at(root, trust));
    assert(!FileUtils.test(
               Path.build_filename(root, "manifest.json.prev"), FileTest.EXISTS));
    rm_rf(root);
}

// --- core apply: DoS precheck + power-loss GC safety ----------------------

void test_core_apply_oversize_rejected() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    // Stage a binary larger than the signed entry.size -> rejected at the stat
    // pre-check, before the full read (DoS guard).
    uint8[] good = read_bytes_or_fail(FIX + "/voboost-inject");
    string padded = (string) good + string.nfill(1024, 'x');
    try {
        FileUtils.set_contents(
            Path.build_filename(staging, "voboost-inject"), padded);
    } catch (FileError e) {
        assert_not_reached();
    }
    var rm = load_release_manifest(ota);
    assert(ota.apply_core_update(
               Path.build_filename(staging, "voboost-inject"), rm)
           == CoreApplyOutcome.REJECTED_BAD_HASH);
    assert(!ota.core_switch_pending());
    rm_rf(root);
    rm_rf(staging);
}

void make_core_symlink(string root, string target_basename) {
    try {
        File.new_for_path(Path.build_filename(root, "voboost-inject"))
        .make_symbolic_link(target_basename);
    } catch (Error e) {
        assert_not_reached();
    }
}

void write_core_marker(string root, string prev_basename) {
    try {
        FileUtils.set_contents(
            Path.build_filename(root, "run/core-switch-pending"),
            prev_basename);
    } catch (FileError e) {
        assert_not_reached();
    }
}

// Power-loss between writing the marker and repointing: stable still points at
// the file the marker names, so confirm must NOT delete it (else a dangling
// symlink on the next restart). atomic-apply-rollback "Power-loss during core".
void test_core_confirm_keeps_active_when_not_repointed() {
    string root = fresh_root();
    var ota = new Ota(root, new TrustStore());
    string sha =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    string named = "voboost-inject-" + sha;
    try {
        FileUtils.set_contents(Path.build_filename(root, named), "B-binary\n");
    } catch (FileError e) {
        assert_not_reached();
    }
    make_core_symlink(root, named);
    write_core_marker(root, named);
    ota.confirm_core_switch();
    assert(!ota.core_switch_pending());
    assert(FileUtils.test(Path.build_filename(root, named), FileTest.EXISTS));
    assert(link_target(Path.build_filename(root, "voboost-inject")) == named);
    rm_rf(root);
}

public static int main(string[] args) {
    Test.init(ref args);
    // Route daemon logs to a temp dir so the OTA code paths (which call Log)
    // stay silent on a successful pass (codestyle: tests silent on success).
    Voboost.Log.init(Path.build_filename(Environment.get_tmp_dir(),
                                         "vob-ota-log-%d".printf((int) Posix.getpid())));
    Test.add_func("/ota/release-manifest/verify", test_release_manifest_verify);
    Test.add_func("/ota/release-manifest/bad-sig", test_release_manifest_bad_sig);
    Test.add_func("/ota/release-manifest/tampered", test_release_manifest_tampered);
    Test.add_func("/ota/release-manifest/oversize", test_release_manifest_oversize_rejected);
    Test.add_func("/ota/release-manifest/bad-entry", test_release_manifest_bad_entry_rejected);
    Test.add_func("/ota/release-manifest/bad-channel", test_release_manifest_bad_channel_rejected);
    Test.add_func("/ota/agent-apply/installs", test_agent_apply_installs_into_root);
    Test.add_func("/ota/agent-apply/bad-sig", test_agent_apply_rejects_bad_sig_and_keeps_active);
    Test.add_func("/ota/agent-apply/partial-failure", test_agent_apply_partial_failure_stays_on_old);
    Test.add_func("/ota/boot-recovery/restores-prev", test_boot_recovery_restores_prev);
    Test.add_func("/ota/boot-recovery/noop", test_boot_recovery_noop_when_active_ok);
    Test.add_func("/ota/boot-recovery/active-bad", test_boot_recovery_restores_when_active_bad);
    Test.add_func("/ota/core-apply/success", test_core_apply_success);
    Test.add_func("/ota/core-apply/bad-sha", test_core_apply_bad_sha_rejected);
    Test.add_func("/ota/core-apply/oversize", test_core_apply_oversize_rejected);
    Test.add_func("/ota/core-apply/rollback", test_core_rollback_repoints_to_previous);
    Test.add_func("/ota/core-apply/confirm", test_core_confirm_clears_marker_and_gcs_previous);
    Test.add_func("/ota/core-apply/confirm-powerloss", test_core_confirm_keeps_active_when_not_repointed);
    return Test.run();
}
