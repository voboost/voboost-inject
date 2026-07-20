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

// A temp root_zone with a run/ subdir (the inject-switch marker lives there).
string fresh_root() {
    string d = fresh_dir("root");
    DirUtils.create(Path.build_filename(d, "run"), 0700);
    return d;
}

string fresh_staging() {
    string d = fresh_dir("stage");
    return d;
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

// Stage an inject payload (single appended-sig ELF) + the
// voboost-inject-update-ready marker into staging/.
void stage_inject(string staging, string inject_name) {
    copy_file(FIX + "/" + inject_name,
              Path.build_filename(staging, "voboost-inject"));
    try {
        FileUtils.set_contents(
            Path.build_filename(staging, "voboost-inject-update-ready"), "ready");
    } catch (FileError e) {
        assert_not_reached();
    }
}

// Write a fake "old" running binary at the stable launch path.
void write_old_binary(string root) {
    try {
        FileUtils.set_contents(
            Path.build_filename(root, "voboost-inject"), "old-inject-binary\n");
    } catch (FileError e) {
        assert_not_reached();
    }
}

string file_sha(string path) {
    uint8[] data = read_bytes_or_fail(path);
    return Checksum.compute_for_data(ChecksumType.SHA256, data);
}

// --- release-manifest verify ----------------------------------------------

void test_release_manifest_verify() {
    var ota = new Ota("/data/voboost", new TrustStore());
    var rm = load_release_manifest(ota);
    assert(rm.version == "1.0.0-beta1");
    assert(rm.channel == "inject");
    assert(rm.files.length == 1);
    assert(rm.files[0].path == "voboost-inject");
    assert(rm.files[0].channel == "inject");
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

void test_release_manifest_oversize_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] sig = read_bytes_or_fail(FIX + "/release-manifest.json.sig");
    uint8[] big = new uint8[Ota.MAX_RELEASE_MANIFEST_BYTES + 1];
    assert(ota.verify_release_manifest(big, sig) == null);
}

void test_release_manifest_bad_entry_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest-bad-entry.json");
    uint8[] sig = read_bytes_or_fail(
        FIX + "/release-manifest-bad-entry.json.sig");
    assert(ota.verify_release_manifest(rm, sig) == null);
}

void test_release_manifest_bad_channel_rejected() {
    var ota = new Ota("/data/voboost", new TrustStore());
    uint8[] rm = read_bytes_or_fail(FIX + "/release-manifest-bad-channel.json");
    uint8[] sig = read_bytes_or_fail(
        FIX + "/release-manifest-bad-channel.json.sig");
    assert(ota.verify_release_manifest(rm, sig) == null);
}

// --- appended-sig verify --------------------------------------------------

// verify_appended_sig accepts a good payload and returns the ELF bytes.
void test_appended_sig_verify_good() {
    uint8[] payload = read_bytes_or_fail(FIX + "/voboost-inject");
    uint8[] elf;
    assert(Ota.verify_appended_sig(payload, new TrustStore(), out elf));
    // The returned ELF bytes match the fixture ELF byte-for-byte.
    uint8[] expected = read_bytes_or_fail(FIX + "/voboost-inject-elf");
    assert(elf.length == expected.length);
    assert(Posix.memcmp(elf, expected, elf.length) == 0);
}

// A flipped signature byte fails verification (the magic and SIG_OFFSET are
// fine; the ed25519 check rejects).
void test_appended_sig_bad_sig_rejected() {
    uint8[] payload = read_bytes_or_fail(FIX + "/voboost-inject-bad-sig");
    uint8[] elf;
    assert(!Ota.verify_appended_sig(payload, new TrustStore(), out elf));
}

// Trailing bytes without the VOBSIG1 magic are rejected at the magic check.
void test_appended_sig_no_magic_rejected() {
    uint8[] payload = read_bytes_or_fail(FIX + "/voboost-inject-no-magic");
    uint8[] elf;
    assert(!Ota.verify_appended_sig(payload, new TrustStore(), out elf));
}

// A file shorter than the 80-byte trailing block is rejected by the minimum
// size check before any parsing.
void test_appended_sig_truncated_rejected() {
    uint8[] payload = read_bytes_or_fail(FIX + "/voboost-inject-truncated");
    uint8[] elf;
    assert(!Ota.verify_appended_sig(payload, new TrustStore(), out elf));
}

// A SIG_OFFSET that points past the file is rejected by the bounds check.
void test_appended_sig_bad_offset_rejected() {
    uint8[] payload = read_bytes_or_fail(FIX + "/voboost-inject-bad-offset");
    uint8[] elf;
    assert(!Ota.verify_appended_sig(payload, new TrustStore(), out elf));
}

// An exactly-empty payload (zero bytes) is rejected.
void test_appended_sig_empty_rejected() {
    var empty = new uint8[0];
    uint8[] elf;
    assert(!Ota.verify_appended_sig(empty, new TrustStore(), out elf));
}


// --- inject apply / rollback ----------------------------------------------

// A successful self-replace: the running binary is renamed to .prev, the new
// binary takes the stable pathname, the marker is set, and the marker in
// staging/ is consumed (single-use).
void test_inject_apply_success() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    string oldsha = file_sha(Path.build_filename(root, "voboost-inject"));
    stage_inject(staging, "voboost-inject");
    assert(ota.apply_inject_update(staging)
           == InjectApplyOutcome.APPLIED);
    // The marker is consumed (single-use).
    assert(!FileUtils.test(
               Path.build_filename(staging, "voboost-inject-update-ready"),
               FileTest.EXISTS));
    // The new binary is at the stable pathname; the old is at .prev.
    assert(file_sha(Path.build_filename(root, "voboost-inject"))
           != oldsha);
    assert(FileUtils.test(
               Path.build_filename(root, "voboost-inject.prev"),
               FileTest.EXISTS));
    assert(file_sha(Path.build_filename(root, "voboost-inject.prev"))
           == oldsha);
    // The voboost-inject-switch-pending marker is set.
    assert(ota.inject_switch_pending());
    rm_rf(root);
    rm_rf(staging);
}

// A bad appended signature is rejected; the current binary stays active and
// the marker is consumed (the bad payload is dropped).
void test_inject_apply_bad_sig() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    stage_inject(staging, "voboost-inject-bad-sig");
    assert(ota.apply_inject_update(staging)
           == InjectApplyOutcome.REJECTED_BAD_BINARY);
    assert(!ota.inject_switch_pending());
    assert(!FileUtils.test(
               Path.build_filename(root, "voboost-inject.prev"),
               FileTest.EXISTS));
    // The marker is consumed even on rejection.
    assert(!FileUtils.test(
               Path.build_filename(staging, "voboost-inject-update-ready"),
               FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// A payload missing the VOBSIG1 magic is rejected at the magic check.
void test_inject_apply_no_magic() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    stage_inject(staging, "voboost-inject-no-magic");
    assert(ota.apply_inject_update(staging)
           == InjectApplyOutcome.REJECTED_BAD_BINARY);
    rm_rf(root);
    rm_rf(staging);
}

// A truncated payload (shorter than the 80-byte trailing block) is rejected.
void test_inject_apply_truncated() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    stage_inject(staging, "voboost-inject-truncated");
    assert(ota.apply_inject_update(staging)
           == InjectApplyOutcome.REJECTED_BAD_BINARY);
    rm_rf(root);
    rm_rf(staging);
}

// No staged inject file -> REJECTED_NO_APK, marker consumed.
void test_inject_apply_no_inject() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    try {
        FileUtils.set_contents(
            Path.build_filename(staging, "voboost-inject-update-ready"), "ready");
    } catch (FileError e) {
        assert_not_reached();
    }
    assert(ota.apply_inject_update(staging)
           == InjectApplyOutcome.REJECTED_NO_APK);
    assert(!FileUtils.test(
               Path.build_filename(staging, "voboost-inject-update-ready"),
               FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// Rollback on a DEGRADED restart: .prev is restored over the bad new binary,
// the marker is cleared.
void test_inject_rollback_restores_prev() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    string oldsha = file_sha(Path.build_filename(root, "voboost-inject"));
    stage_inject(staging, "voboost-inject");
    ota.apply_inject_update(staging);
    assert(ota.inject_switch_pending());
    assert(ota.rollback_inject_switch());
    assert(!ota.inject_switch_pending());
    // The stable pathname now holds the old binary again.
    assert(file_sha(Path.build_filename(root, "voboost-inject")) == oldsha);
    // .prev is consumed by the rollback rename.
    assert(!FileUtils.test(
               Path.build_filename(root, "voboost-inject.prev"),
               FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// Confirm on a READY restart: marker cleared, .prev removed.
void test_inject_confirm_clears_marker_and_removes_prev() {
    string root = fresh_root();
    string staging = fresh_staging();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    stage_inject(staging, "voboost-inject");
    ota.apply_inject_update(staging);
    assert(ota.inject_switch_pending());
    ota.confirm_inject_switch();
    assert(!ota.inject_switch_pending());
    assert(!FileUtils.test(
               Path.build_filename(root, "voboost-inject.prev"),
               FileTest.EXISTS));
    rm_rf(root);
    rm_rf(staging);
}

// No .prev rollback target: rollback returns false (stay DEGRADED).
void test_inject_rollback_no_prev_target() {
    string root = fresh_root();
    var ota = new Ota(root, new TrustStore());
    write_old_binary(root);
    // Simulate a marker with no .prev (power-loss between the rename and the
    // marker write, or a first-update edge).
    try {
        FileUtils.set_contents(
            Path.build_filename(root, "run/voboost-inject-switch-pending"), "pending");
    } catch (FileError e) {
        assert_not_reached();
    }
    assert(ota.inject_switch_pending());
    assert(!ota.rollback_inject_switch());
    // The marker is cleared even when there is no .prev (no crash-loop).
    assert(!ota.inject_switch_pending());
    rm_rf(root);
}

// --- boot recovery (daemon manifest) --------------------------------------

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
               Path.build_filename(root, "manifest.json.prev"),
               FileTest.EXISTS));
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

void test_boot_recovery_restores_when_active_bad() {
    string root = fresh_root();
    var trust = new TrustStore();
    var ota = new Ota(root, trust);
    DirUtils.create(Path.build_filename(root, "agents"), 0700);
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json"));
    copy_file(FIX + "/manifest-bad.sig",
              Path.build_filename(root, "manifest.sig"));
    copy_file(FIX + "/agents/wm-viewport.js",
              Path.build_filename(root, "agents/wm-viewport.js"));
    copy_file(FIX + "/manifest.json",
              Path.build_filename(root, "manifest.json.prev"));
    copy_file(FIX + "/manifest.sig",
              Path.build_filename(root, "manifest.sig.prev"));
    assert(ota.recover_manifest());
    assert(manifest_verifies_at(root, trust));
    assert(!FileUtils.test(
               Path.build_filename(root, "manifest.json.prev"),
               FileTest.EXISTS));
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
    Test.add_func("/ota/appended-sig/verify-good", test_appended_sig_verify_good);
    Test.add_func("/ota/appended-sig/bad-sig", test_appended_sig_bad_sig_rejected);
    Test.add_func("/ota/appended-sig/no-magic", test_appended_sig_no_magic_rejected);
    Test.add_func("/ota/appended-sig/truncated", test_appended_sig_truncated_rejected);
    Test.add_func("/ota/appended-sig/bad-offset", test_appended_sig_bad_offset_rejected);
    Test.add_func("/ota/appended-sig/empty", test_appended_sig_empty_rejected);
    Test.add_func("/ota/inject-apply/success", test_inject_apply_success);
    Test.add_func("/ota/inject-apply/bad-sig", test_inject_apply_bad_sig);
    Test.add_func("/ota/inject-apply/no-magic", test_inject_apply_no_magic);
    Test.add_func("/ota/inject-apply/truncated", test_inject_apply_truncated);
    Test.add_func("/ota/inject-apply/no-inject", test_inject_apply_no_inject);
    Test.add_func("/ota/inject-apply/rollback", test_inject_rollback_restores_prev);
    Test.add_func("/ota/inject-apply/confirm",
                  test_inject_confirm_clears_marker_and_removes_prev);
    Test.add_func("/ota/inject-apply/rollback-no-prev", test_inject_rollback_no_prev_target);
    Test.add_func("/ota/boot-recovery/restores-prev", test_boot_recovery_restores_prev);
    Test.add_func("/ota/boot-recovery/noop", test_boot_recovery_noop_when_active_ok);
    Test.add_func("/ota/boot-recovery/active-bad", test_boot_recovery_restores_when_active_bad);
    return Test.run();
}
