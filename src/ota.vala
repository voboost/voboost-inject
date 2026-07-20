namespace Voboost {
// One entry of a verified release manifest (release-manifest spec). Held only
// after the manifest's detached signature verifies against the embedded key and
// its size/entry bounds hold. The release manifest lists APKs (one inject entry
// for the daemon APK); it is the OTA client's trust source for the APK
// size+sha256 before staging. The daemon re-verifies the staged APK's embedded
// manifest (not the release manifest) at apply time.
public class ReleaseFile : Object {
public string path { get; construct; }
public string channel { get; construct; }
public string sha256 { get; construct; }
public int64 size { get; construct; }
public string version { get; construct; }

public ReleaseFile(string path, string channel, string sha256,
                   int64 size, string version) {
    Object(path: path, channel: channel, sha256: sha256,
           size: size, version: version);
}
}

public class ReleaseManifest : Object {
public string version { get; internal set; default = ""; }
public string channel { get; internal set; default = ""; }
public GenericArray<ReleaseFile> files { get; private set; }

public ReleaseManifest() {
    this.files = new GenericArray<ReleaseFile>();
}

// Find the inject-channel entry matching a basename. The release manifest lists
// APKs; the inject entry is the daemon APK. Non-inject entries never satisfy an
// inject lookup even if their path collides (defense-in-depth,
// release-manifest spec).
public ReleaseFile? find_inject(string basename) {
    for (uint i = 0; i < this.files.length; i++) {
        var f = this.files[i];
        if (f.channel == "inject" && f.path == basename) {
            return f;
        }
    }
    return null;
}
}

// Result of Ota.apply_inject_update. APPLIED means the caller MUST perform a
// clean self-shutdown so Android init restarts the service on the new binary;
// the running binary is never replaced in place (it is renamed aside to .prev
// and the new binary installed at the same pathname). Every REJECTED_* leaves
// the current binary active and unchanged.
public enum InjectApplyOutcome {
    APPLIED,
    REJECTED_NO_APK,
    REJECTED_BAD_BINARY,
    // The previous binary could not be preserved for rollback (IO error during
    // the rename aside); the switch is aborted so a bad new binary is never
    // installed without a rollback target.
    REJECTED_NO_ROLLBACK;
}

// APK-level inject self-update (ota-core-selfupdate change). Frida-free file-
// system logic; the daemon (Supervisor) triggers it and performs the
// self-shutdown / re-inject.
//
// On-disk layout (root_zone = /data/voboost):
//   manifest.json + manifest.sig         active signed daemon manifest (the
//                                         root-zone active copy, written at
//                                         provisioning/VERIFY_SELF from the
//                                         APK's embedded manifest)
//   manifest.json.prev + manifest.sig.prev one-deep rollback copy
//   voboost-inject                        the daemon binary init execs
//   voboost-inject.prev                   the previous binary, kept for rollback
//   run/voboost-inject-switch-pending     marker set after a self-replace
//
// The app zone staging/ dir is UNTRUSTED: the staged APK is re-verified by the
// daemon (its embedded manifest.json+.sig against EMBEDDED_PUBKEY) before any
// byte becomes active. The APK's own Android v2/v3 signature is NOT verified
// by the daemon (design D1: the daemon trusts the embedded manifest, not the
// APK signature). See ota-core-selfupdate design D1-D5.
public class Ota : Object {
public string root_zone { get; construct; }
public TrustStore trust { get; construct; }

// Bounds for the release-manifest parser (mirrors PlanReader.MAX_PLAN_BYTES).
public const int MAX_RELEASE_MANIFEST_BYTES = 1048576;
public const int MAX_RELEASE_ENTRIES = 4096;
// DoS bound for the staged inject payload (a single appended-sig ELF). The
// daemon ELF is tens of MB; 64 MB is a generous upper bound that rejects
// anything unreasonable before reading the file into memory.
// INJ-04: was 256 MB, which allowed FileUtils.get_data to allocate up to
// 256 MB before the post-read size check. 64 MB is still 4-8x a typical
// daemon ELF and bounds the peak memory of the apply path.
public const int64 MAX_INJECT_BYTES = 67108864;

// Fixed names. OTA applies are serialized on the daemon's single-threaded
// GMainLoop, so no two applies race for the same temp.
private const string MANIFEST = "manifest.json";
private const string MANIFEST_SIG = "manifest.sig";
private const string MANIFEST_PREV = "manifest.json.prev";
private const string MANIFEST_SIG_PREV = "manifest.sig.prev";
private const string INJECT_BINARY = "voboost-inject";
private const string INJECT_PREV = "voboost-inject.prev";
private const string INJECT_MARKER = "run/voboost-inject-switch-pending";
// The producer's "a verified daemon ELF is staged" marker, created last in
// the app-zone staging/ dir. Lives in the app zone but the daemon (root)
// owns its lifecycle as the consumer. Single-use (design D4).
private const string INJECT_UPDATE_READY = "voboost-inject-update-ready";

public Ota(string root_zone, TrustStore trust) {
    Object(root_zone: root_zone, trust: trust);
}

// True when the producer signalled a verified staged daemon APK. The daemon
// applies only while this is present (ota-core-selfupdate staging contract)
// and consumes it BEFORE the apply, so a successful self-replace + init
// restart is not re-applied on every boot — which would crash-loop the inject
// plane via self-shutdown + init restart.
public bool inject_update_ready(string staging_dir) {
    return FileUtils.test(
        Path.build_filename(staging_dir, INJECT_UPDATE_READY),
        FileTest.EXISTS);
}

// Remove the marker. Called BEFORE the apply (design D4: single-use, consume
// first). Best-effort: an unlink failure only means the next boot re-checks
// inject_update_ready and (for an identical verified APK) the apply runs again
// — the inject plane consumes it before its self-shutdown, where it must
// succeed for the loop to be broken, and it does (same dir just read, root
// perms).
public void consume_inject_update_ready(string staging_dir) {
    FileUtils.unlink(
        Path.build_filename(staging_dir, INJECT_UPDATE_READY));
}

// Verify + parse a release manifest. Returns null on a bad signature, malformed
// JSON, an out-of-bounds size/entry count, or any malformed entry (the whole
// manifest is rejected on one bad entry — release-manifest spec).
public ReleaseManifest? verify_release_manifest(
    uint8[] json_bytes, uint8[] sig) {
    if (json_bytes.length > MAX_RELEASE_MANIFEST_BYTES) {
        Log.err("ota", "release-manifest exceeds size bound");
        return null;
    }
    if (!this.trust.verify_signature(json_bytes, sig)) {
        Log.err("ota", "release-manifest signature rejected");
        return null;
    }
    var parser = new Json.Parser();
    try {
        parser.load_from_data((string) json_bytes, json_bytes.length);
    } catch (Error e) {
        return null;
    }
    var root = parser.get_root();
    if (root == null || root.get_node_type() != Json.NodeType.OBJECT) {
        return null;
    }
    var obj = root.get_object();
    var rm = new ReleaseManifest();
    rm.version = safe_string(obj, "version", "");
    rm.channel = safe_string(obj, "channel", "");
    if (!obj.has_member("files")) {
        return null;
    }
    var files_node = obj.get_member("files");
    if (files_node.get_node_type() != Json.NodeType.ARRAY) {
        return null;
    }
    var arr = files_node.get_array();
    if (arr.get_length() > MAX_RELEASE_ENTRIES) {
        Log.err("ota", "release-manifest exceeds entry bound");
        return null;
    }
    for (uint i = 0; i < arr.get_length(); i++) {
        var elem = arr.get_element(i);
        if (elem == null
            || elem.get_node_type() != Json.NodeType.OBJECT) {
            return null;
        }
        var f = elem.get_object();
        string path = safe_string(f, "path");
        string channel = safe_string(f, "channel");
        string sha = safe_string(f, "sha256");
        string ver = safe_string(f, "version");
        if (path == "" || sha == "" || ver == ""
            || (channel != "agents" && channel != "inject"
                && channel != "app")
            || !f.has_member("size")) {
            return null;
        }
        var size_node = f.get_member("size");
        if (size_node.get_node_type() != Json.NodeType.VALUE
            || size_node.get_value_type() != typeof(int64)) {
            return null;
        }
        rm.files.add(new ReleaseFile(path, channel, sha,
                                     size_node.get_int(), ver));
    }
    return rm;
}

// Boot recovery for the daemon manifest: if the active manifest is absent or
// its signature does not verify, but manifest.json.prev does verify, restore
// it. Returns true if a recovery happened. atomic-apply-rollback spec.
public bool recover_manifest() {
    string active = Path.build_filename(this.root_zone, MANIFEST);
    string active_sig = Path.build_filename(this.root_zone, MANIFEST_SIG);
    if (manifest_verifies(active, active_sig)) {
        return false;
    }
    string prev = Path.build_filename(this.root_zone, MANIFEST_PREV);
    string prev_sig = Path.build_filename(this.root_zone, MANIFEST_SIG_PREV);
    if (!manifest_verifies(prev, prev_sig)) {
        return false;
    }
    // Restore: rename .prev over the active (atomic on one filesystem). If
    // the active is absent this creates it; if present-but-bad it is replaced.
    // Both renames must succeed: if the manifest lands but its signature does
    // not, the active pair is left half-updated (manifest.json fresh,
    // manifest.sig stale) and the .prev backup is destroyed. Roll the first
    // rename back if the second fails so .prev survives for the next attempt.
    if (FileUtils.rename(prev, active) != 0) {
        Log.err("ota", "restore manifest.json rename failed");
        return false;
    }
    if (FileUtils.rename(prev_sig, active_sig) != 0) {
        Log.err("ota", "restore manifest.sig rename failed; rolling back");
        // Best-effort restore: move manifest.json back to .prev so the
        // verified .prev pair is preserved for the next recovery attempt.
        // A failure here leaves the active manifest without a .prev backup
        // (already an unrecoverable state); log and proceed.
        if (FileUtils.rename(active, prev) != 0) {
            Log.err("ota", "manifest.json rollback failed; .prev lost");
        }
        return false;
    }
    Log.ok("ota", "restored manifest from .prev");
    return true;
}

// Apply a staged inject update (ota-core-selfupdate). The marker is consumed
// FIRST (single-use, design D4), then the staged inject file (a single ELF
// with an appended ed25519 signature) is found, the appended signature is
// re-verified against EMBEDDED_PUBKEY over the ELF bytes (design D1), and the
// ELF portion is atomically self-replaced (rename aside to .prev, install the
// new binary at the same pathname, design D2). The
// voboost-inject-switch-pending marker is written and the caller self-shuts
// down so init restarts the new binary. On any REJECTED_* the current binary
// stays active (the marker is already consumed — the bad payload is dropped,
// not retried every boot). The inject payload carries no embedded per-agent
// manifest; the per-agent manifest rides in the app APK.
public InjectApplyOutcome apply_inject_update(string staging_dir) {
    // Consume the marker BEFORE the apply (design D4): a successful
    // self-replace + self-shutdown + init-restart must not re-apply the same
    // payload on every boot (crash-loop). The marker is the trigger, not part
    // of the verified set, so consuming it first is safe.
    consume_inject_update_ready(staging_dir);
    string inject = find_staged_inject(staging_dir);
    if (inject == null) {
        Log.err("ota", "no staged inject file in staging/");
        return InjectApplyOutcome.REJECTED_NO_APK;
    }
    // DoS guard: reject an oversized inject file before reading it.
    Posix.Stat st;
    if (Posix.stat(inject, out st) != 0 || st.st_size > MAX_INJECT_BYTES) {
        Log.err("ota", "staged inject file oversize/absent");
        return InjectApplyOutcome.REJECTED_NO_APK;
    }
    uint8[] inject_bytes;
    try {
        FileUtils.get_data(inject, out inject_bytes);
    } catch (Error e) {
        Log.err("ota", "staged inject file read: " + e.message);
        return InjectApplyOutcome.REJECTED_NO_APK;
    }
    if (inject_bytes.length > MAX_INJECT_BYTES) {
        Log.err("ota", "staged inject file grew past bound");
        return InjectApplyOutcome.REJECTED_NO_APK;
    }
    // Re-verify the appended ed25519 signature over the ELF bytes against
    // EMBEDDED_PUBKEY (design D1). The trailing VOBSIG1 block names the ELF
    // part by SIG_OFFSET; verify_appended_sig slices and verifies it.
    uint8[] bin_bytes;
    if (!verify_appended_sig(inject_bytes, this.trust, out bin_bytes)) {
        Log.err("ota", "staged inject signature rejected");
        return InjectApplyOutcome.REJECTED_BAD_BINARY;
    }
    if (bin_bytes.length == 0) {
        Log.err("ota", "staged inject ELF is empty");
        return InjectApplyOutcome.REJECTED_BAD_BINARY;
    }
    // Install the new binary as a root-zone temp, fsync, fchmod 0755.
    string tmp = Path.build_filename(this.root_zone, ".ota.inject.tmp");
    if (!write_bytes_exec(tmp, bin_bytes)) {
        Log.err("ota", "inject install write failed");
        FileUtils.unlink(tmp);
        return InjectApplyOutcome.REJECTED_BAD_BINARY;
    }
    // Preserve the previous binary as .prev for rollback (design D3). rename
    // of the running binary is safe on Linux/Android: the running process
    // keeps its inode until exit. Aborts if the previous binary cannot be
    // preserved: a switch with no rollback target must never proceed.
    string stable = Path.build_filename(this.root_zone, INJECT_BINARY);
    string prev = Path.build_filename(this.root_zone, INJECT_PREV);
    if (!preserve_previous_binary(stable, prev)) {
        Log.err("ota", "cannot preserve previous inject; aborting switch");
        FileUtils.unlink(tmp);
        return InjectApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // The marker MUST land before the new binary takes the pathname: it is
    // the rollback trigger on a DEGRADED restart. Without it the switch is
    // not safe to activate.
    if (!write_marker()) {
        Log.err("ota", "cannot write inject-switch marker; aborting switch");
        restore_previous_binary(stable, prev);
        FileUtils.unlink(tmp);
        return InjectApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // Install the new binary at the stable pathname (atomic rename). This is
    // the commit step: the running process keeps its old inode; the next exec
    // (by init after the self-shutdown) resolves the new binary.
    if (FileUtils.rename(tmp, stable) != 0) {
        Log.err("ota", "inject install rename failed; aborting switch");
        FileUtils.unlink(Path.build_filename(this.root_zone, INJECT_MARKER));
        restore_previous_binary(stable, prev);
        FileUtils.unlink(tmp);
        return InjectApplyOutcome.REJECTED_BAD_BINARY;
    }
    Log.ok("ota", "inject self-updated -> " + stable);
    return InjectApplyOutcome.APPLIED;
}

public bool inject_switch_pending() {
    return FileUtils.test(
        Path.build_filename(this.root_zone, INJECT_MARKER), FileTest.EXISTS);
}

// Confirm a successful inject switch: clear the marker and remove .prev (the
// previous binary is no longer needed). atomic-apply-rollback "Ready restart
// confirms the switch".
public void confirm_inject_switch() {
    string marker = Path.build_filename(this.root_zone, INJECT_MARKER);
    FileUtils.unlink(marker);
    FileUtils.unlink(Path.build_filename(this.root_zone, INJECT_PREV));
}

// Roll back a failed inject switch: restore .prev over the bad new binary and
// clear the marker. Caller self-shuts down so init restarts the previous
// binary. atomic-apply-rollback "Degraded restart rolls back". If .prev is
// absent (first-update edge, or power-loss between the rename and the marker
// write) the daemon cannot restore and stays DEGRADED rather than exec a
// known-bad binary with no rollback target.
public bool rollback_inject_switch() {
    string marker = Path.build_filename(this.root_zone, INJECT_MARKER);
    FileUtils.unlink(marker);
    string stable = Path.build_filename(this.root_zone, INJECT_BINARY);
    string prev = Path.build_filename(this.root_zone, INJECT_PREV);
    if (!FileUtils.test(prev, FileTest.EXISTS)) {
        Log.err("ota", "no .prev rollback target; staying DEGRADED");
        return false;
    }
    // rename .prev over the bad new binary (atomic on one filesystem).
    if (FileUtils.rename(prev, stable) != 0) {
        Log.err("ota", "rollback rename failed");
        return false;
    }
    Log.ok("ota", "inject rolled back -> " + stable);
    return true;
}

// --- helpers ----------------------------------------------------------

// True if path+sig exist and the signature verifies against the embedded key.
private bool manifest_verifies(string path, string sig_path) {
    if (!FileUtils.test(path, FileTest.EXISTS)
        || !FileUtils.test(sig_path, FileTest.EXISTS)) {
        return false;
    }
    uint8[] json_bytes;
    uint8[] sig;
    try {
        FileUtils.get_data(path, out json_bytes);
        FileUtils.get_data(sig_path, out sig);
    } catch (Error e) {
        return false;
    }
    return this.trust.verify_signature(json_bytes, sig);
}

// Find the staged inject file in staging/. The producer stages it under a
// fixed name; return its path or null. (The producer contract: exactly one
// inject file named voboost-inject — a single appended-sig ELF, no extension
// — in staging/.)
private string? find_staged_inject(string staging_dir) {
    string inject = Path.build_filename(staging_dir, "voboost-inject");
    if (FileUtils.test(inject, FileTest.EXISTS)) {
        return inject;
    }
    return null;
}

// Preserve the previous binary as .prev. If .prev already exists (a prior
// switch left it, or a previous apply was interrupted), it is overwritten —
// the active binary is the authoritative previous. rename of the running
// binary is safe on Linux/Android (the running process keeps its inode).
// Returns false if the active binary cannot be renamed aside (no rollback
// target -> abort the switch).
private bool preserve_previous_binary(string stable, string prev) {
    if (!FileUtils.test(stable, FileTest.EXISTS)) {
        // First update (no binary yet): nothing to preserve. The switch
        // proceeds with no .prev; rollback will stay DEGRADED if the new
        // binary is bad (the never-broken invariant: no binary is lost).
        return true;
    }
    return FileUtils.rename(stable, prev) == 0;
}

// Restore .prev over the stable pathname (used when aborting a switch after
// the previous binary was preserved but before the new binary committed).
private void restore_previous_binary(string stable, string prev) {
    if (FileUtils.test(prev, FileTest.EXISTS)) {
        FileUtils.rename(prev, stable);
    }
}

// Write data to dst as a fresh regular file (set_contents replaces a pre-placed
// symlink), fsync via an O_NOFOLLOW fd (refuses a racing symlink back to a
// root file), fchmod 0700. Mirrors Status.write_atomic.
private bool write_bytes_exec(string dst, uint8[] data) {
    try {
        FileUtils.set_contents(dst, (string) data, data.length);
    } catch (Error e) {
        return false;
    }
    int fd = Posix.open(dst, Posix.O_WRONLY | Posix.O_NOFOLLOW);
    if (fd < 0) {
        FileUtils.unlink(dst);
        return false;
    }
    Posix.fchmod(fd, 0700);
    Posix.fsync(fd);
    Posix.close(fd);
    return true;
}

// Durably write the inject-switch marker. Returns false on any IO failure (the
// caller aborts the switch: without a marker a DEGRADED restart cannot roll
// back, so the switch must not proceed).
private bool write_marker() {
    string run_dir = Path.build_filename(this.root_zone, "run");
    DirUtils.create_with_parents(run_dir, 0700);
    string marker = Path.build_filename(this.root_zone, INJECT_MARKER);
    string tmp = Path.build_filename(run_dir, ".ota.marker.tmp");
    try {
        FileUtils.set_contents(tmp, "pending");
    } catch (Error e) {
        return false;
    }
    int fd = Posix.open(tmp, Posix.O_WRONLY | Posix.O_NOFOLLOW);
    if (fd >= 0) {
        Posix.fsync(fd);
        Posix.close(fd);
    }
    return FileUtils.rename(tmp, marker) == 0;
}

// --- appended-signature verify (design D1/D2) ---------------------------
// The staged inject payload is a single file: the daemon ELF bytes followed
// by an 80-byte trailing block (8 bytes magic "VOBSIG1\0", 8 bytes LE uint64
// SIG_OFFSET naming the end of the ELF part, 64 bytes raw ed25519 signature
// over the ELF bytes). The kernel loads the ELF by its header and ignores the
// trailing bytes at exec; the daemon reads the trailing block here to
// re-verify the signature before installing the ELF portion.

// Verify the appended signature of a staged inject file. On success, slices
// the ELF bytes [0..SIG_OFFSET) into `out elf_bytes` and returns true. On any
// structural failure (file too short, missing VOBSIG1 magic, SIG_OFFSET out
// of bounds) or signature failure, returns false and sets elf_bytes to empty.
// Static + pure (no instance state); takes the TrustStore explicitly so tests
// can call it directly without constructing an Ota.
public static bool verify_appended_sig(
        uint8[] bytes, TrustStore trust, out uint8[] elf_bytes) {
    elf_bytes = new uint8[0];
    // Trailing block = 8 magic + 8 offset + 64 signature = 80 bytes.
    const int TRAILING = 80;
    // Need at least 1 ELF byte + the trailing block.
    if (bytes.length < TRAILING + 1) {
        return false;
    }
    int trailing_start = bytes.length - TRAILING;
    // Magic: "VOBSIG1\0" (8 bytes ASCII, NUL-padded). Built byte-by-byte so
    // the comparator gets a real pointer; a Vala inline-array declaration is
    // not allowed here.
    uint8[] magic = new uint8[] {
        'V', 'O', 'B', 'S', 'I', 'G', '1', 0
    };
    if (Posix.memcmp(&bytes[trailing_start], &magic[0], 8) != 0) {
        return false;
    }
    // SIG_OFFSET (LE uint64) at trailing_start + 8: the authoritative end of
    // the ELF part. Bounds-checked: must leave at least 1 ELF byte and must
    // not overrun past the trailing block start.
    uint64 sig_offset = read_le64(bytes, trailing_start + 8);
    if (sig_offset < 1 || sig_offset > (uint64) trailing_start) {
        return false;
    }
    // Signature: 64 raw bytes immediately after the offset field.
    int sig_off = trailing_start + 16;
    uint8[] sig = new uint8[64];
    Posix.memcpy(sig, &bytes[sig_off], 64);
    // Slice the ELF part and verify the detached ed25519 signature over it.
    elf_bytes = new uint8[(int) sig_offset];
    Posix.memcpy(elf_bytes, &bytes[0], (size_t) sig_offset);
    return trust.verify_signature(elf_bytes, sig);
}

// Read an 8-byte little-endian unsigned 64-bit integer at `off`. The only LE
// reader left after the ZIP reader was removed (the inject payload has one
// LE field: SIG_OFFSET).
private static uint64 read_le64(uint8[] b, int off) {
    uint64 v = 0;
    v |= (uint64) b[off];
    v |= (uint64) b[off + 1] << 8;
    v |= (uint64) b[off + 2] << 16;
    v |= (uint64) b[off + 3] << 24;
    v |= (uint64) b[off + 4] << 32;
    v |= (uint64) b[off + 5] << 40;
    v |= (uint64) b[off + 6] << 48;
    v |= (uint64) b[off + 7] << 56;
    return v;
}


private static string safe_string(Json.Object obj, string name,
                                  string def = "") {
    if (!obj.has_member(name)) {
        return def;
    }
    var n = obj.get_member(name);
    if (n.get_node_type() == Json.NodeType.VALUE
        && n.get_value_type() == typeof(string)) {
        return n.get_string();
    }
    return def;
}
}
}
