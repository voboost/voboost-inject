namespace Voboost {
// One entry of a verified release manifest (release-manifest spec). Held only
// after the manifest's detached signature verifies against the embedded key and
// its size/entry bounds hold.
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

// Find the core-channel entry matching a basename (the core apply matches the
// staged binary by name and requires the core channel — defense-in-depth on
// signed content, release-manifest spec). Non-core entries never satisfy a
// core apply even if their path collides.
public ReleaseFile? find_core(string basename) {
    for (uint i = 0; i < this.files.length; i++) {
        var f = this.files[i];
        if (f.channel == "core" && f.path == basename) {
            return f;
        }
    }
    return null;
}
}

// Result of Ota.apply_core_update. APPLIED means the caller MUST perform a clean
// self-shutdown so Android init restarts the service on the new binary; the
// running binary is never replaced in place. Every REJECTED_* leaves the current
// binary active and unchanged.
public enum CoreApplyOutcome {
    APPLIED,
    REJECTED_BAD_HASH,
    REJECTED_NO_ENTRY,
    REJECTED_NO_MANIFEST,
    // The previous binary could not be preserved for rollback (IO error during
    // the first-update migration); the switch is aborted so a bad new binary is
    // never installed without a rollback target.
    REJECTED_NO_ROLLBACK;
}

// OTA apply/rollback for both planes (ota change). Frida-free file-system logic;
// the daemon (Supervisor) triggers it and performs the self-shutdown / re-inject.
//
// On-disk layout (root_zone = /data/voboost):
//   manifest.json + manifest.sig         active signed daemon manifest
//   manifest.json.prev + manifest.sig.prev one-deep rollback copy
//   <agents[].file>                       agent payloads. A changed agent SHALL
//                                         ship at a new, sha-derived path
//                                         (atomic-apply-rollback), so an update
//                                         never overwrites a file the active
//                                         manifest still references.
//   voboost-inject                        stable launch path the init hook execs
//   voboost-inject-<sha>                  content-addressed core binary
//   run/core-switch-pending               marker naming the previous core file
//
// The app zone staging/ dir is UNTRUSTED: every byte copied out of it is
// re-verified on a root-owned inode before it can become active (mirrors
// Status.write_atomic: set_contents + O_NOFOLLOW + fsync + rename). See
// incremental-delta "Daemon re-verifies staged material".
public class Ota : Object {
public string root_zone { get; construct; }
public TrustStore trust { get; construct; }

// Bounds for the release-manifest parser (mirrors PlanReader.MAX_PLAN_BYTES).
public const int MAX_RELEASE_MANIFEST_BYTES = 1048576;
public const int MAX_RELEASE_ENTRIES = 4096;

// Fixed temp names: OTA applies are serialized on the daemon's single-threaded
// GMainLoop, so no two applies race for the same temp.
private const string MANIFEST = "manifest.json";
private const string MANIFEST_SIG = "manifest.sig";
private const string MANIFEST_PREV = "manifest.json.prev";
private const string MANIFEST_SIG_PREV = "manifest.sig.prev";
private const string CORE_BINARY = "voboost-inject";
private const string CORE_MARKER = "run/core-switch-pending";
// The producer's "a complete staged set is ready" marker, created last in the
// app-zone staging/ dir (update-planes). Lives in the app zone but the daemon
// (root) owns its lifecycle as the consumer.
private const string UPDATE_READY = "update-ready";

public Ota(string root_zone, TrustStore trust) {
    Object(root_zone: root_zone, trust: trust);
}

// True when the producer signalled a complete staged set. The daemon applies
// only while this is present (update-planes staging contract) and consumes it
// after any apply attempt, so a successful update is not re-applied on every
// boot — which would crash-loop the core plane via self-shutdown + init restart.
public bool staged_update_ready(string staging_dir) {
    return FileUtils.test(
        Path.build_filename(staging_dir, UPDATE_READY), FileTest.EXISTS);
}

// Remove the marker after an apply attempt (success or verified-failure). A
// present marker implies a complete set per the contract, so a verified failure
// is a genuinely bad set the app must re-stage — not something to retry every
// boot. Best-effort: an unlink failure only means the next boot re-checks
// staged_update_ready and (for an identical verified set) no-ops; the core
// plane consumes it before its self-shutdown, where it must succeed for the
// loop to be broken, and it does (same dir just read, root perms).
public void consume_update_ready(string staging_dir) {
    FileUtils.unlink(Path.build_filename(staging_dir, UPDATE_READY));
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
            || (channel != "agents" && channel != "core"
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

// Boot recovery for the daemon manifest: if the active manifest is absent or its
// signature does not verify, but manifest.json.prev does verify, restore it.
// Returns true if a recovery happened. atomic-apply-rollback spec.
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
    // Restore: rename .prev over the active (atomic on one filesystem). If the
    // active is absent this creates it; if present-but-bad it is replaced.
    FileUtils.rename(prev, active);
    FileUtils.rename(prev_sig, active_sig);
    Log.ok("ota", "restored manifest from .prev");
    return true;
}

// Apply a staged agent update. Re-verifies the staged manifest signature and
// every referenced agent sha256 with the embedded key, then atomically swaps the
// manifest (old -> manifest.json.prev). Returns true on success; on any failure
// the active manifest and agent set are untouched. atomic-apply-rollback spec.
public bool apply_agent_update(string staging_dir) {
    string staged = Path.build_filename(staging_dir, MANIFEST);
    string staged_sig = Path.build_filename(staging_dir, MANIFEST_SIG);
    uint8[] json_bytes;
    uint8[] sig;
    try {
        FileUtils.get_data(staged, out json_bytes);
        FileUtils.get_data(staged_sig, out sig);
    } catch (Error e) {
        Log.err("ota", "staged manifest read: " + e.message);
        return false;
    }
    var staged_manifest = new Manifest();
    if (!staged_manifest.load_verified(json_bytes, sig, this.trust)) {
        Log.err("ota", "staged manifest signature rejected");
        return false;
    }
    // Install every changed agent payload from staging into the root zone first
    // (TOCTOU-safe: copy to a root temp, fsync, re-verify on the root inode,
    // then rename into place). Unchanged files (only present in root_zone) are
    // verified in place. All files are in place BEFORE the manifest swap, so the
    // new manifest never references a missing file.
    var installed = new GenericArray<string>();
    for (uint i = 0; i < staged_manifest.agents.length; i++) {
        var a = staged_manifest.agents[i];
        string staged_file = Path.build_filename(staging_dir, a.file);
        string root_file = Path.build_filename(this.root_zone, a.file);
        if (FileUtils.test(staged_file, FileTest.EXISTS)) {
            string tmp = Path.build_filename(
                this.root_zone, ".ota.agent.tmp");
            if (!copy_file_verify(staged_file, tmp, a.sha256)) {
                Log.err("ota", "agent install failed: " + a.id);
                FileUtils.unlink(tmp);
                return false;
            }
            // Ensure the target subdirectory exists (a new agent may carry a
            // path like agents/foo.js whose dir is not present yet).
            DirUtils.create_with_parents(Path.get_dirname(root_file), 0700);
            if (FileUtils.rename(tmp, root_file) != 0) {
                Log.err("ota", "agent rename failed: " + a.id);
                FileUtils.unlink(tmp);
                return false;
            }
            installed.add(root_file);
        } else if (!this.trust.verify_agent(root_file, a.sha256)) {
            // Not staged and the existing root copy does not match: the update
            // is incomplete or corrupt. Leave the active set intact.
            Log.err("ota", "agent file missing/unverified: " + a.id);
            cleanup_temps(installed);
            return false;
        }
    }
    // Swap the manifest last: copy staged manifest + sig to root temps, fsync,
    // re-verify, then rename active -> .prev and temps -> active.
    string m_tmp = Path.build_filename(this.root_zone, ".ota.manifest.tmp");
    string s_tmp = Path.build_filename(this.root_zone, ".ota.manifest.sig.tmp");
    if (!write_bytes_verify(m_tmp, json_bytes)
        || !write_bytes_verify(s_tmp, sig)) {
        FileUtils.unlink(m_tmp);
        FileUtils.unlink(s_tmp);
        cleanup_temps(installed);
        return false;
    }
    var staged_recheck = new Manifest();
    uint8[] m_tmp_bytes;
    uint8[] s_tmp_bytes;
    try {
        FileUtils.get_data(m_tmp, out m_tmp_bytes);
        FileUtils.get_data(s_tmp, out s_tmp_bytes);
    } catch (Error e) {
        FileUtils.unlink(m_tmp);
        FileUtils.unlink(s_tmp);
        cleanup_temps(installed);
        return false;
    }
    if (!staged_recheck.load_verified(m_tmp_bytes, s_tmp_bytes,
                                      this.trust)) {
        Log.err("ota", "staged manifest re-verify failed");
        FileUtils.unlink(m_tmp);
        FileUtils.unlink(s_tmp);
        cleanup_temps(installed);
        return false;
    }
    string active = Path.build_filename(this.root_zone, MANIFEST);
    string active_sig = Path.build_filename(this.root_zone, MANIFEST_SIG);
    string prev = Path.build_filename(this.root_zone, MANIFEST_PREV);
    string prev_sig = Path.build_filename(this.root_zone, MANIFEST_SIG_PREV);
    FileUtils.rename(active, prev);
    FileUtils.rename(active_sig, prev_sig);
    FileUtils.rename(m_tmp, active);
    FileUtils.rename(s_tmp, active_sig);
    Log.ok("ota", "agent set updated");
    return true;
}

// Apply a staged core binary. Verifies its sha256 (and size) against the verified
// release manifest, installs it as voboost-inject-<sha>, writes the
// core-switch-pending marker naming the previous active file, and atomically
// repoints the stable launch path to the new file. Returns APPLIED on success
// (caller self-shuts down so init restarts the new binary). update-planes +
// atomic-apply-rollback specs.
public CoreApplyOutcome apply_core_update(
    string staged_binary, ReleaseManifest rm) {
    string name = Path.get_basename(staged_binary);
    ReleaseFile? entry = rm.find_core(name);
    if (entry == null) {
        Log.err("ota", "no core entry for " + name);
        return CoreApplyOutcome.REJECTED_NO_ENTRY;
    }
    // DoS guard: the trusted signed size lets us reject an oversized staged
    // binary BEFORE reading it into memory (mirrors plan_file_too_big). The
    // post-read length check below stays authoritative against TOCTOU growth.
    Posix.Stat st;
    if (Posix.stat(staged_binary, out st) != 0
        || st.st_size != entry.size) {
        Log.err("ota", "core size disagrees (DoS guard)");
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    uint8[] data;
    try {
        FileUtils.get_data(staged_binary, out data);
    } catch (Error e) {
        Log.err("ota", "core read: " + e.message);
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    if (data.length != entry.size) {
        Log.err("ota", "core size mismatch");
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    string sha = Checksum.compute_for_data(ChecksumType.SHA256, data);
    if (sha != entry.sha256.down()) {
        Log.err("ota", "core sha256 mismatch");
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    // Install the new content-addressed file and re-verify on its root inode.
    string new_file = Path.build_filename(
        this.root_zone, CORE_BINARY + "-%s".printf(entry.sha256));
    if (!write_bytes_verify(new_file, data)
        || sha_of(new_file) != entry.sha256.down()) {
        Log.err("ota", "core install verify failed");
        FileUtils.unlink(new_file);
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    // Preserve the previous active file under a content-addressed name so
    // rollback has a target (first update migrates a plain binary to the
    // content-addressed layout). Aborts if the previous binary cannot be
    // preserved: a switch with no rollback target must never proceed.
    string stable = Path.build_filename(this.root_zone, CORE_BINARY);
    string? prev_name = previous_core_name(stable);
    if (prev_name == null) {
        Log.err("ota", "cannot preserve previous core; aborting switch");
        FileUtils.unlink(new_file);
        return CoreApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // The marker MUST land before the repoint: it is the rollback trigger on a
    // DEGRADED restart. Without it the switch is not safe to activate.
    if (!write_marker(prev_name)) {
        Log.err("ota", "cannot write core-switch marker; aborting switch");
        FileUtils.unlink(new_file);
        return CoreApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // Repoint is the commit step. If it fails the switch did not take effect;
    // remove the marker (so it is not mistaken for a pending switch) and the
    // installed file, leaving the current binary active. The caller treats any
    // non-APPLIED outcome as "no self-shutdown".
    if (!repoint(stable, Path.get_basename(new_file))) {
        Log.err("ota", "core repoint failed; aborting switch");
        FileUtils.unlink(Path.build_filename(this.root_zone, CORE_MARKER));
        FileUtils.unlink(new_file);
        return CoreApplyOutcome.REJECTED_BAD_HASH;
    }
    Log.ok("ota", "core updated -> " + Path.get_basename(new_file));
    return CoreApplyOutcome.APPLIED;
}

public bool core_switch_pending() {
    return FileUtils.test(
        Path.build_filename(this.root_zone, CORE_MARKER), FileTest.EXISTS);
}

// Confirm a successful core switch: clear the marker and GC the previous file.
// The previous file is GC'd ONLY when the launch path no longer points at it
// (the switch took effect). If stable still resolves to prev_name — power was
// lost between writing the marker and repointing — the previous file IS the
// active binary and must be kept, or stable becomes a dangling symlink.
// atomic-apply-rollback "Ready restart confirms the switch" / "Power-loss".
public void confirm_core_switch() {
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
    string stable = Path.build_filename(this.root_zone, CORE_BINARY);
    string? prev_name = read_marker();
    FileUtils.unlink(marker);
    if (prev_name == null || prev_name == "") {
        return;
    }
    string? current = read_link(stable);
    if (current != null && current != prev_name) {
        FileUtils.unlink(
            Path.build_filename(this.root_zone, prev_name));
    }
}

// Roll back a failed core switch: repoint the launch path back to the previous
// file and clear the marker. Caller self-shuts down so init restarts the
// previous binary. atomic-apply-rollback "Degraded restart rolls back".
public void rollback_core_switch() {
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
    string? prev_name = read_marker();
    FileUtils.unlink(marker);
    if (prev_name != null && prev_name != "") {
        repoint(Path.build_filename(this.root_zone, CORE_BINARY),
                prev_name);
        Log.ok("ota", "core rolled back -> " + prev_name);
    }
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

// Copy src into dst (a root-zone path) as a fresh regular file, fsync it, then
// re-verify its sha256 equals expected_sha on the dst inode. Returns false on
// any IO error or mismatch (dst is removed on failure). TOCTOU-safe: the app
// cannot swap the root-owned dst between the write and the re-verify.
private bool copy_file_verify(
    string src, string dst, string expected_sha) {
    uint8[] data;
    try {
        FileUtils.get_data(src, out data);
    } catch (Error e) {
        return false;
    }
    if (!write_bytes_verify(dst, data)) {
        return false;
    }
    return sha_of(dst) == expected_sha.down();
}

// Write data to dst as a fresh regular file (set_contents replaces a pre-placed
// symlink), fsync via an O_NOFOLLOW fd (refuses a racing symlink back to a
// root file), fchmod 600. Mirrors Status.write_atomic.
private bool write_bytes_verify(string dst, uint8[] data) {
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
    Posix.fchmod(fd, 0600);
    Posix.fsync(fd);
    Posix.close(fd);
    return true;
}

private string? sha_of(string path) {
    try {
        uint8[] data;
        FileUtils.get_data(path, out data);
        return Checksum.compute_for_data(ChecksumType.SHA256, data);
    } catch (Error e) {
        return null;
    }
}

// The content-addressed name of the previous active core file, preserving it
// under voboost-inject-<oldsha> if it is not already content-addressed. Returns
// null if the previous binary cannot be read or durably preserved (so the caller
// aborts the switch rather than installing a new binary with no rollback target).
private string? previous_core_name(string stable) {
    string? target = read_link(stable);
    if (target != null && target.has_prefix(CORE_BINARY + "-")) {
        return target;
    }
    // First update (plain binary): preserve the current bytes under a
    // content-addressed name so rollback has a target. Durable write.
    string? oldsha = sha_of(stable);
    if (oldsha == null) {
        return null;
    }
    string prev = Path.build_filename(
        this.root_zone, CORE_BINARY + "-%s".printf(oldsha));
    if (!FileUtils.test(prev, FileTest.EXISTS)) {
        uint8[] data;
        try {
            FileUtils.get_data(stable, out data);
        } catch (Error e) {
            return null;
        }
        if (!write_bytes_verify(prev, data)) {
            return null;
        }
    }
    return Path.get_basename(prev);
}

// Atomically repoint the stable launch path at `stable` to `target_basename`
// (a content-addressed voboost-inject-<sha> in the same dir): create the symlink
// at a temp name, then rename over `stable`. Returns false if the symlink or the
// rename failed (the caller treats that as a non-apply: the switch did not take
// effect). The running binary's inode persists across the rename; the next exec
// resolves the new target.
private bool repoint(string stable, string target_basename) {
    string tmp = Path.build_filename(this.root_zone, ".ota.core.tmp");
    FileUtils.unlink(tmp);
    try {
        File.new_for_path(tmp).make_symbolic_link(target_basename);
    } catch (Error e) {
        Log.err("ota", "symlink: " + e.message);
        return false;
    }
    if (FileUtils.rename(tmp, stable) != 0) {
        Log.err("ota", "repoint rename failed");
        FileUtils.unlink(tmp);
        return false;
    }
    return true;
}

private string? read_link(string path) {
    try {
        var info = File.new_for_path(path).query_info(
            "standard::symlink-target",
            FileQueryInfoFlags.NOFOLLOW_SYMLINKS);
        // GLib omits standard::symlink-target for a regular file; get_*()
        // would g_critical then, so guard with has_attribute.
        if (!info.has_attribute("standard::symlink-target")) {
            return null;
        }
        return info.get_symlink_target();
    } catch (Error e) {
        return null;
    }
}

// Durably write the core-switch marker naming the previous active file. Returns
// false on any IO failure (the caller aborts the switch: without a marker a
// DEGRADED restart cannot roll back, so the switch must not proceed).
private bool write_marker(string previous_basename) {
    string run_dir = Path.build_filename(this.root_zone, "run");
    DirUtils.create_with_parents(run_dir, 0700);
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
    string tmp = Path.build_filename(run_dir, ".ota.marker.tmp");
    try {
        FileUtils.set_contents(tmp, previous_basename);
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

private string? read_marker() {
    try {
        string contents;
        FileUtils.get_contents(
            Path.build_filename(this.root_zone, CORE_MARKER),
            out contents);
        return contents.strip();
    } catch (Error e) {
        return null;
    }
}

private void cleanup_temps(GenericArray<string> temps) {
    for (uint i = 0; i < temps.length; i++) {
        FileUtils.unlink(temps[i]);
    }
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
