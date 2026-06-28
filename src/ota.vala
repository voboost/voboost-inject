namespace Voboost {
// One entry of a verified release manifest (release-manifest spec). Held only
// after the manifest's detached signature verifies against the embedded key and
// its size/entry bounds hold. The release manifest lists APKs (one core entry
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

// Find the core-channel entry matching a basename. The release manifest lists
// APKs; the core entry is the daemon APK. Non-core entries never satisfy a
// core lookup even if their path collides (defense-in-depth, release-manifest
// spec).
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

// Result of Ota.apply_core_apk_update. APPLIED means the caller MUST perform a
// clean self-shutdown so Android init restarts the service on the new binary;
// the running binary is never replaced in place (it is renamed aside to .prev
// and the new binary installed at the same pathname). Every REJECTED_* leaves
// the current binary active and unchanged.
public enum CoreApplyOutcome {
    APPLIED,
    REJECTED_NO_APK,
    REJECTED_BAD_MANIFEST,
    REJECTED_BAD_BINARY,
    // The previous binary could not be preserved for rollback (IO error during
    // the rename aside); the switch is aborted so a bad new binary is never
    // installed without a rollback target.
    REJECTED_NO_ROLLBACK;
}

// APK-level core self-update (ota-core-selfupdate change). Frida-free file-
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
//   run/core-switch-pending              marker set after a self-replace
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
// Bounds for the APK ZIP reader (design D5): a pathologically large archive
// must not exhaust memory. The daemon APK is tens of MB; 256 MB is a generous
// upper bound that rejects anything unreasonable before parsing.
public const int64 MAX_APK_BYTES = 268435456;
public const int MAX_APK_ENTRIES = 65536;

// Fixed names. OTA applies are serialized on the daemon's single-threaded
// GMainLoop, so no two applies race for the same temp.
private const string MANIFEST = "manifest.json";
private const string MANIFEST_SIG = "manifest.sig";
private const string MANIFEST_PREV = "manifest.json.prev";
private const string MANIFEST_SIG_PREV = "manifest.sig.prev";
private const string CORE_BINARY = "voboost-inject";
private const string CORE_PREV = "voboost-inject.prev";
private const string CORE_MARKER = "run/core-switch-pending";
// The producer's "a verified daemon APK is staged" marker, created last in
// the app-zone staging/ dir. Lives in the app zone but the daemon (root)
// owns its lifecycle as the consumer. Single-use (design D4).
private const string CORE_UPDATE_READY = "core-update-ready";
// The fixed asset path of the daemon ELF inside the APK (design D5 open
// question, pinned by the daemon APK build). The ZIP reader locates it by
// this name; the build MUST place the raw ELF here.
private const string APK_BINARY_ENTRY = "assets/voboost-inject";
private const string APK_MANIFEST_ENTRY = "assets/manifest.json";
private const string APK_MANIFEST_SIG_ENTRY = "assets/manifest.sig";

public Ota(string root_zone, TrustStore trust) {
    Object(root_zone: root_zone, trust: trust);
}

// True when the producer signalled a verified staged daemon APK. The daemon
// applies only while this is present (ota-core-selfupdate staging contract)
// and consumes it BEFORE the apply, so a successful self-replace + init
// restart is not re-applied on every boot — which would crash-loop the core
// plane via self-shutdown + init restart.
public bool core_update_ready(string staging_dir) {
    return FileUtils.test(
        Path.build_filename(staging_dir, CORE_UPDATE_READY),
        FileTest.EXISTS);
}

// Remove the marker. Called BEFORE the apply (design D4: single-use, consume
// first). Best-effort: an unlink failure only means the next boot re-checks
// core_update_ready and (for an identical verified APK) the apply runs again
// — the core plane consumes it before its self-shutdown, where it must
// succeed for the loop to be broken, and it does (same dir just read, root
// perms).
public void consume_core_update_ready(string staging_dir) {
    FileUtils.unlink(
        Path.build_filename(staging_dir, CORE_UPDATE_READY));
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

// Apply a staged core APK update (ota-core-selfupdate). The marker is
// consumed FIRST (single-use, design D4), then the staged APK is found, its
// embedded manifest.json+.sig re-verified against EMBEDDED_PUBKEY (design
// D1), the daemon ELF binary extracted from the APK (design D5), and the
// running binary atomically self-replaced (rename aside to .prev, install
// the new binary at the same pathname, design D2). The core-switch-pending
// marker is written and the caller self-shuts down so init restarts the new
// binary. On any REJECTED_* the current binary stays active (the marker is
// already consumed — the bad APK is dropped, not retried every boot).
public CoreApplyOutcome apply_core_apk_update(string staging_dir) {
    // Consume the marker BEFORE the apply (design D4): a successful
    // self-replace + self-shutdown + init-restart must not re-apply the same
    // APK on every boot (crash-loop). The marker is the trigger, not part of
    // the verified set, so consuming it first is safe.
    consume_core_update_ready(staging_dir);
    string apk = find_staged_apk(staging_dir);
    if (apk == null) {
        Log.err("ota", "no staged daemon APK in staging/");
        return CoreApplyOutcome.REJECTED_NO_APK;
    }
    // DoS guard: reject an oversized APK before reading it into memory.
    Posix.Stat st;
    if (Posix.stat(apk, out st) != 0 || st.st_size > MAX_APK_BYTES) {
        Log.err("ota", "staged APK oversize/absent");
        return CoreApplyOutcome.REJECTED_NO_APK;
    }
    uint8[] apk_bytes;
    try {
        FileUtils.get_data(apk, out apk_bytes);
    } catch (Error e) {
        Log.err("ota", "staged APK read: " + e.message);
        return CoreApplyOutcome.REJECTED_NO_APK;
    }
    if (apk_bytes.length > MAX_APK_BYTES) {
        Log.err("ota", "staged APK grew past bound");
        return CoreApplyOutcome.REJECTED_NO_APK;
    }
    // Re-verify the APK's embedded manifest against EMBEDDED_PUBKEY (design
    // D1). The APK's own Android signature is NOT verified here.
    uint8[] m_bytes = new uint8[0];
    uint8[] s_bytes = new uint8[0];
    if (!extract_apk_entry(apk_bytes, APK_MANIFEST_ENTRY, out m_bytes)) {
        Log.err("ota", "staged APK missing embedded manifest entry");
        return CoreApplyOutcome.REJECTED_BAD_MANIFEST;
    }
    if (!extract_apk_entry(
            apk_bytes, APK_MANIFEST_SIG_ENTRY, out s_bytes)) {
        Log.err("ota", "staged APK missing embedded manifest.sig entry");
        return CoreApplyOutcome.REJECTED_BAD_MANIFEST;
    }
    var embedded = new Manifest();
    if (!embedded.load_verified(m_bytes, s_bytes, this.trust)) {
        Log.err("ota", "staged APK embedded manifest rejected");
        return CoreApplyOutcome.REJECTED_BAD_MANIFEST;
    }
    // Extract the daemon ELF binary from the APK.
    uint8[] bin_bytes;
    if (!extract_apk_entry(apk_bytes, APK_BINARY_ENTRY, out bin_bytes)) {
        Log.err("ota", "staged APK missing daemon binary entry");
        return CoreApplyOutcome.REJECTED_BAD_BINARY;
    }
    if (bin_bytes.length == 0) {
        Log.err("ota", "staged APK daemon binary is empty");
        return CoreApplyOutcome.REJECTED_BAD_BINARY;
    }
    // Install the new binary as a root-zone temp, fsync, fchmod 0755.
    string tmp = Path.build_filename(this.root_zone, ".ota.core.tmp");
    if (!write_bytes_exec(tmp, bin_bytes)) {
        Log.err("ota", "core install write failed");
        FileUtils.unlink(tmp);
        return CoreApplyOutcome.REJECTED_BAD_BINARY;
    }
    // Preserve the previous binary as .prev for rollback (design D3). rename
    // of the running binary is safe on Linux/Android: the running process
    // keeps its inode until exit. Aborts if the previous binary cannot be
    // preserved: a switch with no rollback target must never proceed.
    string stable = Path.build_filename(this.root_zone, CORE_BINARY);
    string prev = Path.build_filename(this.root_zone, CORE_PREV);
    if (!preserve_previous_binary(stable, prev)) {
        Log.err("ota", "cannot preserve previous core; aborting switch");
        FileUtils.unlink(tmp);
        return CoreApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // The marker MUST land before the new binary takes the pathname: it is
    // the rollback trigger on a DEGRADED restart. Without it the switch is
    // not safe to activate.
    if (!write_marker()) {
        Log.err("ota", "cannot write core-switch marker; aborting switch");
        restore_previous_binary(stable, prev);
        FileUtils.unlink(tmp);
        return CoreApplyOutcome.REJECTED_NO_ROLLBACK;
    }
    // Install the new binary at the stable pathname (atomic rename). This is
    // the commit step: the running process keeps its old inode; the next exec
    // (by init after the self-shutdown) resolves the new binary.
    if (FileUtils.rename(tmp, stable) != 0) {
        Log.err("ota", "core install rename failed; aborting switch");
        FileUtils.unlink(Path.build_filename(this.root_zone, CORE_MARKER));
        restore_previous_binary(stable, prev);
        FileUtils.unlink(tmp);
        return CoreApplyOutcome.REJECTED_BAD_BINARY;
    }
    Log.ok("ota", "core self-updated -> " + stable);
    return CoreApplyOutcome.APPLIED;
}

public bool core_switch_pending() {
    return FileUtils.test(
        Path.build_filename(this.root_zone, CORE_MARKER), FileTest.EXISTS);
}

// Confirm a successful core switch: clear the marker and remove .prev (the
// previous binary is no longer needed). atomic-apply-rollback "Ready restart
// confirms the switch".
public void confirm_core_switch() {
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
    FileUtils.unlink(marker);
    FileUtils.unlink(Path.build_filename(this.root_zone, CORE_PREV));
}

// Roll back a failed core switch: restore .prev over the bad new binary and
// clear the marker. Caller self-shuts down so init restarts the previous
// binary. atomic-apply-rollback "Degraded restart rolls back". If .prev is
// absent (first-update edge, or power-loss between the rename and the marker
// write) the daemon cannot restore and stays DEGRADED rather than exec a
// known-bad binary with no rollback target.
public bool rollback_core_switch() {
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
    FileUtils.unlink(marker);
    string stable = Path.build_filename(this.root_zone, CORE_BINARY);
    string prev = Path.build_filename(this.root_zone, CORE_PREV);
    if (!FileUtils.test(prev, FileTest.EXISTS)) {
        Log.err("ota", "no .prev rollback target; staying DEGRADED");
        return false;
    }
    // rename .prev over the bad new binary (atomic on one filesystem).
    if (FileUtils.rename(prev, stable) != 0) {
        Log.err("ota", "rollback rename failed");
        return false;
    }
    Log.ok("ota", "core rolled back -> " + stable);
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

// Find the staged daemon APK in staging/. The producer stages it under a
// fixed name; return its path or null. (The producer contract: exactly one
// daemon APK named voboost-inject.apk in staging/.)
private string? find_staged_apk(string staging_dir) {
    string apk = Path.build_filename(staging_dir, "voboost-inject.apk");
    if (FileUtils.test(apk, FileTest.EXISTS)) {
        return apk;
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

// Durably write the core-switch marker. Returns false on any IO failure (the
// caller aborts the switch: without a marker a DEGRADED restart cannot roll
// back, so the switch must not proceed).
private bool write_marker() {
    string run_dir = Path.build_filename(this.root_zone, "run");
    DirUtils.create_with_parents(run_dir, 0700);
    string marker = Path.build_filename(this.root_zone, CORE_MARKER);
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

// --- minimal ZIP reader (design D5) ------------------------------------
// Parses the ZIP central directory to locate a named entry, then reads its
// local header for the data offset and compression method. Method 0 (stored)
// returns the bytes verbatim; method 8 (deflate) inflates via
// ZlibDecompressor (RAW format, no zlib header). Bounded by MAX_APK_BYTES /
// MAX_APK_ENTRIES. Only the requested named entry is ever extracted.

// Extract a named entry from an in-memory APK (ZIP) archive into `out data`.
// Returns false on any parse/decompress error or if the entry is absent.
// Static: pure function of its inputs (no instance state), so tests can call
// it directly without constructing an Ota.
public static bool extract_apk_entry(uint8[] apk, string name,
                                     out uint8[] data) {
    data = new uint8[0];
    // Locate the End-of-Central-Directory record (EOCD): a 22-byte record
    // with signature 0x06054b50, possibly followed by a variable-length
    // comment. Scan from the end of the archive backwards (bounded).
    if (apk.length < 22) {
        return false;
    }
    int eocd = -1;
    int scan_from = apk.length - 22;
    int scan_to = apk.length - 65557;  // max comment is 65535 bytes
    if (scan_to < 0) {
        scan_to = 0;
    }
    for (int i = scan_from; i >= scan_to; i--) {
        if (apk[i] == 0x50 && apk[i + 1] == 0x4b
            && apk[i + 2] == 0x05 && apk[i + 3] == 0x06) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) {
        return false;
    }
    int cd_entries = (int) read_le16(apk, eocd + 10);
    int cd_size = (int) read_le32(apk, eocd + 12);
    int cd_offset = (int) read_le32(apk, eocd + 16);
    if (cd_entries > MAX_APK_ENTRIES || cd_offset < 0
        || cd_offset + cd_size > apk.length) {
        return false;
    }
    // Walk the central directory to find the named entry.
    int p = cd_offset;
    for (int i = 0; i < cd_entries; i++) {
        if (p + 46 > apk.length) {
            return false;
        }
        if (apk[p] != 0x50 || apk[p + 1] != 0x4b
            || apk[p + 2] != 0x01 || apk[p + 3] != 0x02) {
            return false;  // not a central-file header
        }
        int method = (int) read_le16(apk, p + 10);
        int comp_size = (int) read_le32(apk, p + 20);
        int uncomp_size = (int) read_le32(apk, p + 24);
        int name_len = (int) read_le16(apk, p + 28);
        int extra_len = (int) read_le16(apk, p + 30);
        int comment_len = (int) read_le16(apk, p + 32);
        int local_offset = (int) read_le32(apk, p + 42);
        if (p + 46 + name_len + extra_len + comment_len > apk.length) {
            return false;
        }
        // ZIP filenames are NOT NUL-terminated in the archive; copy the
        // slice into a NUL-terminated buffer before the (string) cast.
        int nstart = p + 46;
        var name_buf = new uint8[name_len + 1];
        Posix.memcpy(name_buf, &apk[nstart], name_len);
        name_buf[name_len] = 0;
        string entry_name = (string) name_buf;
        if (entry_name == name) {
            return read_local_entry(
                apk, local_offset, method, comp_size, uncomp_size,
                out data);
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    return false;  // entry not found
}

// Read a local file header at `offset` and extract the entry data. Static:
// pure function of its inputs (called from the static extract_apk_entry).
private static bool read_local_entry(uint8[] apk, int offset,
                                     int method, int comp_size,
                                     int uncomp_size, out uint8[] data) {
    data = new uint8[0];
    if (offset < 0 || offset + 30 > apk.length) {
        return false;
    }
    if (apk[offset] != 0x50 || apk[offset + 1] != 0x4b
        || apk[offset + 2] != 0x03 || apk[offset + 3] != 0x04) {
        return false;  // not a local file header
    }
    int name_len = (int) read_le16(apk, offset + 26);
    int extra_len = (int) read_le16(apk, offset + 28);
    int data_off = offset + 30 + name_len + extra_len;
    if (data_off < 0 || data_off + comp_size > apk.length) {
        return false;
    }
    int dend = data_off + comp_size;
    if (method == 0) {
        // Stored (no compression): the compressed size equals the
        // uncompressed size; copy verbatim via slice.
        uint8[] slice = apk[data_off : dend];
        data = new uint8[slice.length];
        Posix.memcpy(data, slice, slice.length);
        return true;
    }
    if (method == 8) {
        // Deflate (raw, no zlib header): inflate via ZlibDecompressor.
        uint8[] comp = apk[data_off : dend];
        return inflate_raw(comp, uncomp_size, out data);
    }
    return false;  // unsupported method
}

// Inflate a raw deflate stream (no zlib header) into `out data`. Uses
// ZlibDecompressor with ZlibCompressorFormat.RAW. The uncompressed size is a
// hint; the whole compressed buffer is fed to the converter at once (deflate
// streams in an APK are small relative to the APK bound) and the output
// buffer is grown if the hint was too small.
private static bool inflate_raw(uint8[] comp, int64 uncomp_size,
                                out uint8[] data) {
    data = new uint8[0];
    // Allocate generously: the stored uncompressed size is authoritative for
    // well-formed APKs; fall back to a growing buffer if it is zero/lying.
    size_t out_cap = (size_t) (uncomp_size > 0
                               ? uncomp_size : comp.length * 4);
    if (out_cap < 64) {
        out_cap = 64;
    }
    if (out_cap > MAX_APK_BYTES) {
        return false;
    }
    // A converter is single-use; retry with a fresh one + a bigger buffer if
    // the hint was too small.
    while (true) {
        var dec = new ZlibDecompressor(ZlibCompressorFormat.RAW);
        var out_buf = new uint8[out_cap];
        size_t bytes_read = 0;
        size_t bytes_written = 0;
        try {
            var res = dec.convert(comp, out_buf, ConverterFlags.NONE,
                                  out bytes_read, out bytes_written);
            if (res == ConverterResult.FINISHED
                || (bytes_read == comp.length && bytes_written > 0)) {
                data = out_buf[0 : bytes_written];
                return true;
            }
        } catch (Error e) {
            return false;
        }
        // Not finished and not all input consumed: the output buffer was too
        // small. Grow and retry with a fresh converter.
        if (out_cap * 2 > MAX_APK_BYTES) {
            return false;
        }
        out_cap *= 2;
    }
}

private static int read_le16(uint8[] b, int off) {
    return (int) b[off] | ((int) b[off + 1] << 8);
}

private static int read_le32(uint8[] b, int off) {
    return (int) b[off] | ((int) b[off + 1] << 8)
           | ((int) b[off + 2] << 16)
           | ((int) b[off + 3] << 24);
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
