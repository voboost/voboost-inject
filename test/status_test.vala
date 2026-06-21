using Voboost;

// Read a whole file without an unhandled-FileError warning; a missing or
// unreadable file in a test is a fatal setup error.
string read_or_fail(string path) {
    string contents;
    try {
        FileUtils.get_contents(path, out contents);
    } catch (FileError e) {
        error("read %s: %s", path, e.message);
    }
    return contents;
}

void test_serialize_all_states() {
    string path = Path.build_filename(
        Environment.get_tmp_dir(), "vob-status-test.json");
    var st = new Status(path);
    st.manifest_version = 1;
    st.kill_switch = true;
    st.panic_quarantine = true;
    st.set_injection("a", "system_server", InjectionState.ACTIVE);
    st.set_injection("b", "system_server", InjectionState.FAILED);
    st.set_injection("c", "p", InjectionState.SKIPPED_COEXIST);
    st.set_injection("d", "p", InjectionState.WAITING);
    st.set_injection("e", "p", InjectionState.QUARANTINED);

    string json = st.serialize();
    assert(json.contains("\"active\""));
    assert(json.contains("\"failed\""));
    assert(json.contains("\"skipped-coexist\""));
    assert(json.contains("\"waiting\""));
    assert(json.contains("\"quarantined\""));
    assert(json.contains("\"killed\""));
}

void test_atomic_write_and_reread() {
    string path = Path.build_filename(
        Environment.get_tmp_dir(), "vob-status-atomic.json");
    var st = new Status(path);
    st.set_injection("a", "p", InjectionState.ACTIVE);
    try {
        st.write_atomic();
    } catch (Error e) {
        assert_not_reached();
    }
    string back = read_or_fail(path);
    assert(back.contains("\"a\""));
    FileUtils.unlink(path);
}

// Verify that the same agent id in different processes is tracked
// independently (lookup matches by id AND process).
void test_multi_process_same_agent_id() {
    string path = Path.build_filename(
        Environment.get_tmp_dir(), "vob-status-multi.json");
    var st = new Status(path);
    // Same agent id, different processes — both must be tracked.
    st.set_injection("agent-x", "proc-a", InjectionState.ACTIVE);
    st.set_injection("agent-x", "proc-b", InjectionState.FAILED);

    string json = st.serialize();
    assert(json.contains("proc-a"));
    assert(json.contains("proc-b"));
    assert(json.contains("\"active\""));
    assert(json.contains("\"failed\""));

    // Update one process must not overwrite the other.
    st.set_injection("agent-x", "proc-a", InjectionState.WAITING);
    string json2 = st.serialize();
    assert(json2.contains("\"waiting\""));
    assert(json2.contains("\"failed\""));

    FileUtils.unlink(path);
}

// A pre-placed symlink at the fixed temp path (the app zone is
// app-writable) must not route the daemon's root status write at the
// symlink target: set_contents replaces the symlink with a regular file
// and the chmod/fsync open the temp with O_NOFOLLOW. The "root" sentinel
// the symlink points at is left untouched. See app-interface spec
// "A symlink in the app zone cannot redirect the status write".
void test_symlink_at_temp_does_not_follow() {
    string dir = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-status-symlink-%d".printf(Posix.getpid()));
    DirUtils.create_with_parents(dir, 0700);
    string path = Path.build_filename(dir, "inject-status.json");
    string sentinel = Path.build_filename(dir, "sentinel");
    try {
        FileUtils.set_contents(sentinel, "ROOT-SENTINEL");
    } catch (FileError e) {
        assert_not_reached();
    }
    // Attacker pre-places the fixed temp name as a symlink to the sentinel.
    string tmp = Path.build_filename(dir, ".inject-status.tmp");
    FileUtils.unlink(tmp);
    assert(Posix.symlink(sentinel, tmp) == 0);

    var st = new Status(path);
    st.set_injection("a", "p", InjectionState.ACTIVE);
    try {
        st.write_atomic();
    } catch (Error e) {
        assert_not_reached();
    }
    // The sentinel is untouched; the real status path holds the data.
    string scontent = read_or_fail(sentinel);
    assert(scontent == "ROOT-SENTINEL");
    string pcontent = read_or_fail(path);
    assert(pcontent.contains("\"a\""));

    FileUtils.unlink(path);
    FileUtils.unlink(sentinel);
    Posix.rmdir(dir);
}

public static int main(string[] args) {
    Test.init(ref args);
    Test.add_func("/status/serialize-states", test_serialize_all_states);
    Test.add_func("/status/atomic-write", test_atomic_write_and_reread);
    Test.add_func("/status/multi-process", test_multi_process_same_agent_id);
    Test.add_func("/status/symlink-temp", test_symlink_at_temp_does_not_follow);
    return Test.run();
}
