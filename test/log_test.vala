using Voboost;

// Log tests write to isolated temp directories to avoid cross-test
// interference and to leave no artefacts behind.

private string fresh_dir(string label) {
    string dir = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-log-test-%s-%d".printf(label, Posix.getpid()));
    DirUtils.create_with_parents(dir, 0700);
    return dir;
}

private void cleanup(string dir) {
    // Best-effort: remove log files then the directory. Close the
    // enumerator before rmdir — an open GFileEnumerator holds the dirfd,
    // so Posix.rmdir can fail (EBUSY on macOS) and leak the test dir in
    // $TMPDIR. Mirrors Log.prune's finally-close.
    try {
        var d = File.new_for_path(dir);
        var en = d.enumerate_children(
            "standard::name", FileQueryInfoFlags.NONE, null);
        try {
            FileInfo? info = null;
            while ((info = en.next_file(null)) != null) {
                FileUtils.unlink(
                    Path.build_filename(dir, info.get_name()));
            }
        } finally {
            try {
                en.close(null);
            } catch (Error close_err) {
            }
        }
    } catch (Error e) {
    }
    Posix.rmdir(dir);
}

// Read a whole file without an unhandled-FileError warning; a missing log
// file in a test is a fatal setup error (matches the read_or_fail helpers
// in the other test suites — the project builds with 0 valac warnings).
string read_or_fail(string path) {
    string contents;
    try {
        FileUtils.get_contents(path, out contents);
    } catch (FileError e) {
        error("read %s: %s", path, e.message);
    }
    return contents;
}

void test_log_format() {
    string dir = fresh_dir("fmt");
    var log = new Voboost.Log(dir);
    log.write(LogTag.STAR, "src", "test message");

    string today = new DateTime.now_local().format("%Y-%m-%d");
    string path = Path.build_filename(
        dir, "inject-" + today + ".log");
    string content = read_or_fail(path);
    // Shared format: yyyy-MM-dd HH:mm:ss.SSS [*] src: test message
    assert(content.contains(" [*] src: test message"));

    cleanup(dir);
}

void test_log_tags() {
    string dir = fresh_dir("tags");
    var log = new Voboost.Log(dir);
    log.write(LogTag.MINUS, "s", "err");
    log.write(LogTag.PLUS, "s", "ok");
    log.write(LogTag.STAR, "s", "info");

    string today = new DateTime.now_local().format("%Y-%m-%d");
    string path = Path.build_filename(
        dir, "inject-" + today + ".log");
    string content = read_or_fail(path);
    assert(content.contains("[-]"));
    assert(content.contains("[+]"));
    assert(content.contains("[*]"));

    cleanup(dir);
}

void test_log_file_permissions() {
    string dir = fresh_dir("perm");
    var log = new Voboost.Log(dir);
    log.write(LogTag.STAR, "s", "check");

    string today = new DateTime.now_local().format("%Y-%m-%d");
    string path = Path.build_filename(
        dir, "inject-" + today + ".log");
    Posix.Stat st;
    assert(Posix.stat(path, out st) == 0);
    // Log file must be owner-read/write only (0600).
    assert((st.st_mode & 0777) == 0600);

    cleanup(dir);
}

void test_log_creates_directory() {
    string dir = Path.build_filename(
        Environment.get_tmp_dir(),
        "vob-log-mkdir-%d".printf(Posix.getpid()));
    // Directory does not exist yet.
    assert(!FileUtils.test(dir, FileTest.EXISTS));
    var log = new Voboost.Log(dir);
    log.write(LogTag.STAR, "s", "created");
    // Directory must now exist.
    assert(FileUtils.test(dir, FileTest.IS_DIR));

    cleanup(dir);
}

public static int main(string[] args) {
    Test.init(ref args);
    Test.add_func("/log/format", test_log_format);
    Test.add_func("/log/tags", test_log_tags);
    Test.add_func("/log/permissions", test_log_file_permissions);
    Test.add_func("/log/creates-dir", test_log_creates_directory);
    return Test.run();
}
