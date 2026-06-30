using Voboost;

const string FIX = "test/fixtures";

// Read a whole file as bytes without an unhandled-FileError warning; a
// missing fixture in a test is a fatal setup error.
uint8[] read_bytes_or_fail(string path) {
    uint8[] data;
    try {
        FileUtils.get_data(path, out data);
    } catch (FileError e) {
        error("read %s: %s", path, e.message);
    }
    return data;
}

void test_valid_signature_parses() {
    uint8[] json_bytes = read_bytes_or_fail(FIX + "/manifest.json");
    uint8[] sig = read_bytes_or_fail(FIX + "/manifest.sig");

    var trust = new TrustStore();
    var m = new Manifest();
    assert(m.load_verified(json_bytes, sig, trust) == true);
    assert(m.manifest_version == 1);
    assert(m.daemon_version == "1.0.0-beta1");

    var a = m.find("wm-viewport");
    assert(a != null);
    assert(a.process == "system_server");
}

void test_bad_signature_rejected() {
    uint8[] json_bytes = read_bytes_or_fail(FIX + "/manifest.json");
    uint8[] bad = read_bytes_or_fail(FIX + "/manifest-bad.sig");

    var trust = new TrustStore();
    var m = new Manifest();
    assert(m.load_verified(json_bytes, bad, trust) == false);
    assert(m.find("wm-viewport") == null);
}

void test_agent_sha256_matches() {
    uint8[] json_bytes = read_bytes_or_fail(FIX + "/manifest.json");
    uint8[] sig = read_bytes_or_fail(FIX + "/manifest.sig");
    var trust = new TrustStore();
    var m = new Manifest();
    assert(m.load_verified(json_bytes, sig, trust));
    var a = m.find("wm-viewport");
    assert(trust.verify_agent(FIX + "/" + a.file, a.sha256));
}

public static int main(string[] args) {
    Test.init(ref args);
    Test.add_func("/manifest/valid-signature", test_valid_signature_parses);
    Test.add_func("/manifest/bad-signature", test_bad_signature_rejected);
    Test.add_func("/manifest/agent-sha256", test_agent_sha256_matches);
    return Test.run();
}
