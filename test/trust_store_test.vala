using Voboost;

const string FIX = "test/fixtures";

void test_verify_valid_signature() {
    uint8[] json_bytes;
    uint8[] sig;
    try {
        FileUtils.get_data(FIX + "/manifest.json", out json_bytes);
        FileUtils.get_data(FIX + "/manifest.sig", out sig);
    } catch (Error e) {
        assert_not_reached();
    }
    var trust = new TrustStore();
    assert(trust.verify_signature(json_bytes, sig) == true);
}

void test_verify_bad_signature() {
    uint8[] json_bytes;
    uint8[] bad;
    try {
        FileUtils.get_data(FIX + "/manifest.json", out json_bytes);
        FileUtils.get_data(FIX + "/manifest-bad.sig", out bad);
    } catch (Error e) {
        assert_not_reached();
    }
    var trust = new TrustStore();
    assert(trust.verify_signature(json_bytes, bad) == false);
}

void test_verify_wrong_data() {
    // Signature is valid for manifest.json, not for arbitrary data.
    uint8[] sig;
    try {
        FileUtils.get_data(FIX + "/manifest.sig", out sig);
    } catch (Error e) {
        assert_not_reached();
    }
    var trust = new TrustStore();
    uint8[] wrong = "not the signed data".data;
    assert(trust.verify_signature(wrong, sig) == false);
}

void test_verify_short_signature_rejected() {
    // A signature shorter than 64 bytes must be rejected outright.
    var trust = new TrustStore();
    uint8[] short_sig = new uint8[32];
    uint8[] msg = "test".data;
    assert(trust.verify_signature(msg, short_sig) == false);
}

void test_sha256_file_known_content() {
    // sha256_file must produce a 64-char hex digest for any file.
    string path = Path.build_filename(
        Environment.get_tmp_dir(), "vob-sha256-test.bin");
    try {
        FileUtils.set_contents(path, "hello");
    } catch (Error e) {
        assert_not_reached();
    }
    var trust = new TrustStore();
    try {
        string hash = trust.sha256_file(path);
        assert(hash.length == 64);
        // SHA256 ("hello") is well-known.
        assert(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e" +
               "1b161e5c1fa7425e73043362938b9824");
    } catch (Error e) {
        assert_not_reached();
    }
    FileUtils.unlink(path);
}

void test_sha256_file_missing() {
    var trust = new TrustStore();
    assert(trust.verify_agent("/nonexistent/file.so", "abc") == false);
}

public static int main(string[] args) {
    Test.init(ref args);
    Test.add_func("/trust/valid-sig", test_verify_valid_signature);
    Test.add_func("/trust/bad-sig", test_verify_bad_signature);
    Test.add_func("/trust/wrong-data", test_verify_wrong_data);
    Test.add_func("/trust/short-sig", test_verify_short_signature_rejected);
    Test.add_func("/trust/sha256-file", test_sha256_file_known_content);
    Test.add_func("/trust/sha256-missing", test_sha256_file_missing);
    return Test.run();
}
