using Voboost;

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

Manifest verified_manifest() {
    uint8[] json_bytes = read_bytes_or_fail("test/fixtures/manifest.json");
    uint8[] sig = read_bytes_or_fail("test/fixtures/manifest.sig");
    var m = new Manifest();
    assert(m.load_verified(json_bytes, sig, new TrustStore()));
    return m;
}

void test_valid_plan_accepted() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"version\":1,\"agents\":[{\"id\":\"wm-viewport\"," +
                  "\"enabled\":true,\"config\":{\"scale\":1.2,\"apps\":[\"a\"]}}]}";
    var plan = reader.validate(json);
    assert(plan.entries.length == 1);
    assert(plan.entries[0].id == "wm-viewport");
    assert(plan.entries[0].enabled == true);
    // config is retained opaque (verbatim JSON), not interpreted.
    assert(plan.entries[0].config.contains("\"scale\""));
    assert(plan.entries[0].config.contains("\"apps\""));
}

void test_unknown_id_rejected() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"agents\":[{\"id\":\"nope\",\"enabled\":true}]}";
    var plan = reader.validate(json);
    assert(plan.entries.length == 0);
}

void test_missing_config_defaults_empty() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"agents\":[{\"id\":\"wm-viewport\",\"enabled\":true}]}";
    var plan = reader.validate(json);
    assert(plan.entries.length == 1);
    assert(plan.entries[0].config == "{}");
}

void test_disable_all_flag() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"disabled\":true,\"agents\":[]}";
    var plan = reader.validate(json);
    assert(plan.disable_all == true);
}

void test_startup_field_parsed() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"startup\":\"none\",\"agents\":[]}";
    var plan = reader.validate(json);
    assert(plan.startup == "none");
}

// Oversized config (> MAX_CONFIG_BYTES) must be rejected (DoS guard).
void test_oversized_config_rejected() {
    var reader = new PlanReader(verified_manifest());
    var big = new StringBuilder();
    for (int i = 0; i < PlanReader.MAX_CONFIG_BYTES + 100; i++) {
        big.append_c('x');
    }
    string json = "{\"agents\":[{\"id\":\"wm-viewport\",\"enabled\":true," +
                  "\"config\":{\"blob\":\"" + big.str + "\"}}]}";
    var plan = reader.validate(json);
    assert(plan.entries.length == 0);
}

// Duplicate agent ids in the plan must be rejected; only the first
// occurrence is kept (prevents double safety-budget consumption).
void test_duplicate_id_rejected() {
    var reader = new PlanReader(verified_manifest());
    string json = "{\"agents\":[" +
                  "{\"id\":\"wm-viewport\",\"enabled\":true}," +
                  "{\"id\":\"wm-viewport\",\"enabled\":true}]}";
    var plan = reader.validate(json);
    assert(plan.entries.length == 1);
}

// Whole-file cap: inject.json exceeding MAX_PLAN_BYTES is rejected
// outright (memory/DoS guard) — parsing never runs, so the plan is empty.
void test_oversized_plan_rejected() {
    var reader = new PlanReader(verified_manifest());
    var big = new StringBuilder();
    string chunk = string.nfill(4096, 'x');
    while (big.str.length <= PlanReader.MAX_PLAN_BYTES) {
        big.append(chunk);
    }
    // Embed the oversized blob as a JSON string value so the file is one
    // JSON value larger than MAX_PLAN_BYTES.
    string json = "{\"version\":1,\"startup\":\"" + big.str + "\"}";
    assert(json.length > PlanReader.MAX_PLAN_BYTES);
    var plan = reader.validate(json);
    assert(plan.entries.length == 0);
    assert(plan.plan_version == 0);
}

// Malformed field types must not crash the daemon — the daemon
// gracefully falls back to defaults (untrusted app input).
void test_wrong_field_types_use_defaults() {
    var reader = new PlanReader(verified_manifest());
    // "version" as string, "disabled" as string, "startup" as int,
    // "enabled" as string — all must fall back without crashing.
    string json = "{\"version\":\"not-an-int\",\"disabled\":\"yes\"," +
                  "\"startup\":123,\"agents\":[" +
                  "{\"id\":\"wm-viewport\",\"enabled\":\"sure\"}]}";
    var plan = reader.validate(json);
    assert(plan.plan_version == 0);
    assert(plan.disable_all == false);
    assert(plan.startup == "");
    // "enabled" is not a bool → defaults to false → entry is skipped
    // because it is not enabled and has no config worth forwarding.
    // But the entry IS created (id matched manifest); enabled=false.
    assert(plan.entries.length == 1);
    assert(plan.entries[0].enabled == false);
}

public static int main(string[] args) {
    // PlanReader logs rejected plan entries (unknown id, duplicate,
    // oversized). Point Log at a temp dir so those writes succeed instead
    // of hitting /data/voboost/logs and spewing to stderr — tests MUST be
    // silent on a successful pass (see test/meson.build header comment).
    Voboost.Log.init(Path.build_filename(
                         Environment.get_tmp_dir(),
                         "vob-plan-test-%d".printf(Posix.getpid())));
    Test.init(ref args);
    Test.add_func("/plan/valid", test_valid_plan_accepted);
    Test.add_func("/plan/unknown-id", test_unknown_id_rejected);
    Test.add_func("/plan/missing-config", test_missing_config_defaults_empty);
    Test.add_func("/plan/disable-all", test_disable_all_flag);
    Test.add_func("/plan/startup", test_startup_field_parsed);
    Test.add_func("/plan/oversized-config", test_oversized_config_rejected);
    Test.add_func("/plan/duplicate-id", test_duplicate_id_rejected);
    Test.add_func("/plan/oversized-plan", test_oversized_plan_rejected);
    Test.add_func("/plan/wrong-types", test_wrong_field_types_use_defaults);
    return Test.run();
}
