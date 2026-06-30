namespace Voboost {
public class PlanEntry : Object {
public string id { get; construct; }
public bool enabled { get; construct; }
// Opaque agent config, serialized JSON (verbatim from inject.json, or
// "{}" if absent). The daemon never interprets it — it is forwarded to
// the agent via rpc.exports.init parameters.config.
public string config { get; construct; }

public PlanEntry(string id, bool enabled, string config) {
    Object(id: id, enabled: enabled, config: config);
}
}

public class Plan : Object {
public int plan_version { get; set; default = 0; }
// Startup gate value (see daemon-lifecycle). The startup decision is
// taken before the manifest loads (main.vala); kept here for status.
public string startup { get; set; default = ""; }
public bool disable_all { get; set; default = false; }
public GenericArray<PlanEntry> entries { get; private set; }

public Plan() {
    this.entries = new GenericArray<PlanEntry> ();
}
}

// Reads inject.json (untrusted, app-written) and validates each entry
// against the verified Manifest: id must be whitelisted and config must be
// within the size bound. config is OPAQUE — the daemon does not inspect it
// (no parameter schema); it is stored verbatim and forwarded to the agent.
// process/sha256 are NEVER read from the plan. The size bounds are a
// memory/DoS guard, not schema validation. See injection-control
// "Injection plan validation" + "Opaque config delivery".
public class PlanReader : Object {
public Manifest manifest { get; construct; }

// Per-agent config cap and whole-file cap (memory/DoS guard).
public const int MAX_CONFIG_BYTES = 65536;             // 64 KiB
public const int MAX_PLAN_BYTES = 1048576;             // 1 MiB

public PlanReader(Manifest manifest) {
    Object(manifest: manifest);
}

public Plan validate(string json) {
    var plan = new Plan();
    if (json.length > MAX_PLAN_BYTES) {
        Log.err("plan", "inject.json exceeds MAX_PLAN_BYTES");
        return plan;
    }
    var parser = new Json.Parser();
    try {
        parser.load_from_data(json, -1);
    } catch (Error e) {
        return plan;
    }

    var root = parser.get_root();
    if (root == null || root.get_node_type() != Json.NodeType.OBJECT) {
        return plan;
    }
    var obj = root.get_object();
    plan.plan_version = safe_int(obj, "version", 0);
    plan.startup = safe_string(obj, "startup", "");
    plan.disable_all = safe_bool(obj, "disabled", false);

    if (!obj.has_member("agents")) {
        return plan;
    }
    var agents_node = obj.get_member("agents");
    if (agents_node.get_node_type() != Json.NodeType.ARRAY) {
        return plan;
    }
    var arr = agents_node.get_array();
    // Track seen ids to reject duplicates (a duplicate would cause double
    // safety-budget consumption and duplicate status entries).
    var seen = new HashTable<string, bool> (str_hash, str_equal);
    for (uint i = 0; i < arr.get_length(); i++) {
        var elem = arr.get_element(i);
        if (elem == null ||
            elem.get_node_type() != Json.NodeType.OBJECT) {
            continue;
        }
        var e = elem.get_object();
        string id = safe_string(e, "id");
        if (id == "") {
            continue;
        }
        if (seen.lookup(id)) {
            Log.err("plan", "rejected duplicate agent id " + id);
            continue;
        }
        if (this.manifest.find(id) == null) {
            Log.err("plan", "rejected unknown agent id " + id);
            continue;
        }
        seen.insert(id, true);
        bool enabled = safe_bool(e, "enabled", false);
        string config = "{}";
        if (e.has_member("config")) {
            config = node_to_json(e.get_member("config"));
        }
        if (config.length > MAX_CONFIG_BYTES) {
            Log.err("plan", "rejected oversized config for " + id);
            continue;
        }
        plan.entries.add(new PlanEntry(id, enabled, config));
    }
    return plan;
}

// Serialize an opaque JSON node back to a compact string for forwarding.
private string node_to_json(Json.Node node) {
    var gen = new Json.Generator();
    gen.set_root(node);
    return gen.to_data(null);
}

// Type-safe JSON field accessors for untrusted input. Without these,
// get_string_member / get_int_member / get_boolean_member crash on
// type mismatches (they return null and Vala dereferences it).
// inject.json is app-written and untrusted — a malformed field
// (e.g. "version": "oops") must not crash the daemon.

private static string safe_string(Json.Object obj, string name,
                                  string def = "") {
    if (!obj.has_member(name)) {
        return def;
    }
    var n = obj.get_member(name);
    if (n.get_node_type() == Json.NodeType.VALUE &&
        n.get_value_type() == typeof(string)) {
        return n.get_string();
    }
    return def;
}

private static int safe_int(Json.Object obj, string name, int def = 0) {
    if (!obj.has_member(name)) {
        return def;
    }
    var n = obj.get_member(name);
    if (n.get_node_type() == Json.NodeType.VALUE &&
        n.get_value_type() == typeof(int64)) {
        return (int) n.get_int();
    }
    return def;
}

private static bool safe_bool(Json.Object obj, string name,
                              bool def = false) {
    if (!obj.has_member(name)) {
        return def;
    }
    var n = obj.get_member(name);
    if (n.get_node_type() == Json.NodeType.VALUE &&
        n.get_value_type() == typeof(bool)) {
        return n.get_boolean();
    }
    return def;
}
}
}
