namespace Voboost {

// An agent is always JavaScript, run on frida-core's QuickJS runtime via a
// per-process session script. There is no native agent kind: every shipped
// agent hooks Java methods through frida-java-bridge, which runs on QuickJS,
// and the frida-gum native C API has no bridge to Java/ART methods.
public class AgentDef : Object {
public string id { get; construct; }
public string channel { get; construct; }
public string file { get; construct; }
public string sha256 { get; construct; }
public string process { get; construct; }
// Per-agent boot gate. When true, defer injection until
// sys.boot_completed=1; default false = inject as soon as the target is
// reachable (earliest). See daemon-lifecycle "Per-agent boot-readiness".
public bool requires_boot { get; construct; }

public AgentDef(string id, string channel, string file, string sha256,
                string process, bool requires_boot) {
    Object(id: id, channel: channel, file: file, sha256: sha256,
           process: process, requires_boot: requires_boot);
}
}

// Holds the manifest ONLY after its detached signature is verified against
// the embedded key. An agent's process and kind come from here, never from
// the plan. parse () resets all fields up front; on unparseable JSON it
// returns false leaving a clean (empty) state. See trust-verification spec.
public class Manifest : Object {
public int manifest_version { get; private set; default = 0; }
public string daemon_version { get; private set; default = ""; }
public GenericArray<AgentDef> agents { get; private set; }

public Manifest() {
    this.agents = new GenericArray<AgentDef> ();
}

// Verify signature first; parse only on success. Returns false on a
// bad signature or malformed JSON, always leaving the manifest in a
// clean (empty) state on failure.
public bool load_verified(uint8[] json_bytes, uint8[] signature,
                          TrustStore trust) {
    if (!trust.verify_signature(json_bytes, signature)) {
        return false;
    }
    return parse((string) json_bytes);
}

private bool parse(string json) {
    // Reset all fields before attempting to parse; this guarantees no
    // partial state is visible after a malformed-but-signed manifest.
    this.manifest_version = 0;
    this.daemon_version = "";
    this.agents = new GenericArray<AgentDef> ();

    var parser = new Json.Parser();
    try {
        parser.load_from_data(json, -1);
    } catch (Error e) {
        return false;
    }

    var root = parser.get_root();
    if (root == null || root.get_node_type() != Json.NodeType.OBJECT) {
        return false;
    }
    var obj = root.get_object();

    this.manifest_version = safe_int(obj, "version", 0);
    this.daemon_version = safe_string(obj, "daemon", "");

    if (!obj.has_member("agents")) {
        return true;
    }
    var agents_node = obj.get_member("agents");
    if (agents_node.get_node_type() != Json.NodeType.ARRAY) {
        return true;
    }
    var arr = agents_node.get_array();
    // Track seen ids to skip duplicates (mirrors PlanReader.validate): a
    // signed manifest with two agents sharing an id would make find () and
    // the proc_map silently pick the first, dropping the second agent's
    // payload entirely. The manifest is trusted/signed, so this is a
    // release-build guard, not an attacker surface — but a duplicate must
    // not pass silently.
    var seen = new HashTable<string, bool> (str_hash, str_equal);
    for (uint i = 0; i < arr.get_length(); i++) {
        var elem = arr.get_element(i);
        if (elem == null ||
            elem.get_node_type() != Json.NodeType.OBJECT) {
            continue;
        }
        var a = elem.get_object();
        string id = safe_string(a, "id");
        if (id == "" || !a.has_member("sha256")
            || !a.has_member("process")
            || !a.has_member("file")) {
            Log.err("manifest",
                    "skipping agent with missing required fields");
            continue;
        }
        if (seen.lookup(id)) {
            Log.err("manifest", "skipping duplicate agent id " + id);
            continue;
        }
        seen.insert(id, true);
        this.agents.add(new AgentDef(
                            id,
                            safe_string(a, "channel", "agents"),
                            safe_string(a, "file"),
                            safe_string(a, "sha256"),
                            safe_string(a, "process"),
                            safe_bool(a, "boot", false)));
    }
    return true;
}

public AgentDef? find(string id) {
    for (uint i = 0; i < this.agents.length; i++) {
        if (this.agents[i].id == id) {
            return this.agents[i];
        }
    }
    return null;
}

// Type-safe JSON accessors — defense-in-depth for signed content.
// A signer producing malformed field types would crash the daemon
// without these (same pattern as PlanReader for untrusted input).

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
