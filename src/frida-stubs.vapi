// Minimal stubs for types referenced by frida-core-1.0.vapi but omitted by
// its generate.py. The public API VAPI declares DeviceManager : HostSessionHub,
// Session : AgentMessageSink, and uses WebRequestHeaderFunc — but those types
// live in frida-core's internal VAPI and frida-base, which pull in the full
// dependency tree (Gum, Xpc, etc.). These stubs let valac resolve the type
// names without requiring the entire frida internals.
[CCode (cprefix = "Frida", lower_case_cprefix = "frida_", cheader_filename = "frida-core.h")]
namespace Frida {
	public interface HostSessionHub : GLib.Object {
	}
	public interface AgentMessageSink : GLib.Object {
	}
	public delegate void WebRequestHeaderFunc (string name, string val);
}
