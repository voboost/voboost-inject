# Design — injection-control (frida → ptrace)

<!-- Date: 2026-07-23. Records why the daemon's injection model is re-specified
     around libinjector + maps-marker reconciliation, and why the frida-specific
     requirements are removed rather than adapted. -->

## D1 — Why remove the frida requirements rather than modify them

**Choice:** REMOVE "In-process frida-core driving", "Spawn-gating for earliest
injection", "Per-agent runtime routing and per-process lazy runtime", and
"Emulator spawn-gating escape hatch"; ADD ptrace-based requirements.

**Reasoning:** these four describe frida mechanisms with no successor of the same
shape. frida-core is gone; there is no local device, no `create_script`, no
QuickJS, no global spawn-gating, and no frida-gum `g_assert` for the escape hatch
to work around. A MODIFIED requirement keeps the same name and identity — but the
identity here *is* "frida drives injection". Renaming-in-place would leave a spec
whose requirement names lie about the mechanism. REMOVE + ADD makes the mechanism
swap explicit in the delta and keeps each requirement name truthful.

**Rejected — MODIFY "In-process frida-core driving" into a ptrace requirement:**
the name is load-bearing (other specs and reviewers grep for "frida"); keeping it
while gutting the body is worse than a clean remove + add.

## D2 — Why drop the spawn rail entirely

**Choice:** attach-only; no spawn-gating requirement at all.

**Reasoning:** all 16 agents are proven to work in attach mode
(verified across all 16 agents). The one target that looked like it
needed spawn-gating — `system_server` / app-viewport — is a long-lived process the
daemon attaches to, and its `onDisplayChanged` event hook fires for every future
display change regardless of when the daemon started (SS is born on tick ~1088,
before the daemon). Spawn-gating in frida was also *global* (it suspended every
spawned process), which cost a resume path for non-targets; none of that
machinery is worth carrying for a rail no agent needs.

## D3 — Reconciliation is the core new behavior

**Choice:** the daemon reconciles by the real `libimplant.so` path in
`/proc/<pid>/maps`; injected code outlives the daemon.

**Reasoning:** this is the single biggest divergence from frida.
With frida the session died with the daemon, so a restart re-attached and
re-injected. With ptrace+dlopen the implant loads a real file and keeps running
independently, so a daemon restart — crucially including OTA self-update — must
*not* re-inject (that would double-load and could crash the target) and must not
tear hooks down. The marker being a real path (not frida's `memfd:frida-agent
(deleted)`) makes the reconcile check unambiguous. Teardown therefore cannot be a
daemon-exit side effect; it is driven by a "no agents" plan over channel B, where
the agent runtime calls its own `teardown()`.

## D4 — Config delivery moves to channel B, opacity preserved

**Choice:** deliver validated config verbatim by writing the target's channel-B
config file; keep the opacity principle; drop `rpc.exports.init`.

**Reasoning:** frida-RPC is gone, so config can no longer ride a `Script.post`
init call. The design's channel B (a watched `media_rw_data_file`) already exists
for live-update; injection just seeds it and hands the path to `implant_init`.
The opacity invariant (daemon never parses config) is unchanged and stays here;
the file transport mechanics (atomic write-tmp+rename, inotify, SELinux type)
belong to `update-planes`, and the Java-side read belongs to `agent-entry-seam`.
This split keeps one owner per concern and avoids duplicating the channel-B rules
in three specs.

## D5 — pid resolution simplifies without frida

**Choice:** resolve pid purely from `/proc/<pid>/cmdline` `argv[0]`.

**Reasoning:** the frida `enumerate_processes` name match only ever existed
because frida reported the app *label* ("Launcher Stub") instead of the package
id, forcing a `/proc` fallback that did the real work. With frida gone, the
fallback becomes the primary (and only) path, and it already resolves both app
targets (`argv[0]` = package id) and native/system targets (`argv[0]` =
`system_server`). The NUL-handling note is kept but re-stated language-agnostically
(take bytes up to the first NUL) since the daemon is now Rust, not Vala/GLib —
the old `g_strsplit`-on-NUL crash was a GLib-specific footgun, but "don't split on
NUL; `argv[0]` is the leading token" is the durable rule.

## D6 — 32-bit support is now a native-payload consequence

**Choice:** keep the "32-bit target process support" requirement but re-root it in
`native-payload` runtime bitness detection + both-ABI carriage.

**Reasoning:** frida delivered 32-bit reach via a build option (`compat=auto`
embedding `frida-helper-32`). The new mechanism delivers it structurally: the
injector detects bitness per injection and the daemon carries both ABIs of the
implant. Keeping the requirement (rather than removing it) preserves the on-device
invariant — *the daemon must reach 32-bit targets or it is not viable* — while
pointing at the new mechanism. The per-injection detection itself is specified
once, in `native-payload`; here the daemon-level obligation is "carry both ABIs
and pass the matching one".
