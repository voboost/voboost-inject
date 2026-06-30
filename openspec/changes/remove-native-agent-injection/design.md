# Design — remove-native-agent-injection

<!-- Date: 2026-06-30. Records why the native agent injection path is removed
     rather than kept as a forward-looking hook. -->

## D1 — Why remove rather than keep the native kind

**Choice:** delete the `native` agent kind, the `inject_library_blob` path,
the `entrypoint` manifest field, and the per-process lazy-QuickJS optimization,
leaving a single JavaScript-only injection path.

**Reasoning:** every shipped agent hooks Java methods through `Java.use()`
(frida-java-bridge), which runs on QuickJS. The frida-gum native C API only
intercepts native ELF symbols; it has no bridge to Java/ART methods. A native
agent would therefore require reimplementing frida-java-bridge in C (ART
internals, JNI reflection, method patching) — effectively rewriting Frida —
which is out of scope and not planned. A code path that no agent can exercise
and that nothing on the roadmap will exercise is dead weight: it adds manifest
fields, a parallel injection path with its own timeout/sha256 handling, spec
text and scenarios describing behavior nothing exercises, and hedging
comments throughout `frida_controller.vala`. Removing it makes the daemon's
single injection path obvious and shrinks the trust-verification and
injection-control surface area.

**Rejected — keep the `native` kind as a forward-looking hook:** an unused
branch still has to be maintained, tested, and reasoned about in every change
to the injection path. The cost is paid now for a benefit that will not
arrive. If a genuine native-agent need ever appears, the path can be
re-introduced against the then-current codebase with the then-current frida
API; the deleted code would not apply cleanly anyway.

**Rejected — keep `kind` but drop `entrypoint`/`inject_native`:** the `kind`
field exists only to route between js and native. With no native path there is
no routing decision, so `kind` is a vestigial field that the manifest signer
must still populate and the parser must still read. Removing it simplifies the
signed manifest contract.

## D2 — Why drop the per-process lazy-QuickJS optimization

**Choice:** QuickJS is loaded for every target the daemon injects; the
"attach only when the first js agent runs" laziness is removed.

**Reasoning:** the lazy-attach optimization existed solely so a process that
received only `native` agents would never load QuickJS. With no native agents,
every injected target receives at least one js agent, so the lazy path never
avoids the attach in practice. Keeping it would preserve a branch that always
takes the same direction. The attach still happens once per target and is
reused across re-injection (idempotent loaded_agents tracking is unchanged).

## D3 — Why simplify the `process_crashed` handler

**Choice:** the `process_crashed` handler keeps only the "if a session exists,
leave it to `detached`" guard and the `loaded_agents.remove` + `process_lost`
fallthrough. The native-only PID-reuse hedge and the "JS->native migration"
deferral comments are removed.

**Reasoning:** the PID-reuse hedge existed because a native-only target has no
session object to compare against a recycled pid. With every target carrying
a session, the `detached` handler's object-identity guard covers PID reuse for
all targets, and `process_crashed` is only the fallthrough for a crash with no
surviving session. The deferral comment referenced a migration that will not
happen (D1).
