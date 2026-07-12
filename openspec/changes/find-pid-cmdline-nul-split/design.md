## Design

### D1: NUL-split crash root cause

`g_strsplit` (GLib C function behind Vala's `string.split()`) requires
`delimiter[0] != '\0'`. The Vala code `cmdline.split("\0", 2)` compiles to
a call with delimiter `"\0"` (a single NUL byte), which violates this
precondition. GLib logs a CRITICAL assertion and the subsequent memory
access causes SIGSEGV.

### D2: Why removing the split is correct

`FileUtils.get_contents("/proc/<pid>/cmdline", out cmdline)` reads the
file into a heap buffer and returns it as a Vala `string` (C: `char*`
NUL-terminated). `/proc/<pid>/cmdline` format is
`argv[0]\0argv[1]\0...\0` (each argument separated by NUL, double-NUL at
end). The first NUL byte in the buffer becomes the C string terminator.
Therefore the returned `cmdline` string contains exactly `argv[0]` — the
package id for Android app processes. No split is needed; `cmdline` is
already the value to compare.

### D3: Edge case — empty cmdline

Kernel threads and zombie processes may have an empty cmdline (the read
returns 0 bytes, so `cmdline == ""`). The comparison `"" == process`
fails, which is correct — kernel threads are never injection targets.

### D4: Alternative considered

Read the raw bytes with `Posix.read` and manually split on NUL. Rejected:
unnecessary complexity since `FileUtils.get_contents` already gives us
argv[0] for free via C string NUL-termination.
