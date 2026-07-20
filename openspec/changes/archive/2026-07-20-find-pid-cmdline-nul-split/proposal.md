## Why

`FridaController.find_pid` scans `/proc/<pid>/cmdline` to resolve Android
app package ids that frida's `enumerate_processes` reports as labels. The
current code splits the cmdline on NUL (`cmdline.split("\0", 2)[0]`) to
extract argv[0]. GLib's `g_strsplit` requires a non-empty delimiter whose
first character is not `'\0'`; passing a NUL byte triggers a CRITICAL
assertion (`g_strsplit: assertion 'delimiter[0] != '\0'' failed`) and then
a segmentation fault, killing the daemon on every `find_pid` call that
reaches the `/proc` fallback.

## What Changes

- Remove the `cmdline.split("\0", 2)[0]` call. `FileUtils.get_contents`
  reads the file into a NUL-terminated C string; the first NUL in
  `/proc/<pid>/cmdline` (which separates argv[0] from argv[1]) becomes
  the string terminator. The returned `cmdline` string already IS argv[0]
  — no split is needed. Compare `cmdline` directly against `process`.

## Impact

- **Crash fix:** the daemon no longer segfaults when `find_pid` reaches
  the `/proc` fallback. Running-target injection (attach) works.
- **Correctness:** argv[0] extraction is unchanged — the Vala string
  already contains exactly argv[0] due to C string NUL-termination.
- **No new surface:** same `/proc` read, same comparison, fewer ops.
