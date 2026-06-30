## ADDED Requirements

### Requirement: Streaming APK entry inflate

The daemon's APK ZIP reader SHALL inflate deflated entries (method 8) via a
streaming converter (`GConverterInputStream` over a `MemoryInputStream` with a
`GZlibDecompressor` in RAW format) reading in fixed-size chunks, so that the
peak memory of the inflate is bounded by the entry's uncompressed size plus
one chunk, not by `MAX_APK_BYTES`. The output buffer SHALL be sized at the
entry's stored uncompressed size; a zero or lying hint SHALL fall back to a
growable buffer still capped at `MAX_APK_BYTES`.

Context: the previous `ZlibDecompressor.convert` retry loop allocated a fresh
output buffer up to `MAX_APK_BYTES` (64 MiB) per iteration. The APK is
signature-verified before apply and the bound is 64 MiB, so the old code was
acceptable; streaming removes the per-iteration peak entirely as
defense-in-depth (R4-INJ-01).

#### Scenario: Deflated entry with a trustworthy uncompressed size
- **WHEN** the ZIP reader extracts a method-8 entry whose stored
  `uncomp_size` is positive and matches the stream
- **THEN** the inflate allocates a buffer of `uncomp_size` bytes and reads
  the compressed slice in 64 KiB chunks through the streaming converter
- **AND** the peak memory is `uncomp_size + 64 KiB`, never `MAX_APK_BYTES`

#### Scenario: Deflated entry with a zero or lying uncompressed size
- **WHEN** the stored `uncomp_size` is zero or smaller than the actual
  inflated output
- **THEN** the inflate grows the output buffer (doubling) and retries, still
  capped at `MAX_APK_BYTES`
- **AND** returns false if the grown buffer would exceed `MAX_APK_BYTES`
