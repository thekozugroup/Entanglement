# compress

Round-trippable DEFLATE compression **and** decompression in one tier-1 plugin.
Pure compute: no filesystem, no network, no declared capabilities.

- Backend: [`flate2`](https://crates.io/crates/flate2) with `default-features = false,
  features = ["rust_backend"]` → [`miniz_oxide`](https://crates.io/crates/miniz_oxide),
  pure Rust. The crate's default `zlib` C backend does **not** build for
  `wasm32-wasip2`.
- Wrappers supported: gzip (RFC 1952), zlib (RFC 1950), raw DEFLATE (RFC 1951).
- Compressed output is wrapped in a self-describing 16-byte `ENTZ` container that
  records the wrapper, the level, the original length and a CRC32, so decompression
  needs no out-of-band metadata and detects corruption.

## Input envelope

The input is an optional ASCII **directive line** followed by the payload:

```
[directive "\n"] <payload bytes>
```

The mode is resolved in this order:

1. **Directive line present** — the first line matches
   `^(compress|decompress)(:<field>)*\n`, where every byte before the newline is in
   `[a-z0-9:._-]`, the newline occurs within the first 64 bytes, and the line begins
   with `compress` or `decompress`. Everything after the newline is the payload.
2. **No directive, payload starts with `ENTZ`** — decompress.
3. **Otherwise** — compress with gzip at level 6.

Because rule 1 requires a strictly lowercase-ASCII line, arbitrary binary payloads
(PNG, JPEG, tarballs) fall through to rules 2/3 untouched. If you need to *compress*
data that itself begins with the four bytes `ENTZ`, pass an explicit `compress\n`
directive.

### Directive fields

`:`-separated, order-independent, each may appear at most once:

| Field | Values | Default | Applies to |
| --- | --- | --- | --- |
| format | `gzip` (or `gz`), `zlib`, `deflate` (or `raw`) | `gzip` | both |
| level | `0`–`9` (`0` = store, `9` = max) | `6` | `compress` only |

Examples: `compress`, `compress:zlib`, `compress:deflate:9`, `compress:9:gzip`,
`decompress`, `decompress:zlib`.

An unknown verb, unknown format, out-of-range level, duplicated field, empty field,
or a level on `decompress` is rejected with `InvalidInput` naming the problem.

## Output

### `compress`

A 16-byte little-endian `ENTZ` header followed by the compressed stream:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `ENTZ` (`45 4E 54 5A`) |
| 4 | 1 | container version — `1` |
| 5 | 1 | format tag — `1` gzip, `2` zlib, `3` deflate |
| 6 | 1 | compression level used, `0..=9` (informational) |
| 7 | 1 | flags — reserved, must be `0` |
| 8 | 4 | `u32` LE original (uncompressed) length |
| 12 | 4 | `u32` LE CRC32 of the original bytes |
| 16 | .. | the gzip / zlib / raw-DEFLATE stream |

### `decompress`

The original bytes, exactly. An `ENTZ` container is validated end to end — version,
reserved flags, format tag, declared length and CRC32 must all agree — so a corrupt
or tampered stream fails loudly instead of returning plausible garbage. A **bare**
gzip / zlib / raw-DEFLATE stream (no `ENTZ` header) is also accepted; the wrapper is
sniffed from the leading bytes, or you can force it with `decompress:<format>`.

## Limits and errors

| Condition | Error |
| --- | --- |
| empty input | `InvalidInput` |
| directive with no payload after it | `InvalidInput` |
| malformed directive | `InvalidInput` |
| payload is not a valid stream for the format | `InvalidInput` |
| truncated `ENTZ` container (< 16 bytes) | `InvalidInput` |
| unknown container version / format tag / reserved flags set | `InvalidInput` |
| length or CRC32 mismatch after inflate | `InvalidInput` |
| input over 64 MiB | `ResourceExhausted` |
| inflate output over 64 MiB (compression bomb) | `ResourceExhausted` |

The 64 MiB budget is deliberately well under the 256 MiB wasm store limit, since a
decompression pass holds the input, the sliding window and the output at once.
Nothing in this plugin panics or unwraps on caller-supplied bytes.

## Invoke

`entangle plugins invoke` prints non-UTF-8 output as base64, so pipe through
`base64 -d` for the binary side of the round trip.

```bash
# 1. compress a file (implicit: gzip, level 6)
entangle plugins invoke <fingerprint>/compress@0.1.0 \
  --input-file ./notes.txt \
  | sed 's/^output (base64): //' | base64 -d > notes.entz

# 2. explicit format + level: prepend a directive line
{ printf 'compress:zlib:9\n'; cat ./notes.txt; } > payload.bin
entangle plugins invoke <fingerprint>/compress@0.1.0 --input-file payload.bin

# 3. decompress — the ENTZ magic selects the mode, no directive needed
entangle plugins invoke <fingerprint>/compress@0.1.0 --input-file notes.entz
# → output: <the original text>

# quick inline smoke test
entangle plugins invoke <fingerprint>/compress@0.1.0 --input 'hello hello hello'
```

## Wasm size

The release component is ~139 KiB — almost all of it `miniz_oxide`.

## Tests

`cargo test` (host target, 25 tests in `src/codec.rs`) covers: round trips across all
three wrappers × levels 0/1/6/9, real shrink on repetitive input, header length/CRC
fields, implicit-mode resolution, directive parsing including field-order freedom and
every malformed form, wrapper sniffing, bare-stream decompression, binary payloads not
being mistaken for directives, empty input, truncated containers, corrupt bodies,
tampered length/CRC/version/format-tag/flag fields, single-byte and incompressible
inputs, and the compression-bomb ceiling.

## Files

- `src/codec.rs` — all logic, plus the test suite. No wasm-only types, so it builds
  and runs on the host target.
- `src/error.rs` — native mirror of the WIT `plugin-error` variant (the SDK's
  `PluginError` is `wit-bindgen`-generated and only exists on `wasm32`).
- `src/lib.rs` — `wasm32`-gated entrypoint that maps `Error` → `PluginError`.
- `entangle.toml` — tier-1 manifest, zero capabilities.
