# qr-encode

UTF-8 text in, QR code out. Tier 1, pure compute: no filesystem, no network, no
declared capabilities.

- Encoder: [`qrcode`](https://crates.io/crates/qrcode) with
  `default-features = false`. That drops the crate's `image` feature (which would
  drag the entire `image` crate into the component) *and* its `svg` feature — we
  render SVG, block art and JSON ourselves so we can control the quiet zone,
  colours and run-length packing. With no features, `qrcode` has **zero**
  transitive dependencies.
- Normal QR versions 1–40, ECC levels L/M/Q/H. Mode selection (numeric /
  alphanumeric / byte) is left to the encoder's optimiser, so all-digit and
  all-uppercase payloads pack far denser than their byte-mode capacity.

## Input envelope

```
[ "#!qr" [ " " key=value ]... "\n" ] <UTF-8 text to encode>
```

- **No options line** (the common case): the *entire* input is the text and all
  defaults apply. `--input 'https://example.com'` just works.
- **Options line**: present only when the input starts with the exact 4 bytes
  `#!qr` followed by a space, a tab, or the terminating newline. Options are
  whitespace-separated `key=value` pairs; the text begins after the first newline.
- To encode text that itself literally starts with `#!qr`, prefix an empty options
  line: `#!qr\n#!qr and the rest`. A run like `#!qrcode` is *not* a sentinel (no
  word boundary), so it is treated as text.

### Options

| Key | Values | Default | Applies to |
| --- | --- | --- | --- |
| `format` | `svg`, `txt` (alias `text`), `json` | `svg` | — |
| `ecc` | `l`, `m`, `q`, `h` (upper case accepted) | `m` | — |
| `scale` | `1`–`32`, SVG pixels per module | `4` | svg |
| `quiet` | `0`–`16`, quiet-zone width in modules | `4` | svg, txt |
| `dark` | `none`, `#RGB`, `#RGBA`, `#RRGGBB`, `#RRGGBBAA`, or a plain colour name | `#000000` | svg |
| `light` | same as `dark`; `none` = transparent background | `#ffffff` | svg |
| `version` | `1`–`40`, force a symbol size instead of auto-fitting | auto | — |

Order does not matter and repeated whitespace is fine. Anything else — a bare word
with no `=`, an unknown key, an out-of-range number, a colour that is not one of
the shapes above — is rejected with `InvalidInput` naming the offending token.
Colours are whitelisted rather than escaped, so no option value can close an SVG
attribute and inject markup.

## Output

### `format=svg` (default)

A single self-contained SVG document, UTF-8, trailing newline:

```
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="116" height="116"
     viewBox="0 0 29 29" shape-rendering="crispEdges" role="img"
     aria-label="QR code, version 1 ECC M">
<rect x="0" y="0" width="29" height="29" fill="#ffffff"/>
<path fill="#000000" d="M4 4h7v1H4z..."/>
</svg>
```

`viewBox` is in **module** units (`modules + 2 × quiet` per side); `width`/`height`
are that side times `scale`, in pixels, so the image scales cleanly at any size.
Horizontal runs of dark modules are merged into one path segment each. With
`light=none` the background `<rect>` is omitted entirely.

### `format=txt`

Unicode block art: `██` per dark module, two spaces per light one — roughly square
in a monospace terminal. `modules + 2 × quiet` lines, each newline-terminated.

### `format=json`

One line, quiet zone reported rather than baked in:

```json
{"version":1,"ecc":"M","modules":21,"quiet_zone":4,"matrix":["1111111...","..."]}
```

`matrix` has `modules` strings of `modules` characters, `'1'` = dark, row-major
from the top-left.

## Errors

| Condition | Error |
| --- | --- |
| empty input | `InvalidInput` |
| input not valid UTF-8 (byte offset reported) | `InvalidInput` |
| input over 8192 bytes | `InvalidInput` |
| `#!qr` sentinel with no terminating newline | `InvalidInput` |
| options line present but text after it empty | `InvalidInput` |
| malformed / unknown / out-of-range option | `InvalidInput` |
| text too long for any version at the chosen ECC | `InvalidInput` |
| text too long for an explicitly forced `version=` | `InvalidInput` |

The "too long" message reports the byte count and the full version-40 capacity for
that ECC level, e.g.

```
invalid input: cannot encode 1274 bytes at ECC H: data too long — a version-40
symbol at ECC H holds at most 1273 bytes, 1852 alphanumeric characters, or 2953
digits; shorten the text or lower `ecc` (l holds the most)
```

Nothing in this plugin panics or unwraps on caller-supplied bytes.

## Invoke

```bash
# simplest case — SVG on stdout
entangle plugins invoke <fingerprint>/qr-encode@0.1.0 \
  --input 'https://entanglement.example/pair?token=abc123'

# terminal-friendly block art, tight quiet zone
entangle plugins invoke <fingerprint>/qr-encode@0.1.0 \
  --input '#!qr format=txt quiet=1
https://entanglement.example'

# high ECC, big modules, transparent background — save the SVG
{ printf '#!qr ecc=h scale=10 light=none\n'; printf 'WIFI:T:WPA;S:mesh;P:hunter2;;'; } > payload.txt
entangle plugins invoke <fingerprint>/qr-encode@0.1.0 --input-file payload.txt \
  | sed 's/^output: //' > wifi.svg
```

## Wasm size

The release component is ~94 KiB — the smallest of the three tier-1 compute plugins,
since `qrcode` with no features has no dependencies at all.

## Tests

`cargo test` (host target, 23 tests in `src/qr.rs`) covers: SVG structure and run
count on a real payload, exact `viewBox`/`width`/`height` geometry for a known
version and quiet zone, every option being honoured, option-order and whitespace
insensitivity, the sentinel escape and word-boundary rule, `txt` grid dimensions
and blank quiet zone, `json` shape including the top-left finder pattern, ECC level
affecting symbol size, forced versions, the exact byte-mode capacity boundary at
all four ECC levels (and that one byte more fails), denser numeric/alphanumeric
modes beating the byte capacity, empty input, non-UTF-8 input, over-long input,
unterminated and empty options lines, ten malformed-option cases, SVG-injection
attempts through `dark=`/`light=`, payloads full of SVG metacharacters, single-char
and emoji/CJK payloads, and out-of-bounds module lookups.

## Files

- `src/qr.rs` — all logic, plus the test suite. No wasm-only types, so it builds
  and runs on the host target.
- `src/error.rs` — native mirror of the WIT `plugin-error` variant (the SDK's
  `PluginError` is `wit-bindgen`-generated and only exists on `wasm32`).
- `src/lib.rs` — `wasm32`-gated entrypoint that maps `Error` → `PluginError`.
- `entangle.toml` — tier-1 manifest, zero capabilities.
