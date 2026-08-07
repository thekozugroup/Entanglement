# image-resize

Decode a PNG or JPEG, resample it to new dimensions, re-encode it. Tier 1, pure
compute: no filesystem, no network, no declared capabilities — the image travels in
as bytes and comes back as bytes, which is exactly what makes it worth dispatching
to another device. Resampling a 12 MP photo with Lanczos3 is the CPU-heavy case
Entanglement's remote-invoke path exists for.

- Codecs: [`image`](https://crates.io/crates/image) 0.25 with
  `default-features = false, features = ["png", "jpeg"]`. **The default feature set
  cannot build for `wasm32-wasip2`** — it enables `rayon` (no threads under wasip2)
  and codecs with C dependencies. `png` (the pure-Rust `png` crate) and `jpeg`
  (`zune-jpeg` for decode, `jpeg-encoder` for encode) are the only two we need and
  both are pure Rust.
- Header parsing: `serde` + `serde_json`.

## Input envelope

```
<one-line JSON object> "\n" <PNG or JPEG bytes>
```

The header is **required** — the target dimensions have to travel with the bytes,
since the sandbox has no other channel. It is a single JSON object, terminated by
the first `\n`; everything after that newline is the encoded image, byte for byte.

```
{"width":800}
<PNG bytes>
```

### Header keys

Unknown keys are **rejected**, so a typo like `"widht"` fails loudly instead of
being silently ignored.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `width` | integer 1–20000 | — | target width in pixels |
| `height` | integer 1–20000 | — | target height in pixels |
| `format` | `"png"` \| `"jpeg"` (`"jpg"` accepted) | same as input | output container |
| `quality` | integer 1–100 | `85` | JPEG quality; ignored for PNG |
| `filter` | see below | `"lanczos3"` | resampling filter |
| `fit` | `"exact"` \| `"contain"` \| `"cover"` | `"exact"` | only meaningful when *both* dimensions are given |

At least one of `width` / `height` is required.

`filter` accepts `nearest`, `triangle` (alias `linear`), `catmullrom` (aliases
`catmull-rom`, `cubic`), `gaussian`, `lanczos3` (alias `lanczos`), case-insensitive.
`nearest` is cheapest, `lanczos3` is the best quality and the most CPU-hungry.

### Aspect ratio

- **One dimension given** — the other is derived from the source aspect ratio,
  rounded to nearest and clamped to at least 1 pixel. `fit` is irrelevant.
- **Both given** — `fit` decides:
  - `exact` (default): stretch to exactly `width` x `height`, ignoring the source
    aspect ratio.
  - `contain`: scale to fit *inside* the box, preserving aspect. The result is
    `width` x `height` or smaller on one axis (200x100 into a 50x50 box → 50x25).
  - `cover`: scale to *cover* the box preserving aspect, then centre-crop to
    exactly `width` x `height`.

## Output

The re-encoded image bytes and nothing else — no header, no wrapper — so the output
can be written straight to a file. The container is `format`, or the source's format
if `format` was omitted.

PNG output preserves the alpha channel. JPEG has no alpha, so an image with
transparency is flattened to RGB8 before encoding rather than being rejected.

## Limits and errors

Budgets are enforced *before* allocation: the source dimensions are read from the
container header (`ImageReader::into_dimensions`) and checked against the pixel
budget without decoding a single scanline, so a 400 MP PNG that is 60 bytes on the
wire is rejected in microseconds rather than trying to claim 1.6 GB.

| Condition | Error |
| --- | --- |
| empty input | `InvalidInput` |
| first byte is not `{` | `InvalidInput` (with an example header) |
| no `\n` in the first 4096 bytes | `InvalidInput` |
| header is not a valid JSON object / has an unknown key / a value of the wrong type | `InvalidInput` |
| no image bytes after the newline | `InvalidInput` |
| neither `width` nor `height` given | `InvalidInput` |
| `width`/`height` is 0 or over 20000 | `InvalidInput` |
| unknown `filter` / `format`, `quality` outside 1–100 | `InvalidInput` |
| input is not PNG or JPEG (or unidentifiable) | `InvalidInput` |
| truncated or corrupt image data | `InvalidInput` |
| input payload over 32 MiB | `ResourceExhausted` |
| source over 16 000 000 pixels | `ResourceExhausted` |
| target over 16 000 000 pixels | `ResourceExhausted` |

16 MP is 64 MiB as RGBA8; the wasm store is capped at 256 MiB and a resize needs the
decoded source, the resampled destination and the encoder buffer live at once, hence
the conservative ceiling. The decoder is additionally handed an `image::Limits` with
a 20000-pixel per-side cap and a 128 MiB allocation cap as defence in depth.

Nothing in this plugin panics or unwraps on caller-supplied bytes.

## Invoke

The header must be prepended to the image, so build the payload with `cat`:

```bash
# 800px wide, aspect preserved, stays PNG
{ printf '{"width":800}\n'; cat photo.png; } > payload.bin
entangle plugins invoke <fingerprint>/image-resize@0.1.0 --input-file payload.bin \
  | sed 's/^output (base64): //' | base64 -d > photo-800.png

# 256x256 square thumbnail, centre-cropped, as JPEG
{ printf '{"width":256,"height":256,"fit":"cover","format":"jpeg","quality":80}\n'; cat photo.jpg; } > payload.bin
entangle plugins invoke <fingerprint>/image-resize@0.1.0 --input-file payload.bin \
  | sed 's/^output (base64): //' | base64 -d > thumb.jpg

# fast preview: nearest-neighbour, fit inside a 320x240 box
{ printf '{"width":320,"height":240,"fit":"contain","filter":"nearest"}\n'; cat photo.png; } > payload.bin
entangle plugins invoke <fingerprint>/image-resize@0.1.0 --input-file payload.bin
```

`entangle plugins invoke` prints non-UTF-8 output as `output (base64): ...`, hence
the `sed`/`base64 -d` pair above.

## Wasm size

The release component is ~547 KiB — noticeably larger than the other tier-1 plugins
(`compress` is 139 KiB, `qr-encode` 94 KiB) because it carries two full codecs plus
the resampling kernels. That is the price of the flagship demo; it is still small
enough to ship over the mesh in one go.

## Tests

`cargo test` (host target, 36 tests in `src/resize.rs`) generates images in memory,
runs them through `process`, and decodes the output to assert the real dimensions
and container. Coverage: both-dimension resize, width-only and height-only aspect
derivation (including rounding to nearest and the clamp to 1 pixel), upscaling,
JPEG-in/JPEG-out, format switching both ways plus the `jpg` alias, quality actually
affecting output size, all three `fit` modes, every filter alias, alpha survival
through PNG, 1x1 targets, and pure `plan()` resolution. Error paths: empty input,
missing/unterminated/oversized header, four malformed-JSON shapes, unknown keys,
no dimensions, zero and oversize dimensions, oversize target area, a hand-built
19000x19000 PNG rejected from its header alone, the exact 16 MP source boundary,
the per-side `MAX_DIM` cap, eight bad `quality`/`filter`/`format`/`fit` values,
unrecognisable bytes, PNGs truncated to 1/2, 1/4 and 1/8, a corrupt IDAT payload,
an oversize input payload, and saturating arithmetic in `scale_dim`.

## Files

- `src/resize.rs` — all logic, plus the test suite. No wasm-only types, so it builds
  and runs on the host target.
- `src/error.rs` — native mirror of the WIT `plugin-error` variant (the SDK's
  `PluginError` is `wit-bindgen`-generated and only exists on `wasm32`).
- `src/lib.rs` — `wasm32`-gated entrypoint that maps `Error` → `PluginError` and
  logs the resolved `WxH -> WxH` plan.
- `entangle.toml` — tier-1 manifest, zero capabilities.
