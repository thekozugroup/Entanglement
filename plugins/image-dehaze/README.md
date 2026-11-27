# image-dehaze

Reduce atmospheric haze in a linear RGB16 image. This Tier 1 WASI component
receives image bytes and returns image bytes. Convert camera RAW to a linear
sRGB raster with a camera decoder before invoking the plugin.

## Image format

Supply a static truecolor PNG with three 16-bit samples per pixel and an
explicit `gAMA` value of `100000` (linear light). The expected primaries and
white point are those of sRGB. When supplied, `cHRM` must have the following
standard PNG scaled coordinates.

| Coordinate | x | y |
| --- | ---: | ---: |
| White | 31270 | 32900 |
| Red | 64000 | 33000 |
| Green | 30000 | 60000 |
| Blue | 15000 | 6000 |

The plugin rejects competing `sRGB`, `iCCP`, and `cICP` profile chunks, alpha
and `tRNS` transparency, and animated PNGs. Output is a static RGB16 PNG with
the original width and height, linear `gAMA`, and the `cHRM` values above.

Either dimension can be 1–4096 pixels, with at most 2,500,000 pixels total.
A request or response can be up to 16 MiB, including any request prefix.
The guest validates dimensions before allocating the decoded sample buffer.
Invalid images return `InvalidInput` and exceeded budgets return
`ResourceExhausted`.

## Whole image and tiles

A whole-image request contains the PNG directly. For a tile request, prepend
the ASCII bytes `EDH1` followed by the global atmospheric red, green, and blue
samples as three consecutive unsigned big-endian 16-bit values. The PNG starts
at byte offset 10. Zero is a valid atmospheric sample. The calculation uses
`max(A, 1)` only as the divisor for normalization and uses the original `A` for
reconstruction.

When processing tiles, estimate one atmospheric RGB value from the source and
attach it to every request. Include seven pixels of halo at each internal tile
edge, bounded by the original frame. Crop the halo from each returned image
before placing it in the result. The retained samples agree exactly with
whole-image processing using the same atmosphere.

## Algorithm

The dark channel at each pixel is the lowest RGB sample in its 15 × 15
neighborhood. Windows are clipped at image boundaries, equivalent to repeating
the border pixels for the minimum. The separable running minimum takes linear
time in the number of pixels.

To estimate atmospheric light, rank the dark-channel samples by decreasing
value, then by increasing row-major index. Keep the top
`max(1, floor(width * height / 1000))` samples. Of their original RGB triples,
choose the one with the largest channel sum, breaking ties by smallest
row-major index. The native `estimate_atmosphere` function implements this
definition on a row-major slice of RGB16 triples.

The normalized dark channel applies the same minimum to the per-channel
ratios `I / max(A, 1)`. The integer calculation uses a scale of `65535`, rounds
ratios to nearest, and caps them at that scale. It estimates transmission as
`max(6554, 65535 - round(0.95 * dark))`, then reconstructs each sample as
`A + round((I - A) * 65535 / transmission)`, clipped to `0..65535`. Rounding
ties go away from zero. The result is deterministic with either estimated or
supplied atmosphere. The prior can overcorrect bright surfaces or sky and can
leave visible edges where depth changes abruptly. [Dark-channel prior paper](https://doi.org/10.1109/TPAMI.2010.168)

## Build and invoke

```sh
cargo test --locked
cargo build --locked --release --target wasm32-wasip2
entangle plugins build . --wasm target/wasm32-wasip2/release/entangle_image_dehaze.wasm --out /tmp/image-dehaze-package
entangle plugins load /tmp/image-dehaze-package
plugin_id=$(sed -n 's/^id = "\(.*\)"$/\1/p' /tmp/image-dehaze-package/entangle.toml)
entangle compute dispatch "$plugin_id" \
  --input-file linear-photo.png --output-file dehazed.png
```

Load the signed package on eligible workers and trust its signing key on those
workers before remote dispatch. The tests generate their own raster fixtures and
cover known haze recovery, a slow independent numerical reference, strict PNG
format and geometry validation, and exact tiled-to-whole pixel parity.
