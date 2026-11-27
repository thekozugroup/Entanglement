# Camera RAW fixtures and photographic quality checks

Two independently identified camera originals are available in the pinned imazen codec corpus at revision `ac980c295cb62c925d03d47990925d49c36eef18`. The corpus attributes these Canon and Nikon Bayer samples to raw.pixls.us under CC0 1.0. Its license section distinguishes privately sourced mobile samples. The Git LFS pointers record the following object hashes and byte lengths. Both original objects were retrieved through the publisher’s standard LFS download endpoint and LibRaw opened their sensor data. Keep the photos and derivatives outside the repository. [Camera collection](https://github.com/imazen/codec-corpus/tree/ac980c295cb62c925d03d47990925d49c36eef18/raw-conformance/valid/bayer) · [Sample licensing and provenance](https://github.com/imazen/codec-corpus/blob/ac980c295cb62c925d03d47990925d49c36eef18/raw-conformance/README.md#license) · [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/)

| File in `raw-conformance/valid/bayer/` | Camera | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `nikon_d40.nef` | Nikon D40 | 5,844,273 | `44e88bc77b7a531b22647bcd07b9393c4568062e8f0906d3bbdecb42fbe29e03` |
| `canon_350d.cr2` | Canon EOS 350D DIGITAL | 10,586,467 | `8cbb84e04d93b005fe082da9c954122a612b5281af00aa088d767850f343fd38` |

For a selective download with Git LFS installed, use a fresh directory. The two hash checks distinguish complete sensor files from their short text pointers.

```sh
work=$(mktemp -d)
GIT_LFS_SKIP_SMUDGE=1 git clone --filter=blob:none --no-checkout https://github.com/imazen/codec-corpus.git "$work/photos"
cd "$work/photos"
GIT_LFS_SKIP_SMUDGE=1 git checkout --detach ac980c295cb62c925d03d47990925d49c36eef18
git lfs pull --include='raw-conformance/valid/bayer/nikon_d40.nef,raw-conformance/valid/bayer/canon_350d.cr2' --exclude=''
cd raw-conformance/valid/bayer
printf '%s  %s\n' \
  44e88bc77b7a531b22647bcd07b9393c4568062e8f0906d3bbdecb42fbe29e03 nikon_d40.nef \
  8cbb84e04d93b005fe082da9c954122a612b5281af00aa088d767850f343fd38 canon_350d.cr2 \
  | sha256sum --check
```

The DNG Lab corpus independently records the same byte lengths, legacy MD5 digests, mosaic dimensions and camera models for both files. These records identify the samples. The fixture-specific distribution statement linked above supplies their license. [Nikon metadata](https://github.com/dnglab/dnglab/blob/4c64720653976343479a883bfd1e6066151ac093/rawler/data/testdata/rawdb/Nikon/D40/raw_modes/NIKON%20D40_ISO_200_12bits_Lossy%20%28type%201%29.NEF.analyze.yaml) · [Canon metadata](https://github.com/dnglab/dnglab/blob/4c64720653976343479a883bfd1e6066151ac093/rawler/data/testdata/rawdb/Canon/EOS%20350D/raw_modes/Canon%20EOS%20350D%20DIGITAL_ISO_100.CR2.analyze.yaml)

## Quality criteria

The independent quality oracle uses three synthetic 128 × 96 scenes with known clear linear RGB16 values, plus a separate clear control. It applies atmospheric scattering using known, spatially varying transmission between 0.45 and 0.80 and a fixed per-scene RGB atmosphere. The signed guest sees only the hazy raster. Before any candidate quality run, the following thresholds were set for the linear RGB16 results.

- Aggregate recovered mean absolute error (MAE) across the three scenes must be at most 90% of aggregate hazy MAE. At least two scenes must improve by at least 5%, and no scene may increase MAE by more than 5%.
- The independent clear control must change by at most 2/255 mean absolute linear amplitude and introduce clipped endpoints in at most 0.5% of channel samples.
- All output rasters must decode fully with the expected dimensions, RGB16 samples, linear gAMA and sRGB cHRM. A whole-frame NumPy/SciPy implementation of the specified integer dark-channel transform independently checks every output sample, including the edges of distributed tiles.
- For each genuine photo, compare native LibRaw command-line development with the pinned rawpy binding configured for camera white balance, linear gamma, sRGB primaries, normal orientation, disabled auto-brightening and 16-bit precision. Compare the full worker result to the independent whole-image transform on the developed samples. These photographs have no paired haze-free reference, so the reported natural-image checks assess decoding, color interpretation and transform conformance. The synthetic scenes measure recovery against known truth.

The independent developed-raster SHA-256 precedents (row-major RGB, 16-bit big-endian channels) are `afd878bf5675172ab9c340b4cf0eef3ae8b1e44699322ff7998247fbc5018660` for the Nikon and `4d51768d2985c5667a368e5b0cf134636386a878927881a609e19900f23546f1` for the Canon. The two separate native development paths agreed on all 42,478,146 channel values. This native comparison uses the same LibRaw version through different wrappers.

Use Python 3 with NumPy, SciPy, PyPNG `0.20220715.0` and rawpy `0.25.1` (LibRaw 0.21.4), plus a matching `dcraw_emu` executable for the reference decoder comparison. The test writes numerical observations and fixture hashes, keeping temporary input/output images local. [Quality oracle](../../scripts/tests/image-dehaze-quality.py)


With the release CLI, daemon and built guest available, run the full photographic check using both local camera files. The test starts its own coordinator and two authenticated workers. Supply `--expected-source-id` for a check bound to a specific frozen source.

```sh
python3 scripts/tests/image-dehaze-quality.py \
  --bin-dir target/release \
  --wasm plugins/image-dehaze/target/wasm32-wasip2/release/entangle_image_dehaze.wasm \
  --photos "$work/photos/raw-conformance/valid/bayer" \
  --out /tmp/image-dehaze-quality.json
```
