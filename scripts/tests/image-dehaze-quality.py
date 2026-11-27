#!/usr/bin/env python3
"""Validate signed dehaze using known clear scenes, independent RAW development and full-frame pixels.

Run with --bin-dir, --wasm, --photos and --out. The two optional external dependencies
PyPNG and rawpy are documented in docs/testing/raw-image-fixtures.md. The --prepare
mode writes only the redistributable synthetic fixtures and their immutable manifest.
"""

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib

import numpy as np
from scipy.ndimage import minimum_filter

ROOT = Path(__file__).resolve().parents[2]
CHROMATICITIES = (31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SCALE = 65535
PHOTOS = {
    "nikon_d40.nef": "44e88bc77b7a531b22647bcd07b9393c4568062e8f0906d3bbdecb42fbe29e03",
    "canon_350d.cr2": "8cbb84e04d93b005fe082da9c954122a612b5281af00aa088d767850f343fd38",
}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pixel_hash(rgb):
    return hashlib.sha256(rgb.astype(">u2", copy=False).tobytes()).hexdigest()


def linear_png(rgb):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    height, width, _ = rgb.shape
    raw = b"".join(b"\0" + row.astype(">u2").tobytes() for row in rgb)
    return b"".join(
        [
            PNG_SIGNATURE,
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 16, 2, 0, 0, 0)),
            chunk(b"gAMA", struct.pack(">I", 100000)),
            chunk(b"cHRM", struct.pack(">8I", *CHROMATICITIES)),
            chunk(b"IDAT", zlib.compress(raw)),
            chunk(b"IEND", b""),
        ]
    )


def read_result(path):
    import png

    with path.open("rb") as stream:
        if stream.read(8) != PNG_SIGNATURE:
            raise ValueError("invalid PNG signature")
        tags = {}
        while True:
            length, kind = struct.unpack(">I4s", stream.read(8))
            if kind in (b"sRGB", b"iCCP", b"cICP", b"tRNS", b"acTL", b"fcTL", b"fdAT"):
                raise ValueError("unexpected transfer function, transparency or animation in RGB16 output")
            if kind in (b"gAMA", b"cHRM"):
                if kind in tags or length > 32:
                    raise ValueError("invalid or duplicate color tag")
                tags[kind] = stream.read(length)
            else:
                stream.seek(length, 1)
            stream.seek(4, 1)
            if kind == b"IEND":
                break
        if stream.read(1) or tags != {
            b"gAMA": struct.pack(">I", 100000),
            b"cHRM": struct.pack(">8I", *CHROMATICITIES),
        }:
            raise ValueError("unexpected PNG color encoding or trailing bytes")
    width, height, rows, info = png.Reader(filename=str(path)).read()
    if info["bitdepth"] != 16 or info["planes"] != 3 or info["greyscale"] or info["alpha"]:
        raise ValueError("expected a fully decoded RGB16 image")
    return np.stack([np.asarray(row, dtype=np.uint16).reshape(width, 3) for row in rows]).reshape(
        height, width, 3
    )


def synthetic_scenes():
    """Three textured chromatic landscapes, with bright sky and a known scattering field."""
    y, x = np.indices((96, 128))
    X, Y = x / 127, y / 95
    for scene, air in enumerate(([0.91, 0.94, 0.98], [0.96, 0.88, 0.82], [0.80, 0.91, 0.97])):
        atmosphere = np.array(air)
        region = (x // (10 + scene) + y // (11 + 2 * scene) + scene) % 3
        palette = np.array([[0.009, 0.39, 0.70], [0.61, 0.014, 0.18], [0.19, 0.72, 0.011]])
        texture = (
            0.61
            + 0.22 * X
            + 0.08 * np.sin(2 * np.pi * (Y + 0.22 * X + scene / 5))
            + 0.05 * ((x + 2 * y) % 5) / 4
        )
        terrain = palette[region] * texture[:, :, None] + 0.003
        sky = atmosphere * (0.91 + 0.075 * X + 0.01 * np.cos(2 * np.pi * Y))[:, :, None]
        clear = np.where((y < 22 + 3 * np.sin(x / 19 + scene))[:, :, None], sky, terrain)
        transmission = 0.625 + 0.175 * np.sin(np.pi * (X - 0.5) + 0.17 * scene) * np.cos(np.pi * Y)
        hazy = clear * transmission[:, :, None] + atmosphere * (1 - transmission[:, :, None])
        yield (
            f"scene-{scene + 1}",
            np.rint(clear * SCALE).astype(np.uint16),
            np.rint(hazy * SCALE).astype(np.uint16),
        )
    # An already clear, colorful, textured scene with a naturally dark channel.
    terrain = (
        palette[(x // 9 + 2 * (y // 13)) % 3]
        * (0.45 + 0.35 * X + 0.14 * np.cos(4 * np.pi * Y))[:, :, None]
    )
    clear = np.rint(terrain * SCALE).astype(np.uint16)
    yield "clear-control", clear, clear.copy()


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True)
    cases = {}
    for name, truth, observed in synthetic_scenes():
        p = directory / (name + ".png")
        p.write_bytes(linear_png(observed))
        cases[name] = {"input_png_sha256": sha(p), "clear_rgb16be_sha256": pixel_hash(truth)}
    result = {"size": [128, 96], "space": "linear sRGB16", "cases": cases}
    (directory / "inputs.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def full_reference(rgb):
    """Independent whole-raster integer specification implemented with SciPy morphology."""
    dark = minimum_filter(rgb.min(axis=2), size=15, mode="nearest").ravel()
    slots = max(1, dark.size // 1000)
    cutoff = np.partition(dark, dark.size - slots)[dark.size - slots]
    indices = np.flatnonzero(dark > cutoff)
    tied = np.flatnonzero(dark == cutoff)[: slots - len(indices)]
    candidates = np.sort(np.concatenate((indices, tied)))
    values = rgb.reshape(-1, 3)[candidates]
    atmosphere = values[values.astype(np.uint32).sum(axis=1).argmax()].astype(np.int64)
    norm = np.full(rgb.shape[:2], SCALE, dtype=np.uint32)
    for i, air in enumerate(atmosphere):
        divisor = max(1, int(air))
        channel = (rgb[:, :, i].astype(np.uint32) * SCALE + divisor // 2) // divisor
        np.minimum(norm, channel, out=norm)
    filtered = minimum_filter(norm, size=15, mode="nearest")
    trans = np.maximum(6554, SCALE - (95 * filtered + 50) // 100).astype(np.int64)
    recovered = np.empty_like(rgb)
    for i, air in enumerate(atmosphere):
        difference = rgb[:, :, i].astype(np.int64) - air
        delta = np.sign(difference) * ((np.abs(difference) * SCALE + trans // 2) // trans)
        recovered[:, :, i] = np.clip(air + delta, 0, SCALE)
    return recovered, atmosphere.tolist()


def synthetic_score(name, truth, hazy, result):
    if result.shape != truth.shape:
        raise ValueError(f"{name}: output geometry mismatch")
    expected, air = full_reference(hazy)
    before = float(np.abs(hazy.astype(np.int32) - truth).mean() / SCALE)
    after = float(np.abs(result.astype(np.int32) - truth).mean() / SCALE)
    new_clip = float(np.mean(((result == 0) | (result == SCALE)) & ((truth != 0) & (truth != SCALE))))
    return {
        "before_mae": before,
        "after_mae": after,
        "newly_clipped_fraction": new_clip,
        "whole_reference_pixel_mismatches": int(np.count_nonzero(result != expected)),
        "atmospheric_rgb16": air,
        "output_rgb16be_sha256": pixel_hash(result),
    }


def develop_photo(path):
    import rawpy

    if sha(path) != PHOTOS[path.name]:
        raise ValueError(f"{path.name}: fixture digest mismatch")
    with rawpy.imread(str(path)) as photo:
        sizes = photo.sizes
        dimensions = [sizes.raw_width, sizes.raw_height]
        cfa = photo.raw_pattern.tolist()
        sensor_sample = photo.raw_image_visible[::8, ::8]
        sensor = {
            "visible_sample_percentiles_1_50_99": np.percentile(sensor_sample, [1, 50, 99]).tolist(),
            "black_levels": photo.black_level_per_channel,
            "white_level": photo.white_level,
            "orientation_flip": sizes.flip,
        }
        rgb = photo.postprocess(
            use_camera_wb=True,
            output_color=rawpy.ColorSpace.sRGB,
            gamma=(1, 1),
            no_auto_bright=True,
            output_bps=16,
        )
    # Independent C++ command/PPM route used by the normal CLI. Decode fresh and compare every sample.
    command = ["dcraw_emu", "-4", "-w", "-o", "1", "-Z", "-", str(path.resolve())]
    with tempfile.TemporaryFile() as output:
        subprocess.run(command, stdout=output, stderr=subprocess.PIPE, check=True, timeout=75)
        output.seek(0)
        if output.readline() != b"P6\n":
            raise ValueError("invalid reference PPM type")
        w, h = map(int, output.readline().split())
        if output.readline() != b"65535\n" or (h, w, 3) != rgb.shape:
            raise ValueError("native decoder orientation, dimensions or precision mismatch")
        color = np.frombuffer(output.read(), dtype=">u2").reshape(h, w, 3)
        same = np.array_equal(rgb, color)
        decoder_mae = 0.0 if same else float(np.abs(color.astype(np.int32) - rgb).mean() / SCALE)
        tool_hash = pixel_hash(color)
    return rgb, {
        "input_sha256": sha(path),
        "sensor": dimensions,
        "bayer_pattern": cfa,
        "mosaic_observations": sensor,
        "developed_dimensions": [w, h],
        "rawpy_version": rawpy.__version__,
        "rawpy_libraw_version": list(rawpy.libraw_version),
        "native_bindings_exact": same,
        "decode_mae": decoder_mae,
        "rawpy_rgb16be_sha256": pixel_hash(rgb),
        "dcraw_emu_rgb16be_sha256": tool_hash,
    }


def check_quality(report):
    rows = list(report["synthetic"].values())
    hazy = [r for r in rows if r["before_mae"] > 0]
    clear = report["synthetic"]["clear-control"]
    checks = {
        "aggregate_mae": sum(r["after_mae"] for r in hazy) <= 0.90 * sum(r["before_mae"] for r in hazy),
        "two_scenes_improve": sum(r["after_mae"] <= 0.95 * r["before_mae"] for r in hazy) >= 2,
        "no_scene_above_1_05": all(r["after_mae"] <= 1.05 * r["before_mae"] for r in hazy),
        "clear_control": clear["after_mae"] <= 2 / 255 and clear["newly_clipped_fraction"] <= 0.005,
        "synthetic_whole_frame": all(r["whole_reference_pixel_mismatches"] == 0 for r in rows),
        "both_raw_bindings_agree": all(r["native_bindings_exact"] for r in report["photos"].values()),
        "genuine_photo_transform": all(
            r["whole_reference_pixel_mismatches"] == 0 and r["changed_samples"] > 0
            for r in report["photos"].values()
        ),
    }
    return checks


def run(args):
    import png
    import scipy

    path = ROOT / "scripts/tests/image-dehaze-batch.py"
    spec = importlib.util.spec_from_file_location("batch_fixture", path)
    batch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(batch)
    cli = args.bin_dir / "entangle"

    def source_id():
        return subprocess.check_output(
            ["python3", ROOT / "scripts/production_score.py", "--source-id"], cwd=ROOT, text=True
        ).strip()

    report = {
        "source_before": source_id(),
        "test_sha256": sha(Path(__file__)),
        "executables_sha256": {
            "cli": sha(cli),
            "daemon": sha(args.bin_dir / "entangled"),
            "guest": sha(args.wasm),
        },
        "providers": {"numpy": np.__version__, "scipy": scipy.__version__, "pypng": png.__version__},
        "synthetic": {},
        "photos": {},
    }
    if args.expected_source_id and report["source_before"] != args.expected_source_id:
        raise ValueError("starting source does not match the expected frozen revision")
    args.out.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.out.write_text(json.dumps(report, indent=2) + "\n")

    with tempfile.TemporaryDirectory(prefix="ent-dehaze-quality-") as tmp, ExitStack() as stack:
        temp = Path(tmp)
        scenes = temp / "scenes"
        report["synthetic_manifest"] = prepare(scenes)
        save()
        coordinator, workers, plugin = batch.start_cluster(args.bin_dir, args.wasm, temp, stack)
        report["peer_ids"] = [w.peer for w in workers]
        report["plugin"] = plugin
        for index, (name, clear, hazy) in enumerate(synthetic_scenes()):
            worker = workers[index % len(workers)]
            result_path = scenes / (name + ".out.png")
            res = batch.run_cli(
                coordinator,
                [
                    "compute",
                    "dispatch",
                    plugin,
                    "--input-file",
                    scenes / (name + ".png"),
                    "--output-file",
                    result_path,
                    "--integrity",
                    "trusted-executor",
                    "--allow",
                    worker.peer,
                ],
            )
            if worker.peer not in res.stderr:
                raise ValueError("synthetic dispatch selected the wrong peer")
            rgb = read_result(result_path)
            report["synthetic"][name] = dict(synthetic_score(name, clear, hazy, rgb), peer=worker.peer)
        save()
        inputs = temp / "photos"
        inputs.mkdir()
        for name, expected in PHOTOS.items():
            original = args.photos / name
            if sha(original) != expected:
                raise ValueError(f"{name}: fixture SHA-256 mismatch")
            shutil.copyfile(original, inputs / name)
        out = temp / "results"
        command = [
            "image",
            "dehaze",
            "--recursive",
            inputs,
            "--output-dir",
            out,
            "--plugin",
            plugin,
            "--jobs",
            "2",
            "--tile-edge",
            "1024",
            "--json",
        ]
        for worker in workers:
            command.extend(["--allow", worker.peer])
        proc = batch.run_cli(coordinator, command, timeout=600)
        rows, summary = batch.parsed_rows(proc.stdout)
        report["batch_summary"] = summary
        if summary["processed"] != len(PHOTOS) or summary["failed"] or summary["resumed"]:
            raise ValueError(f"unexpected batch result {summary}")
        if len(rows) != len(PHOTOS) or {r["input"] for r in rows} != set(PHOTOS):
            raise ValueError("missing, duplicated or extra photo result")
        observed_peers = set()
        for row in rows:
            name = row["input"]
            peer_set = set(row["tile_workers"])
            if not peer_set or not peer_set <= set(report["peer_ids"]):
                raise ValueError(f"{name}: unauthenticated or missing execution attribution")
            observed_peers.update(peer_set)
            original, info = develop_photo(inputs / name)
            output = read_result(out / row["output"])
            if (
                output.shape != original.shape
                or [row["width"], row["height"]] != info["developed_dimensions"]
            ):
                raise ValueError(f"{name}: dimensions or orientation mismatch")
            expected, air = full_reference(original)
            info.update(
                {
                    "atmospheric_rgb16": air,
                    "reference_rgb16be_sha256": pixel_hash(expected),
                    "output_rgb16be_sha256": pixel_hash(output),
                    "whole_reference_pixel_mismatches": int(np.count_nonzero(output != expected)),
                    "changed_samples": int(np.count_nonzero(output != original)),
                    "receipt": row,
                }
            )
            report["photos"][name] = info
            save()
        report["source_after"] = source_id()
        report["checks"] = check_quality(report)
        if args.expected_source_id:
            report["checks"]["expected_source_before_and_after"] = (
                report["source_before"] == report["source_after"] == args.expected_source_id
            )
        report["checks"]["both_configured_workers_executed_photo_tiles"] = observed_peers == set(
            report["peer_ids"]
        )
        save()
        for name, outcome in report["checks"].items():
            print(f"{name}: {outcome}")
        return all(report["checks"].values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare", type=Path, help="only generate the four synthetic fixtures and hash manifest"
    )
    parser.add_argument(
        "--expected-source-id", help="require this canonical frozen source before and after the run"
    )
    for name in ("bin-dir", "wasm", "photos", "out"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
        return True
    if any(v is None for v in (args.bin_dir, args.wasm, args.photos, args.out)):
        parser.error("the end-to-end check needs --bin-dir, --wasm, --photos and --out")
    args.bin_dir = args.bin_dir.resolve()
    args.wasm = args.wasm.resolve()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
