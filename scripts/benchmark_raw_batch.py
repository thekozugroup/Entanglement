"""Time complete RAW dehaze batches on one local executor and an explicitly paired mesh.

The input manifest is a JSON object mapping relative RAW paths to SHA-256.
The profiles must already be running. Each timed invocation uses a fresh output
directory on the same volume. Reports contain file names and peer identifiers.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

from PIL import Image


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def profile_env(home):
    env = dict(os.environ, HOME=str(home.resolve(strict=True)))
    env.pop("ENTANGLE_ALLOW_LOCAL", None)
    return env


def cli_json(cli, env, *args):
    return json.loads(subprocess.check_output([cli, *args, "--json"], env=env, timeout=30))


def simple_path(name):
    return isinstance(name, str) and name != "" and all(
        part not in ("", ".", "..") for part in name.split("/")
    )


def validate_inputs(directory, manifest):
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("expected a nonempty JSON object mapping relative RAW paths to SHA-256")
    for name, digest in manifest.items():
        if not simple_path(name):
            raise ValueError(f"invalid source path in manifest: {name!r}")
        path = directory / name
        if path.resolve(strict=True) != path or not path.is_file() or sha256(path) != digest:
            raise ValueError(f"source changed or is a symlink: {name!r}")


class BatchVerificationError(ValueError):
    """Final coverage or digest failure after per-file output validation."""

    def __init__(self, message, observations):
        super().__init__(message)
        self.observations = observations


def verify_run(ndjson, directory, manifest, peers, tile_edge, reference):
    rows = [json.loads(line) for line in ndjson.splitlines()]
    if not rows:
        raise ValueError("missing batch results")
    summary = rows.pop()
    if (summary["status"], summary["processed"], summary["resumed"], summary["failed"]) != (
        "summary", len(manifest), 0, 0
    ):
        raise ValueError(f"incomplete batch: {summary}")
    outputs, distribution, photos = {}, Counter(), {}
    for row in rows:
        if row["status"] != "processed":
            raise ValueError(f"unexpected row: {row}")
        name = row["input"]
        if name not in manifest or name in outputs or row["output"] != name + ".dehazed.png":
            raise ValueError(f"unknown, repeated or mismatched output: {name!r}")
        path = directory / row["output"]
        if path.resolve(strict=True) != path:
            raise ValueError(f"unexpected output symlink: {path}")
        with path.open("rb") as stream:
            header = stream.read(26)
        if header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR" or header[24:26] != b"\x10\x02":
            raise ValueError(f"expected RGB16 PNG: {name}")
        with Image.open(path) as im:
            width, height = im.size
            if (im.format, im.size, im.info.get("gamma")) != (
                "PNG", (row["width"], row["height"]), 1.0
            ) or im.info.get("chromaticity") != (.3127, .329, .64, .33, .3, .6, .15, .06):
                raise ValueError(f"wrong output image dimensions or encoding: {name}")
            im.verify()
        with Image.open(path) as im:
            im.load()
        chosen = Counter(row["tile_workers"])
        tiles = math.ceil(width / tile_edge) * math.ceil(height / tile_edge)
        if chosen != row["workers"] or sum(chosen.values()) != tiles or chosen.keys() - peers:
            raise ValueError(f"invalid placement receipt for {name}: {chosen}")
        distribution.update(chosen)
        elapsed = row["elapsed_ms"]
        if not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError(f"invalid processing time: {name}")
        photos[name] = {"elapsed_ms": elapsed, "worker_tiles": dict(chosen)}
        outputs[name] = sha256(path)
    missing_sources = sorted(manifest.keys() - outputs.keys())
    unused_workers = sorted(peers - distribution.keys())
    digest_mismatches = {}
    compared = set()
    missing_from_reference = []
    missing_from_outputs = []
    if reference is not None:
        missing_from_reference = sorted(outputs.keys() - reference.keys())
        missing_from_outputs = sorted(reference.keys() - outputs.keys())
        compared = outputs.keys() & reference.keys()
        digest_mismatches = {
            name: {"expected": reference[name], "actual": outputs[name]}
            for name in sorted(compared)
            if outputs[name] != reference[name]
        }
    if missing_sources or unused_workers or digest_mismatches or missing_from_reference or missing_from_outputs:
        messages = []
        if missing_sources:
            messages.append(f"missing RAW sources: {missing_sources!r}")
        if unused_workers:
            messages.append(f"no tiles on specified workers: {unused_workers!r}")
        if digest_mismatches:
            messages.append(f"rendered PNG digest mismatch: {list(digest_mismatches)!r}")
        if missing_from_reference:
            messages.append(f"outputs without reference hashes: {missing_from_reference!r}")
        if missing_from_outputs and missing_from_outputs != missing_sources:
            messages.append(f"reference outputs absent: {missing_from_outputs!r}")
        raise BatchVerificationError(". ".join(messages), {
            "missing_sources": missing_sources,
            "unused_workers": unused_workers,
            "worker_tiles": {peer: distribution[peer] for peer in sorted(peers)},
            "photos": photos,
            "output_sha256": outputs,
            "digest_mismatches": digest_mismatches,
            "missing_from_reference": missing_from_reference,
            "missing_from_outputs": missing_from_outputs,
            "compared_output_hashes_match": not digest_mismatches if compared else None,
        })
    return outputs, dict(distribution), photos


def benchmark(args, report):
    sources = args.input_dir.resolve(strict=True)
    scratch = args.scratch.resolve(strict=True)
    if scratch == sources or scratch.is_relative_to(sources):
        raise ValueError("choose a scratch directory outside the input tree")
    manifest = json.loads(args.manifest.read_bytes())
    validate_inputs(sources, manifest)
    cli = args.cli.resolve(strict=True)
    local, mesh = profile_env(args.single_home), profile_env(args.mesh_home)
    local_status, mesh_status = [cli_json(cli, env, "mesh", "status") for env in (local, mesh)]
    local_id = local_status["local_peer_id"]
    peers = set(args.worker)
    if len(peers) != len(args.worker) or mesh_status["local_peer_id"] in peers:
        raise ValueError("provide distinct remote mesh workers, excluding the mesh coordinator")
    if args.plugin not in cli_json(cli, local, "plugins", "list")["plugins"]:
        raise ValueError("single-machine profile must have the named plugin loaded")
    if cli_json(cli, mesh, "plugins", "list")["plugins"]:
        raise ValueError("use a mesh coordinator with an empty plugin registry")
    report.update(cli_sha256=sha256(cli), input_manifest_sha256=sha256(args.manifest),
                  photographs=len(manifest), submission_host=platform.uname()._asdict(),
                  plugin=args.plugin, jobs=args.jobs, tile_edge=args.tile_edge,
                  single_peer=local_id, coordinator=mesh_status["local_peer_id"],
                  mesh_workers=sorted(peers), trials=[], verified_output_sha256={})
    routes = {"single": (local, {local_id}), "mesh": (mesh, peers)}
    times = {name: [] for name in routes}
    for pair in range(args.trials + 1):
        # The first complete pair warms both routes; then reverse the order on alternate pairs.
        for route in (("single", "mesh") if pair % 2 == 0 else ("mesh", "single")):
            env, allowed = routes[route]
            entry = {"pair": pair, "route": route, "warmup": pair == 0}
            report["trials"].append(entry)
            with tempfile.TemporaryDirectory(prefix="raw-benchmark-", dir=scratch) as tmp:
                out = Path(tmp) / "images"
                cmd = [cli, "image", "dehaze", "--recursive", sources, "--output-dir", out,
                       "--plugin", args.plugin, "--jobs", str(args.jobs), "--tile-edge",
                       str(args.tile_edge), "--json"]
                for peer in sorted(allowed):
                    cmd.extend(["--allow", peer])
                start = time.perf_counter()
                proc = subprocess.run(cmd, capture_output=True, env=env, timeout=args.timeout)
                entry["wall_s"] = time.perf_counter() - start
                entry["exit_code"] = proc.returncode
                if proc.returncode:
                    failed = [row for row in proc.stdout.splitlines() if b'"failed"' in row]
                    raise ValueError(f"batch failed: {proc.stderr[-1500:]!r}, last failure {failed[-2:]!r}")
                reference = report["verified_output_sha256"] or None
                try:
                    outputs, placement, photos = verify_run(
                        proc.stdout, out, manifest, allowed, args.tile_edge, reference
                    )
                except BatchVerificationError as error:
                    entry["failed_verification"] = error.observations
                    raise
                if reference is None:
                    report["verified_output_sha256"] = outputs
                ms = sorted(photo["elapsed_ms"] for photo in photos.values())
                entry.update(worker_tiles=placement, photos=photos, p50_image_ms=statistics.median(ms),
                             p95_image_ms=ms[math.ceil(.95 * len(ms)) - 1])
                if pair:
                    times[route].append(entry["wall_s"])
    validate_inputs(sources, manifest)
    report["median_wall_s"] = {k: statistics.median(v) for k, v in times.items()}
    report["median_wall_speedup"] = report["median_wall_s"]["single"] / report["median_wall_s"]["mesh"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "input-dir", "manifest", "single-home", "mesh-home", "scratch", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--worker", required=True, action="append", help="full remote peer ID, repeat per worker")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--tile-edge", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=86400, help="per-batch wall time limit in seconds")
    args = parser.parse_args()
    if args.trials < 3 or not (args.tile_edge > 0 and math.isfinite(args.timeout) and args.timeout > 0):
        parser.error("require at least three timed pairs, a positive tile edge, and a finite positive timeout")
    report = {}
    with args.report.open("x", encoding="utf-8") as dest:
        try:
            benchmark(args, report)
        except BaseException as error:
            report["error"] = str(error)
            raise
        finally:
            json.dump(report, dest, indent=2, allow_nan=False)
            dest.write("\n")


if __name__ == "__main__":
    main()
