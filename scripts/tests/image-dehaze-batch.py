#!/usr/bin/env python3
"""Exercise recursive RAW dehaze through two authenticated local worker daemons.

This is an integration test, not the three-physical-desktop performance gate.
It creates its own deterministic Bayer DNG files, identities and signing key.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import re
import socket
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import tomllib
import zlib

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("daemon_fixture", ROOT / "scripts/tests/distributed-rust-tests.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SRGB_CHROMATICITIES = (31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000)


def chunk(name, data):
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))


def warmup_png():
    width, height = 32, 32
    raw = b"".join(b"\0" + b"".join(struct.pack(">HHH", 10000 + x * 300, 18000 + y * 300, 14000)
                                      for x in range(width)) for y in range(height))
    return (PNG_SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 16, 2, 0, 0, 0))
            + chunk(b"gAMA", struct.pack(">I", 100000))
            + chunk(b"cHRM", struct.pack(">8I", *SRGB_CHROMATICITIES))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def encode_linear_png(width, height, pixels):
    """Independent RGB16 PNG encoder for the full-frame comparison."""
    if len(pixels) != width * height * 6:
        raise ValueError("bad source raster length")
    stride = width * 6
    raw = b"".join(b"\0" + pixels[y * stride:(y + 1) * stride] for y in range(height))
    return (PNG_SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 16, 2, 0, 0, 0))
            + chunk(b"gAMA", struct.pack(">I", 100000))
            + chunk(b"cHRM", struct.pack(">8I", *SRGB_CHROMATICITIES))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def decode_linear_png(data):
    """Independently decode bounded non-interlaced RGB16 PNG bytes and check color tags."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG")
    pos, chunks, compressed, ended = 8, {}, bytearray(), False
    while pos < len(data):
        if pos + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        size = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        end = pos + 12 + size
        if end > len(data):
            raise ValueError("truncated PNG payload")
        value = data[pos + 8:pos + 8 + size]
        if zlib.crc32(kind + value) != struct.unpack_from(">I", data, pos + 8 + size)[0]:
            raise ValueError("bad PNG CRC")
        if kind == b"IDAT":
            compressed.extend(value)
        elif kind in (b"IHDR", b"gAMA", b"cHRM"):
            if kind in chunks:
                raise ValueError("duplicate PNG header/color chunk")
            chunks[kind] = value
        pos = end
        if kind == b"IEND":
            if value:
                raise ValueError("nonempty PNG end chunk")
            ended = True
            break
    if not ended or pos != len(data) or b"IHDR" not in chunks:
        raise ValueError("PNG missing end/header or contains trailing bytes")
    width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunks[b"IHDR"])
    if not (0 < width <= 4096 and 0 < height <= 4096 and width * height <= 2_500_000):
        raise ValueError("unexpected image dimensions")
    if (depth, color, compression, filtering, interlace) != (16, 2, 0, 0, 0):
        raise ValueError("expected non-interlaced RGB16 PNG")
    if chunks.get(b"gAMA") != struct.pack(">I", 100000):
        raise ValueError("missing linear gamma")
    if chunks.get(b"cHRM") != struct.pack(">8I", *SRGB_CHROMATICITIES):
        raise ValueError("missing canonical sRGB chromaticity")
    stride = width * 6
    expected = height * (stride + 1)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(compressed), expected + 1)
    if len(raw) != expected or not decoder.eof or decoder.unused_data:
        raise ValueError("invalid decompressed PNG length")
    out, previous = bytearray(), bytearray(stride)
    for y in range(height):
        row = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        mode = raw[y * (stride + 1)]
        for i in range(stride):
            left = row[i - 6] if i >= 6 else 0
            up = previous[i]
            upper_left = previous[i - 6] if i >= 6 else 0
            if mode == 1:
                pred = left
            elif mode == 2:
                pred = up
            elif mode == 3:
                pred = (left + up) // 2
            elif mode == 4:
                p = left + up - upper_left
                distances = (abs(p - left), abs(p - up), abs(p - upper_left))
                pred = (left, up, upper_left)[distances.index(min(distances))]
            elif mode == 0:
                pred = 0
            else:
                raise ValueError("invalid PNG filter")
            row[i] = (row[i] + pred) & 255
        out.extend(row)
        previous = row
    return width, height, bytes(out)


def verify_png_oracle():
    """Reject malformed controls so the reference parser cannot silently accept them."""
    good = warmup_png()
    if decode_linear_png(good)[:2] != (32, 32):
        raise AssertionError("PNG oracle failed its positive control")
    malformed = [good[:-12], good + b"extra", good[:33] + bytes([good[33] ^ 1]) + good[34:]]
    for value in malformed:
        try:
            decode_linear_png(value)
        except ValueError:
            continue
        raise AssertionError("PNG oracle accepted a malformed control")


def synthetic_dng(width=512, height=384, seed=0):
    """Generate a minimal uncompressed CFA DNG, without third-party camera data."""
    if width < 64 or height < 64 or width % 2 or height % 2:
        raise ValueError("fixture dimensions must be even and at least 64")
    tags = []
    def put(number, kind, count, data):
        tags.append((number, kind, count, data))
    def shorts(*v):
        return struct.pack("<" + "H" * len(v), *v)
    def longs(*v):
        return struct.pack("<" + "I" * len(v), *v)
    def rational(*v):
        return b"".join(struct.pack("<II", *p) for p in v)
    def signed_rational(*v):
        return b"".join(struct.pack("<ii", *p) for p in v)
    put(254, 4, 1, longs(0)); put(256, 4, 1, longs(width)); put(257, 4, 1, longs(height))
    put(258, 3, 1, shorts(16)); put(259, 3, 1, shorts(1)); put(262, 3, 1, shorts(32803))
    put(271, 2, 9, b"Entangle\0"); put(272, 2, 12, b"Test Camera\0")
    put(273, 4, 1, longs(0)); put(274, 3, 1, shorts(1)); put(277, 3, 1, shorts(1))
    put(278, 4, 1, longs(height)); put(279, 4, 1, longs(width * height * 2)); put(284, 3, 1, shorts(1))
    put(33421, 3, 2, shorts(2, 2)); put(33422, 1, 4, bytes((0, 1, 1, 2)))
    put(50706, 1, 4, bytes((1, 4, 0, 0))); put(50707, 1, 4, bytes((1, 1, 0, 0)))
    put(50708, 2, 21, b"Entangle Test Camera\0"); put(50710, 1, 3, bytes((0, 1, 2)))
    put(50711, 3, 1, shorts(1)); put(50714, 3, 1, shorts(0)); put(50717, 4, 1, longs(65535))
    put(50721, 10, 9, signed_rational((1, 1), (0, 1), (0, 1), (0, 1), (1, 1), (0, 1), (0, 1), (0, 1), (1, 1)))
    put(50728, 5, 3, rational((1, 1), (1, 1), (1, 1))); put(50778, 3, 1, shorts(21))
    put(50829, 4, 4, longs(0, 0, height, width)); tags.sort()
    base = 8 + 2 + len(tags) * 12 + 4
    extra, entries = bytearray(), []
    for number, kind, count, data in tags:
        if len(data) > 4:
            if (base + len(extra)) % 2:
                extra.append(0)
            offset = base + len(extra)
            extra.extend(data)
            data = longs(offset)
        entries.append([number, kind, count, data.ljust(4, b"\0")])
    pixel_offset = base + len(extra)
    pixel_offset += pixel_offset % 2
    for entry in entries:
        if entry[0] == 273:
            entry[3] = longs(pixel_offset)
    result = bytearray(b"II" + shorts(42) + longs(8) + shorts(len(tags)))
    for number, kind, count, data in entries:
        result.extend(struct.pack("<HHI", number, kind, count) + data)
    result.extend(longs(0) + extra)
    result.extend(b"\0" * (pixel_offset - len(result)))
    for y in range(height):
        for x in range(width):
            value = 5000 + 35000 * x // (width - 1) + 9000 * y // (height - 1)
            value += 2500 if ((x // 24 + y // 24 + seed) % 2) else 0
            value = max(1, min(60000, value + seed * 173))
            result.extend(shorts(value))
    return bytes(result)


def independently_decode_dng(path):
    """Use explicit LibRaw linear 16-bit flags, independently of the CLI staging path."""
    result = subprocess.run(["dcraw_emu", "-6", "-W", "-g", "1", "1", "-o", "1", "-w", "-Z", "-", str(path)],
                            capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"independent LibRaw decode failed: {result.stderr.decode(errors='replace')}")
    parts = result.stdout.split(b"\n", 3)
    if len(parts) != 4 or parts[0] != b"P6" or parts[2] != b"65535":
        raise ValueError("independent decoder did not produce full-scale RGB16 PPM")
    width, height = map(int, parts[1].split())
    if len(parts[3]) != width * height * 6:
        raise ValueError("independent decoder returned truncated or trailing raster")
    return width, height, parts[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_blake3(tool, path, expected):
    """Optionally check receipt hashes with an independently invoked BLAKE3 tool."""
    digest = subprocess.check_output([str(tool), str(path)], text=True, timeout=30).split()[0]
    if digest != expected:
        raise AssertionError(f"reported BLAKE3 does not match bytes: {path}")


def run_cli(node, args, *, success=True, timeout=180):
    result = subprocess.run([str(node.binaries / "entangle"), *map(str, args)], env=node.env,
                            capture_output=True, text=True, timeout=timeout)
    if (result.returncode == 0) != success:
        raise RuntimeError(f"command {args!r} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result


def parsed_rows(text):
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"non-JSON output line: {line!r}") from exc
    if not rows or rows[-1].get("status") != "summary":
        raise RuntimeError(f"missing summary in {rows!r}")
    return rows[:-1], rows[-1]


def await_worker(node, plugin, worker, temp):
    """Use a separately directed valid guest request as a bounded discovery warmup."""
    source = temp / ("warmup-" + worker.peer + ".png")
    source.write_bytes(warmup_png())
    args = [node.binaries / "entangle", "compute", "dispatch", plugin, "--input-file", source,
            "--integrity", "trusted-executor", "--allow", worker.peer, "--raw"]
    deadline = time.monotonic() + 45
    while True:
        result = subprocess.run(args, env=node.env, capture_output=True, timeout=45)
        if result.returncode == 0:
            if worker.peer.encode() not in result.stderr:
                raise RuntimeError(f"warmup selected unexpected peer: {result.stderr!r}")
            decode_linear_png(result.stdout)
            return
        if b"no live workers" not in result.stderr.lower() or time.monotonic() >= deadline:
            raise RuntimeError(f"worker warmup failed: {result.stderr.decode(errors='replace')}")
        time.sleep(0.1)


def invocation_count(node):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(8)
        sock.connect(str(node.socket))
        sock.sendall(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "metrics"}).encode() + b"\n")
        with sock.makefile("rb") as response:
            reply = json.loads(response.readline(1024 * 1024))
    if reply.get("id") != 1 or "result" not in reply:
        raise RuntimeError(f"unexpected worker metrics response: {reply!r}")
    return sum(int(n) for n in re.findall(
        r'(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$', reply["result"]))


def dehaze(node, plugin, source, output, peers, *extra, success=True):
    args = ["image", "dehaze", "--recursive", source, "--output-dir", output, "--plugin", plugin,
            "--tile-edge", "256", "--jobs", "4", "--json"]
    for peer in peers:
        args.extend(("--allow", peer))
    return run_cli(node, [*args, *extra], success=success)


def start_cluster(binaries, wasm, root, stack):
    """Start an empty coordinator and two authenticated image-dehaze workers."""
    root = Path(root)
    coordinator = fixture.Node(root / "coordinator", binaries)
    workers = [fixture.Node(root / f"worker-{i}", binaries) for i in range(2)]
    package = root / "package"
    coordinator.cli("plugins", "build", ROOT / "plugins/image-dehaze", "--wasm", wasm, "--out", package)
    plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
    routes = []
    for worker in workers:
        coordinator.trust(worker)
        worker.trust(coordinator)
        worker.cli("keyring", "add", coordinator.key, "--name", "dehaze fixture publisher")
        port = fixture.free_port()
        worker.start(stack, port, [])
        worker.cli("plugins", "load", package)
        routes.append(f"{worker.key}@127.0.0.1:{port}")
    coordinator.start(stack, 0, routes)
    for worker in workers:
        await_worker(coordinator, plugin, worker, root)
    return coordinator, workers, plugin


def exercise(binaries, wasm, b3sum=None):
    verify_png_oracle()
    with tempfile.TemporaryDirectory(prefix="ent-dehaze-test-") as tmp, ExitStack() as stack:
        root = Path(tmp)
        coordinator, workers, plugin = start_cluster(binaries, wasm, root, stack)
        source = root / "inputs"
        source.mkdir()
        paths = ["alpha/a.dng", "alpha/b.dng", "beta/a.dng", "beta/b.dng"]
        for index, relative in enumerate(paths):
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(synthetic_dng(seed=index))
        (source / "notes.txt").write_text("non-image sidecar\n")
        original = {p: sha(source / p) for p in paths}
        outputs, placements, live_rows = {}, {}, {}
        for label, peers in [("first", [workers[0].peer]), ("second", [workers[1].peer]),
                             ("shared", [w.peer for w in workers])]:
            out = root / ("out-" + label)
            counters_before = {worker.peer: invocation_count(worker) for worker in workers}
            result = dehaze(coordinator, plugin, source, out, peers)
            rows, summary = parsed_rows(result.stdout)
            if summary.get("processed") != len(paths) or summary.get("failed") != 0 or summary.get("skipped") != 1:
                raise AssertionError((label, summary, result.stderr))
            if {row["input"] for row in rows} != set(paths):
                raise AssertionError((label, rows))
            pixels, counts = {}, Counter()
            for row in rows:
                if row.get("status") != "processed" or not row.get("workers"):
                    raise AssertionError((label, row))
                expected_path = row["input"] + ".dehazed.png"
                if row["output"] != expected_path:
                    raise AssertionError((label, row))
                if row.get("width") != 512 or row.get("height") != 384:
                    raise AssertionError(f"incorrect receipt dimensions: {row}")
                for key in ("input_blake3", "output_blake3"):
                    if not isinstance(row.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", row[key]):
                        raise AssertionError(f"invalid receipt digest: {key}: {row}")
                used = row["workers"]
                if not set(used) <= set(peers) or any(not isinstance(n, int) or n <= 0 for n in used.values()):
                    raise AssertionError((label, row))
                tile_workers = row.get("tile_workers")
                if not isinstance(tile_workers, list) or len(tile_workers) != 4 or Counter(tile_workers) != Counter(used):
                    raise AssertionError(f"tile/worker accounting mismatch: {label}: {row}")
                counts.update(used)
                image = out / expected_path
                if b3sum is not None:
                    verify_blake3(b3sum, source / row["input"], row["input_blake3"])
                    verify_blake3(b3sum, image, row["output_blake3"])
                width, height, raw = decode_linear_png(image.read_bytes())
                if (width, height) != (512, 384):
                    raise AssertionError((label, row, width, height))
                pixels[row["input"]] = (hashlib.sha256(raw).hexdigest(), sha(image))
            if len(peers) == 1 and set(counts) != set(peers):
                raise AssertionError((label, counts))
            deltas = {worker.peer: invocation_count(worker) - counters_before[worker.peer] for worker in workers}
            if any(deltas[worker.peer] != counts.get(worker.peer, 0) for worker in workers):
                raise AssertionError(f"reported placement differs from actual worker completions: {label}: {counts}, {deltas}")
            outputs[label], placements[label], live_rows[label] = pixels, dict(counts), rows
        for path in paths:
            if len({outputs[label][path][0] for label in outputs}) != 1:
                raise AssertionError(f"worker or tile result differs for {path}: {outputs}")
        reports = {label: {row["input"]: row for row in rows} for label, rows in live_rows.items()}
        if len({reports["first"][path]["input_blake3"] for path in paths}) != len(paths):
            raise AssertionError("distinct source inputs received identical reported digests")
        for path in paths:
            if len({reports[label][path]["input_blake3"] for label in reports}) != 1:
                raise AssertionError(f"reported input digest changed across routes: {path}")
            if len({outputs[label][path][1] for label in outputs}) == 1 and len({reports[label][path]["output_blake3"] for label in reports}) != 1:
                raise AssertionError(f"reported output digest disagrees for identical bytes: {path}")
        if set(placements["shared"]) != {worker.peer for worker in workers}:
            raise AssertionError(f"shared run did not use both workers: {placements['shared']}")
        if {p: sha(source / p) for p in paths} != original:
            raise AssertionError("input bytes changed")

        # The inputs are local synthetic CFA; independent LibRaw gives the raw
        # linear baseline. Reject an identity/pass-through implementation.
        bw, bh, baseline = independently_decode_dng(source / paths[0])
        ow, oh, rendered = decode_linear_png((root / "out-first" / (paths[0] + ".dehazed.png")).read_bytes())
        if (bw, bh) != (ow, oh):
            raise AssertionError("rendered and independent RAW dimensions differ")
        changed = sum(abs(a[0] - b[0]) >= 64 for a, b in zip(struct.iter_unpack(">H", baseline),
                                                            struct.iter_unpack(">H", rendered)))
        if changed < (bw * bh * 3) // 100:
            raise AssertionError(f"dehaze altered fewer than 1% of RGB16 samples: {changed}")

        # One full-frame plugin invocation estimates the atmosphere itself;
        # tiled CLI processing computes a separate global atmosphere and halos.
        # Equal pixels prove seams and whole-frame behavior match on this input.
        full_frame = root / "full-frame-input.png"
        full_frame.write_bytes(encode_linear_png(bw, bh, baseline))
        command = [coordinator.binaries / "entangle", "compute", "dispatch", plugin,
                   "--input-file", full_frame, "--integrity", "trusted-executor",
                   "--allow", workers[0].peer, "--raw"]
        whole = subprocess.run(command, env=coordinator.env, capture_output=True, timeout=90)
        if whole.returncode or workers[0].peer.encode() not in whole.stderr:
            raise AssertionError(f"full-frame dispatch failed: {whole.stderr!r}")
        fw, fh, whole_pixels = decode_linear_png(whole.stdout)
        if (fw, fh) != (ow, oh) or whole_pixels != rendered:
            raise AssertionError("tiled output differs from full-frame plugin result")

        # Existing files must be protected unless their exact saved receipt verifies.
        shared = root / "out-shared"
        before_collision = {p: sha(shared / (p + ".dehazed.png")) for p in paths}
        dehaze(coordinator, plugin, source, shared, [w.peer for w in workers], success=False)
        if {p: sha(shared / (p + ".dehazed.png")) for p in paths} != before_collision:
            raise AssertionError("collision changed a preexisting output")
        counts_before_resume = {worker.peer: invocation_count(worker) for worker in workers}
        resumed = dehaze(coordinator, plugin, source, shared, [w.peer for w in workers], "--resume")
        rows, summary = parsed_rows(resumed.stdout)
        if summary.get("resumed") != len(paths) or summary.get("failed") != 0:
            raise AssertionError((rows, summary))
        if {row["input"] for row in rows if row.get("status") == "resumed"} != set(paths):
            raise AssertionError(rows)
        if {worker.peer: invocation_count(worker) for worker in workers} != counts_before_resume:
            raise AssertionError("resume unexpectedly dispatched work")
        if {p: sha(shared / (p + ".dehazed.png")) for p in paths} != before_collision:
            raise AssertionError("resume changed verified output bytes")

        # A cached receipt cannot expand a later, narrower executor allowlist.
        excluded = {row["input"] for row in live_rows["shared"] if workers[1].peer in row["workers"]}
        if not excluded:
            raise AssertionError("shared run supplied no excluded-worker receipt to test")
        counts_before_narrow = {worker.peer: invocation_count(worker) for worker in workers}
        narrowed = dehaze(coordinator, plugin, source, shared, [workers[0].peer], "--resume", success=False)
        rows, summary = parsed_rows(narrowed.stdout)
        refused = {row["input"] for row in rows if row.get("status") == "failed"}
        if refused != excluded or summary.get("failed") != len(excluded):
            raise AssertionError((excluded, rows, summary))
        if {worker.peer: invocation_count(worker) for worker in workers} != counts_before_narrow:
            raise AssertionError("narrowed resume unexpectedly dispatched work")
        if {p: sha(shared / (p + ".dehazed.png")) for p in paths} != before_collision:
            raise AssertionError("narrowed resume changed stored outputs")

        # A modified stored output must not be accepted as a valid resumable result.
        damaged = shared / (paths[0] + ".dehazed.png")
        saved = damaged.read_bytes()
        damaged.write_bytes(saved[:-1] + bytes([saved[-1] ^ 1]))
        tampered = dehaze(coordinator, plugin, source, shared, [w.peer for w in workers], "--resume", success=False)
        rows, summary = parsed_rows(tampered.stdout)
        if summary.get("failed") != 1 or not any(row.get("input") == paths[0] and row.get("status") == "failed" for row in rows):
            raise AssertionError((rows, summary))
        damaged.write_bytes(saved)

        # Output roots cannot be nested under the source tree.
        nested = source / "unexpected-output"
        dehaze(coordinator, plugin, source, nested, [workers[0].peer], success=False)
        if nested.exists():
            raise AssertionError("nested output root was created")

        # One malformed RAW fails independently; a valid neighbor must survive.
        mixed_source = root / "mixed-input"
        mixed_source.mkdir()
        (mixed_source / "good.dng").write_bytes(synthetic_dng(seed=8))
        (mixed_source / "broken.dng").write_bytes(b"not a DNG\n")
        mixed_out = root / "mixed-output"
        partial = dehaze(coordinator, plugin, mixed_source, mixed_out, [workers[0].peer], success=False)
        rows, summary = parsed_rows(partial.stdout)
        statuses = {row["input"]: row["status"] for row in rows}
        if statuses != {"good.dng": "processed", "broken.dng": "failed"} or summary.get("failed") != 1:
            raise AssertionError((statuses, summary, partial.stderr))
        if (mixed_out / "broken.dng.dehazed.png").exists():
            raise AssertionError("invalid RAW produced an output")
        decode_linear_png((mixed_out / "good.dng.dehazed.png").read_bytes())
        (mixed_source / "broken.dng").write_bytes(synthetic_dng(seed=9))
        recovered = dehaze(coordinator, plugin, mixed_source, mixed_out, [workers[0].peer], "--resume")
        rows, summary = parsed_rows(recovered.stdout)
        statuses = {row["input"]: row["status"] for row in rows}
        if statuses != {"good.dng": "resumed", "broken.dng": "processed"} or summary.get("failed") != 0:
            raise AssertionError((statuses, summary, recovered.stderr))
        decode_linear_png((mixed_out / "broken.dng.dehazed.png").read_bytes())

        # Bad/unknown peers must not deliver a valid output; a known peer works afterward.
        single = root / "single-input"
        single.mkdir()
        (single / "one.dng").write_bytes(synthetic_dng(seed=10))
        malformed_out = root / "bad-peer-output"
        dehaze(coordinator, plugin, single, malformed_out, ["not-a-peer"], success=False)
        if malformed_out.exists() and list(malformed_out.rglob("*.png")):
            raise AssertionError("malformed peer produced output")
        unknown_out = root / "unknown-peer-output"
        dehaze(coordinator, plugin, single, unknown_out, ["0" * 32], success=False)
        if unknown_out.exists() and list(unknown_out.rglob("*.png")):
            raise AssertionError("untrusted peer produced output")
        # Bound directory traversal depth and staged RAW bytes without large allocations.
        deep_source = root / "deep-input"
        deep_source.mkdir()
        deep = deep_source
        for _ in range(129):
            deep = deep / "d"
            deep.mkdir()
        (deep / "one.dng").write_bytes(synthetic_dng(seed=11))
        deep_out = root / "deep-output"
        too_deep = dehaze(coordinator, plugin, deep_source, deep_out, [workers[0].peer], success=False)
        if "nesting exceeds" not in too_deep.stderr.lower() or (deep_out.exists() and list(deep_out.rglob("*.png"))):
            raise AssertionError(f"deep path was not rejected: {too_deep.stderr}")
        oversized_source = root / "oversized-input"
        oversized_source.mkdir()
        with (oversized_source / "large.dng").open("wb") as file:
            file.truncate((128 << 20) + 1)
        before_oversize = {worker.peer: invocation_count(worker) for worker in workers}
        oversized = dehaze(coordinator, plugin, oversized_source, root / "oversized-output", [workers[0].peer], success=False)
        rows, summary = parsed_rows(oversized.stdout)
        if summary.get("failed") != 1 or len(rows) != 1 or rows[0].get("status") != "failed" or "128" not in rows[0].get("error", ""):
            raise AssertionError((rows, summary, oversized.stderr))
        if {worker.peer: invocation_count(worker) for worker in workers} != before_oversize:
            raise AssertionError("oversized RAW reached a worker")

        final_out = root / "recovered-output"
        final = dehaze(coordinator, plugin, single, final_out, [workers[1].peer])
        rows, summary = parsed_rows(final.stdout)
        if len(rows) != 1 or rows[0].get("status") != "processed" or summary.get("failed") != 0:
            raise AssertionError((rows, summary))
        if set(rows[0].get("workers", {})) != {workers[1].peer}:
            raise AssertionError("recovery selected unexpected worker")
        decode_linear_png((final_out / "one.dng.dehazed.png").read_bytes())
        return {"inputs_sha256": original, "decoded_pixel_and_file_sha256": outputs,
                "tile_counts_by_peer": placements, "peers": [w.peer for w in workers],
                "independent_raw_changed_samples_at_least_64": changed,
                "tiled_equals_full_frame_pixels": True,
                "collision_refused": True, "resume_verified": True, "narrowed_allowlist_refused": True,
                "malformed_raw_and_peer_recovery": True,
                "oversized_raw_and_directory_depth_refused": True,
                "independent_blake3_receipts_checked": b3sum is not None,
                "scope": "two local authenticated worker daemons; not a multi-host benchmark"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--b3sum", type=Path, help="optional BLAKE3 executable to independently verify receipt hashes")
    args = parser.parse_args()
    tool = args.b3sum.resolve(strict=True) if args.b3sum else None
    print(json.dumps(exercise(args.bin_dir.resolve(strict=True), args.wasm.resolve(strict=True), tool), indent=2))


if __name__ == "__main__":
    main()
