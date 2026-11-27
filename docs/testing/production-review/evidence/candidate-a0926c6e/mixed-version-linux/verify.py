#!/usr/bin/env python3
"""Verify a common signed WASI guest across two archived Linux releases."""
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

from PIL import Image, __version__ as pillow_version

OLD = "bb70a6193f8879b1feb3e6d3ceb8f2980413ce58"
NEW = "a0926c6ef3471aad01cedd256028437b249ef747"
SOURCE = "sha256:a2848766dd5b69cf72246e7cba06c95afe1807d2556f00efec115cdd40cdca45"
GUESTS = {"image-resize": "b3ad4285a7f71a0377291a4e13676883bb419e815f7fe7e44b9771e615e44983",
          "image-dehaze": "eb0e482edfa642479d5b16caccf39b8e4dac4c4d290699fe6d97ee5d9103b973"}
ROOT = Path(sys.argv[1]).resolve(strict=True)
OUT = Path(sys.argv[2]).resolve()
LEDGER = ROOT / "docs/testing/production-review/evidence"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("batch", ROOT / "scripts/tests/image-dehaze-batch.py")
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source():
    return subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"], cwd=ROOT, text=True).strip()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def rpc(node, method, params=None):
    request = {"id": "mixed-linux-compatibility", "method": method, "jsonrpc": "2.0", "params": params}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as fd:
        fd.settimeout(5)
        fd.connect(str(node.socket))
        fd.sendall(json.dumps(request).encode() + b"\n")
        with fd.makefile("rb") as reader:
            response = json.loads(reader.readline(128 * 1024))
    assert response["id"] == request["id"] and response["jsonrpc"] == "2.0"
    return response


def node(home, cli):
    new = batch.fixture.Node(home, cli)
    new.env.pop("ENTANGLE_ALLOW_LOCAL", None)
    return new


def call(log, cli, env, *arguments, expected=0, binary=False):
    command = [str(cli), *map(str, arguments)]
    proc = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    log.append({"argv": command, "exit_code": proc.returncode, "expected": expected,
                "stderr": proc.stderr.decode(errors="replace"),
                "stdout": {"sha256": digest(proc.stdout), "bytes": len(proc.stdout)} if binary
                else proc.stdout.decode(errors="replace")})
    assert proc.returncode == expected, (command, proc.stderr.decode(errors="replace"))
    return proc


def unpack(archive, commit, target):
    metadata = json.loads((LEDGER / f"candidate-{commit[:8]}" / "linux-archive.json").read_text())
    assert metadata["source_commit"] == commit and metadata["source_id"] == metadata["source_after"]
    assert archive.stat().st_size == metadata["size"] and sha(archive) == metadata["sha256"]
    target.mkdir()
    hashes = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for name in ("entangle", "entangled"):
            filename = metadata["name"].removesuffix(".tar.gz") + "/" + name
            entries = [entry for entry in bundle.getmembers() if entry.name == filename]
            assert len(entries) == 1 and entries[0].isreg()
            value = bundle.extractfile(entries[0]).read()
            assert value.startswith(b"\x7fELF\x02\x01") and value[18:20] == b"\x3e\x00"
            hashes[name] = digest(value)
            assert hashes[name] == metadata["files_sha256"][name]
            (target / name).write_bytes(value)
            (target / name).chmod(0o700)
    return {"source_commit": commit, "source_id": metadata["source_id"], "path": str(archive),
            "archive_sha256_before": sha(archive), "elf_sha256_before": hashes}


def signed_package(work, publisher, name, component, report):
    package = work / (name + "-package")
    call(report["commands"], publisher.binaries / "entangle", publisher.env, "plugins", "build",
         ROOT / "plugins" / name, "--wasm", component, "--out", package)
    manifest = tomllib.loads((package / "entangle.toml").read_text())
    assert manifest["build"]["wit_world"] == "entangle:plugin@0.1.0/plugin"
    assert manifest["plugin"]["tier"] == 1 and manifest["plugin"]["runtime"] == "wasm"
    hashes = {file.name: sha(file) for file in package.iterdir() if file.is_file()}
    assert hashes["plugin.wasm"] == GUESTS[name] and "plugin.wasm.sig" in hashes
    report["guests"][name]["signed_package"] = {"sha256": hashes, "manifest": manifest}
    return package, manifest["plugin"]["id"]


def footprint(work):
    width, height = 17, 13
    rgb = bytes((19*x + 29*y + 41*c) % 256 for y in range(height) for x in range(width) for c in range(3))
    encoded = io.BytesIO()
    Image.frombytes("RGB", (width, height), rgb).save(encoded, "PNG")
    payload = work / "resize.bin"
    payload.write_bytes(b'{"width":34,"height":26,"format":"png","filter":"nearest"}\n' + encoded.getvalue())
    expected = bytes(rgb[(y//2 * width + x//2) * 3 + c] for y in range(26) for x in range(34) for c in range(3))
    return payload, expected


def start_local(target, daemon, stack):
    # The mixed UDS rows share a host and use the daemon's local executor.
    # Keep mesh transport off there. The separately paired RAW row uses QUIC.
    (target.state / "config.toml").write_text("[mesh]\ntransports=[]\n")
    log_path = target.directory / "daemon.log"
    log = stack.enter_context(log_path.open("wb"))
    process = subprocess.Popen([daemon / "entangled", "run"], env=target.env, stdout=log, stderr=log)

    def stop():
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    stack.callback(stop)
    deadline = time.monotonic() + 12
    while not target.socket.is_socket():
        assert process.poll() is None and time.monotonic() < deadline, log_path.read_text()
        time.sleep(.05)


def mixed(work, label, client, daemon, publisher, package, plugin, payload, expected_pixels, row):
    target = node(work / label, client)
    cli = client / "entangle"
    invoke = lambda *args, **kw: call(row["commands"], cli, target.env, *args, **kw)
    row.update(peer=target.peer, cli_sha256=sha(cli), daemon_sha256=sha(daemon / "entangled"), plugin=plugin)
    with ExitStack() as stack:
        start_local(target, daemon, stack)
        assert stat.S_IMODE(target.socket.stat().st_mode) == 0o600
        assert re.search(rb"(?m)^\s*Status\s+reachable\s*$", invoke("version").stdout)
        row["version"] = rpc(target, "version")["result"]
        assert row["version"]["entangled"] == "0.1.0"
        assert rpc(target, "mesh/status")["result"]["local_peer_id"] == target.peer
        assert rpc(target, "plugins/list")["result"]["plugins"] == []
        refused = invoke("plugins", "load", package, expected=1).stderr.lower()
        assert b"untrusted" in refused or b"keyring" in refused, refused
        invoke("keyring", "add", publisher.key, "--name", "Mixed version test publisher")
        invoke("plugins", "load", package)
        assert plugin.encode() in invoke("plugins", "list").stdout
        assert rpc(target, "plugins/list")["result"]["plugins"] == [plugin]

        output = OUT / (label + ".png")
        placement = invoke("compute", "dispatch", plugin, "--input-file", payload, "--output-file", output)
        assert target.peer.encode() in placement.stderr
        png = output.read_bytes()
        assert png.startswith(b"\x89PNG\r\n\x1a\n")
        try:
            png.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            raise AssertionError("expected non-UTF8 PNG bytes")
        with Image.open(io.BytesIO(png)) as image:
            assert image.format == "PNG" and image.size == (34, 26) and image.convert("RGB").tobytes() == expected_pixels
        exact = invoke("compute", "dispatch", plugin, "--input-file", payload, "--raw", binary=True)
        assert exact.stdout == png and target.peer.encode() in exact.stderr
        row["output"] = {"path": output.name, "sha256": digest(png), "bytes": len(png),
                         "pixel_sha256": digest(expected_pixels), "raw_equals_file": True}

        failed_file = work / (label + "-unexpected")
        error = invoke("compute", "dispatch", "invalid-id", "--input-file", payload, "--output-file", failed_file, expected=1)
        assert b"rpc -32602: invalid plugin id" in error.stderr and not failed_file.exists(), error.stderr
        invalid_params = {"plugin_id": plugin, "input": [256], "timeout_ms": 1000, "cpu_cores": 0,
                          "memory_bytes": 0, "gpu_required": False, "gpu_vram_min_bytes": 0,
                          "integrity": {"kind": "none"}}
        row["typed_error"] = rpc(target, "compute/dispatch", invalid_params)
        assert row["typed_error"]["error"]["code"] == -32602
        assert "invalid params" in row["typed_error"]["error"]["message"]
    log = OUT / (label + ".daemon.log")
    log.write_bytes((target.directory / "daemon.log").read_bytes())
    row["daemon_log_sha256"] = sha(log)


def synthetic_raw(work, old, new, publisher, package, plugin, row):
    coordinator, worker = (node(work / ("raw-" + role), old) for role in ("coordinator", "worker"))
    row.update(coordinator_peer=coordinator.peer, worker_peer=worker.peer, daemon_sha256=sha(old / "entangled"),
               client_sha256=sha(new / "entangle"), fixture_source_sha256=sha(Path(batch.__file__)))
    with ExitStack() as stack:
        coordinator.trust(worker)
        worker.trust(coordinator)
        worker.cli("keyring", "add", publisher.key, "--name", "Mixed version RAW publisher")
        port = batch.fixture.free_port()
        worker.start(stack, port, [])
        worker.cli("plugins", "load", package)
        coordinator.start(stack, 0, [f"{worker.key}@127.0.0.1:{port}"])
        assert rpc(coordinator, "plugins/list")["result"]["plugins"] == []
        batch.await_worker(coordinator, plugin, worker, work)
        before = batch.invocation_count(worker)
        input_dir, output = work / "raw-photos", work / "raw-result"
        input_dir.mkdir()
        dng = input_dir / "photo.dng"
        dng.write_bytes(batch.synthetic_dng(width=256, height=192, seed=3))
        initial = sha(dng)
        result = call(row["commands"], new / "entangle", coordinator.env, "image", "dehaze",
                      "--recursive", input_dir, "--output-dir", output, "--plugin", plugin,
                      "--allow", worker.peer, "--tile-edge", 128, "--jobs", 1, "--json")
        photos, summary = batch.parsed_rows(result.stdout)
        photo, = photos
        assert summary["processed"] == 1 and summary["failed"] == 0 and photo["status"] == "processed"
        assert photo["tile_workers"] == [worker.peer] * 4 and photo["workers"] == {worker.peer: 4}
        assert batch.invocation_count(worker) - before == 4
        png = (output / photo["output"]).read_bytes()
        dimensions = (256, 192)
        width, height, pixels = batch.decode_linear_png(png)
        assert (width, height) == dimensions and sha(dng) == initial
        rw, rh, raster = batch.independently_decode_dng(dng)
        assert (rw, rh) == dimensions and raster != pixels
        whole = work / "reference-linear.png"
        whole.write_bytes(batch.encode_linear_png(rw, rh, raster))
        reference = call(row["commands"], old / "entangle", coordinator.env, "compute", "dispatch", plugin,
                         "--input-file", whole, "--integrity", "trusted-executor", "--allow", worker.peer, "--raw", binary=True)
        assert worker.peer.encode() in reference.stderr and batch.decode_linear_png(reference.stdout) == (rw, rh, pixels)
        (OUT / "raw-dehazed.png").write_bytes(png)
        row.update(photo=photo, summary=summary, input_sha256=initial, output_sha256=digest(png),
                   pixel_sha256=digest(pixels), output_bytes=len(png), whole_frame_pixel_parity=True)
    for role, target in [("coordinator", coordinator), ("worker", worker)]:
        log = OUT / f"raw-{role}.daemon.log"
        log.write_bytes((target.directory / "daemon.log").read_bytes())
        row[role + "_log_sha256"] = sha(log)


def main():
    response = {"argv": [sys.executable, *sys.argv], "source_before": source(), "started_utc": utc(),
                "host": [platform.system(), platform.machine(), platform.release(), platform.libc_ver(), pillow_version],
                "harness_sha256": sha(Path(__file__)), "archives": {}, "guests": {}, "rows": {}, "commands": []}
    status = 1
    try:
        assert response["source_before"] == SOURCE and response["host"][:2] == ["Linux", "x86_64"]
        git = ["git", "-C", str(ROOT)]
        assert subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip() == NEW
        subprocess.run([*git, "diff", "--exit-code", OLD, NEW, "--", "plugins/image-resize", "crates/entangle-wit/wit"], check=True)
        guest_dir = ROOT / "target/catalog-smoke/wasm32-wasip2/release"
        components = {name: guest_dir / ("entangle_" + name.replace("-", "_") + ".wasm") for name in GUESTS}
        for name, path in components.items():
            assert path.read_bytes().startswith(b"\0asm\x0d\0\x01\0") and sha(path) == GUESTS[name]
            response["guests"][name] = {"path": str(path), "sha256_before": sha(path), "bytes": path.stat().st_size}
        with tempfile.TemporaryDirectory(prefix="ent-mixed-", dir="/tmp") as directory:
            work = Path(directory)
            old, new = work / "old", work / "new"
            for key, commit, binaries in [("old", OLD, old), ("new", NEW, new)]:
                archive = ROOT / "target/release-candidate" / commit[:12] / "entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
                response["archives"][key] = unpack(archive, commit, binaries)
            assert response["archives"]["new"]["source_id"] == SOURCE
            assert response["archives"]["old"]["elf_sha256_before"]["entangled"] != response["archives"]["new"]["elf_sha256_before"]["entangled"]
            publisher = node(work / "publisher", old)
            response["fixture_publisher"] = publisher.key
            payload, pixels = footprint(work)
            response["input_sha256"] = sha(payload)
            package, plugin = signed_package(work, publisher, "image-resize", components["image-resize"], response)
            for label, client, daemon in [("old-cli-new-daemon", old, new), ("new-cli-old-daemon", new, old)]:
                row = response["rows"][label] = {"commands": []}
                mixed(work, label, client, daemon, publisher, package, plugin, payload, pixels, row)
            assert len({row["peer"] for row in response["rows"].values()}) == 2
            assert len({row["output"]["sha256"] for row in response["rows"].values()}) == 1
            response["exact_png_bytes_match"] = True
            raw = response["synthetic_raw"] = {"commands": []}
            try:
                package, plugin = signed_package(work, publisher, "image-dehaze", components["image-dehaze"], response)
                synthetic_raw(work, old, new, publisher, package, plugin, raw)
                raw["exit_code"] = 0
            except Exception as error:
                raw.update(exit_code=1, error=repr(error))
            for key, binaries in [("old", old), ("new", new)]:
                row = response["archives"][key]
                row["elf_sha256_after"] = {name: sha(binaries / name) for name in row["elf_sha256_before"]}
                row["archive_sha256_after"] = sha(Path(row["path"]))
                assert row["elf_sha256_after"] == row["elf_sha256_before"]
                assert row["archive_sha256_before"] == row["archive_sha256_after"]
        status = 0
    except Exception as error:
        response["error"] = repr(error)
    response["source_after"] = source()
    for row in response["guests"].values():
        row["sha256_after"] = sha(Path(row["path"]))
        status |= int(row["sha256_before"] != row["sha256_after"])
    status |= int(response["source_before"] != response["source_after"])
    response.update(exit_code=status, source_id=response["source_before"], finished_utc=utc(),
                    scope="Mixed archive revisions on one x86_64 Linux machine under JSON-RPC 2.0 and WIT 0.1.")
    with (OUT / "receipt.json").open("x") as receipt:
        json.dump(response, receipt, indent=2)
        receipt.write("\n")
    print(json.dumps({"exit_code": status, "error": response.get("error"), "source_id": response["source_id"],
                      "rows": {name: row.get("output") for name, row in response["rows"].items()},
                      "synthetic_raw": {k: response.get("synthetic_raw", {}).get(k) for k in ("exit_code", "error", "output_sha256")}}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
