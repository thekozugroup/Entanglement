"""Build, sign, load, and verify the bundled WASI plugins on a real daemon.

From the repository root, with Rust and Python 3.11 or later installed:

    rustup target add wasm32-wasip2
    cargo build --locked -p entangle-cli -p entangle-bin
    python3 -m venv target/catalog-smoke-python
    target/catalog-smoke-python/bin/pip install Pillow==12.2.0 zxing-cpp==2.3.0
    target/catalog-smoke-python/bin/python plugins/smoke_test.py \
        target/debug/entangle target/debug/entangled --two-node

Omit --two-node to run only the local daemon workload checks.
"""

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket as net_socket
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import zlib

from PIL import Image, ImageOps
import zxingcpp


CATALOG = Path(__file__).resolve().parent
REPO = CATALOG.parent
WASI_TARGET = "wasm32-wasip2"
PLUGINS = (
    "compress",
    "csv-stats",
    "image-resize",
    "json-pointer",
    "json-query",
    "markdown-html",
    "qr-encode",
)


def run(*args, env=None, timeout=60):
    process = subprocess.run(args, cwd=REPO, env=env, capture_output=True, timeout=timeout)
    if process.returncode:
        raise RuntimeError(
            f"{shlex.join(map(str, args))} exited with {process.returncode}\n"
            f"{process.stdout.decode(errors='replace')}{process.stderr.decode(errors='replace')}"
        )
    return process.stdout


def build_and_sign(entangle, profile, env):
    listing = json.loads(run(entangle, "plugins", "available", "--catalog", CATALOG, "--json", env=env))
    assert not listing["problems"], listing["problems"]
    assert sorted(item["name"] for item in listing["plugins"]) == list(PLUGINS), listing["plugins"]
    assert all(item["tier"] == 1 and item["runtime"] == "wasm" for item in listing["plugins"])

    packages = {}
    target_dir = REPO / "target" / "catalog-smoke"
    for name in PLUGINS:
        print(f"Building and signing {name}", flush=True)
        project = CATALOG / name
        crate_stem = f"entangle_{name.replace('-', '_')}"
        wasm = target_dir / WASI_TARGET / "release" / f"{crate_stem}.wasm"
        wasm.unlink(missing_ok=True)
        run(
            "cargo", "build", "--locked", "--release", "--target", WASI_TARGET,
            "--manifest-path", project / "Cargo.toml", "--target-dir", target_dir,
            timeout=600,
        )
        with wasm.open("rb") as component:
            assert component.read(8) == b"\0asm\x0d\0\x01\0", f"{name} must build a WASI component"

        # Install signs the real artifact and trusts the publisher. The daemon
        # reads the resulting keyring when it starts.
        run(entangle, "plugins", "install", name, "--catalog", CATALOG, "--wasm", wasm, "--no-load", env=env)
        package = profile / ".entangle" / "plugins" / name
        manifest = tomllib.loads((package / "entangle.toml").read_text(encoding="utf-8"))
        plugin_id = manifest["plugin"]["id"]
        assert plugin_id.split("/", 1)[1] == f"{name}@{manifest['plugin']['version']}"
        packages[name] = (plugin_id, package)
    return packages


def verify_workloads(invoke):
    logs = b"".join(
        f'{{"service":"gateway","level":"INFO","status":200,"request_id":{i}}}\n'.encode()
        for i in range(512)
    )
    compressed = invoke("compress", b"compress:gzip:6\n" + logs, use_output_file=True)
    header = struct.unpack("<4sBBBBII", compressed[:16])
    assert header == (b"ENTZ", 1, 1, 6, 0, len(logs), zlib.crc32(logs)), header
    assert len(compressed) < len(logs)
    assert gzip.decompress(compressed[16:]) == logs
    assert invoke("compress", compressed) == logs
    assert invoke("compress", b"decompress:gzip\n" + gzip.compress(logs, mtime=0)) == logs
    print("Verified gzip interoperability and exact log round trips", flush=True)

    sales = (
        b'\xef\xbb\xbfregion,units,revenue,note\r\n'
        b'"Seattle, WA",3,90.5,"paid\r\nonline"\r\n'
        b'"Portland, OR",1,30.5,"refund ""review"""\r\n'
        b'"Seattle, WA",2,60,\r\n'
    )
    stats = json.loads(invoke("csv-stats", sales))
    assert stats == {
        "rows": 3,
        "columns": [
            {"name": "region", "type": "text", "count": 3, "nulls": 0, "distinct": 2},
            {"name": "units", "type": "numeric", "count": 3, "nulls": 0,
             "min": 1, "max": 3, "mean": 2, "sum": 6},
            {"name": "revenue", "type": "numeric", "count": 3, "nulls": 0,
             "min": 30.5, "max": 90.5, "mean": 181 / 3, "sum": 181},
            {"name": "note", "type": "text", "count": 2, "nulls": 1, "distinct": 2},
        ],
    }, stats
    print("Verified sales CSV statistics with quoted fields and CRLF", flush=True)

    left, right = (210, 30, 45, 255), (20, 80, 200, 128)
    source = Image.new("RGBA", (800, 450), left)
    source.paste(right, (400, 0, 800, 450))
    png = io.BytesIO()
    source.save(png, format="PNG")
    thumbnail = invoke(
        "image-resize", b'{"width":160,"height":160,"fit":"contain","format":"png"}\n' + png.getvalue(),
        use_output_file=True,
    )
    with Image.open(io.BytesIO(thumbnail)) as resized:
        assert resized.format == "PNG" and resized.size == (160, 90), (resized.format, resized.size)
        assert resized.mode == "RGBA", resized.mode
        assert resized.getpixel((20, 45)) == left and resized.getpixel((140, 45)) == right
    print("Verified decoded 160×90 PNG thumbnail and RGBA pixels", flush=True)

    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "Gateway", "version": "1.0.0"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "Healthy"}}}}},
    }
    pointer = {"pointer": "#/paths/~1health/get/responses/200/description", "data": openapi}
    assert invoke("json-pointer", json.dumps(pointer).encode()) == b'"Healthy"'
    print("Verified RFC 6901 OpenAPI response reference", flush=True)

    telemetry = {"services": [
        {"name": "gateway", "p95_ms": 36},
        {"name": "billing", "p95_ms": 110},
        {"name": "jobs"},
    ]}
    query = {"query": "services[*].p95_ms", "data": telemetry}
    assert json.loads(invoke("json-query", json.dumps(query).encode())) == [36, 110]
    print("Verified JSON telemetry query and wildcard selection", flush=True)

    markdown = (
        b"# Release notes\n\n- **Fixed** retry handling.\n- ~~Removed~~ legacy flag.\n\n"
        b"See [operator guide](https://docs.example.net/operations).\n"
    )
    html = invoke("markdown-html", markdown)
    assert html == (
        b"<h1>Release notes</h1>\n<ul>\n<li><strong>Fixed</strong> retry handling.</li>\n"
        b"<li><del>Removed</del> legacy flag.</li>\n</ul>\n"
        b'<p>See <a href="https://docs.example.net/operations">operator guide</a>.</p>\n'
    ), html
    print("Verified release notes render to the expected HTML", flush=True)

    url = "https://docs.example.net/operations"
    qr = json.loads(invoke("qr-encode", f"#!qr format=json ecc=q\n{url}".encode()))
    modules, matrix = qr["modules"], qr["matrix"]
    assert qr["ecc"] == "Q" and qr["quiet_zone"] == 4 and modules == 17 + 4 * qr["version"]
    assert len(matrix) == modules and all(len(row) == modules and set(row) <= {"0", "1"} for row in matrix)
    pixels = bytes(0 if bit == "1" else 255 for row in matrix for bit in row)
    symbol = Image.frombytes("L", (modules, modules), pixels)
    symbol = ImageOps.expand(symbol, border=qr["quiet_zone"], fill=255)
    symbol = symbol.resize((symbol.width * 8, symbol.height * 8), Image.Resampling.NEAREST)
    barcode = zxingcpp.read_barcode(symbol, formats=zxingcpp.BarcodeFormat.QRCode)
    assert barcode is not None and barcode.text == url, barcode
    print("Verified QR URL by decoding the generated symbol with ZXing", flush=True)


def identity(profile, init_output):
    match = re.search(rb"Fingerprint:\s*([0-9a-f-]+)", init_output)
    if not match:
        raise RuntimeError("init did not report the identity fingerprint")
    peer_id = match.group(1).decode().replace("-", "")
    der = run("openssl", "pkey", "-in", profile / ".entangle/identity.key",
              "-pubout", "-outform", "DER")
    # SubjectPublicKeyInfo for Ed25519 contains this fixed prefix and 32 key bytes.
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise RuntimeError("unexpected Ed25519 public key encoding")
    return peer_id, der[12:].hex()


def exercise_daemon(entangle, entangled, profile, env, packages, coordinator=None):
    daemon_log = profile / "entangled.log"
    socket = profile / ".entangle" / "sock"
    with daemon_log.open("wb") as log:
        daemon = subprocess.Popen([entangled, "run"], cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("entangled did not start on the test socket")
                time.sleep(0.05)

            for name, (_, package) in packages.items():
                print(f"Loading {name} into entangled", flush=True)
                run(entangle, "plugins", "load", package, env=env)
            loaded = json.loads(run(entangle, "plugins", "list", "--json", env=env))["plugins"]
            assert set(loaded) == {plugin_id for plugin_id, _ in packages.values()}, loaded

            def invoke(name, payload, *, use_output_file=False):
                input_file = profile / "invocation.input"
                input_file.write_bytes(payload)
                plugin_id = packages[name][0]
                args = (entangle, "plugins", "invoke", plugin_id, "--input-file", input_file)
                if use_output_file:
                    output_file = profile / "invocation.output"
                    output_file.unlink(missing_ok=True)
                    run(*args, "--output-file", output_file, env=env)
                    return output_file.read_bytes()
                return run(*args, "--raw", env=env)

            print("Verifying local daemon workloads", flush=True)
            verify_workloads(invoke)
            if coordinator is not None:
                exercise_remote(entangle, entangled, packages, coordinator)
        except Exception:
            print(daemon_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()


def exercise_remote(entangle, entangled, packages, coordinator):
    coordinator_profile, coordinator_env, worker_id = coordinator
    daemon_log = coordinator_profile / "entangled.log"
    sock = coordinator_profile / ".entangle/sock"
    with daemon_log.open("wb") as log:
        daemon = subprocess.Popen([entangled, "run"], cwd=REPO, env=coordinator_env,
                                  stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 45
            while not sock.is_socket():
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("coordinator did not start")
                time.sleep(0.05)
            loaded = json.loads(run(entangle, "plugins", "list", "--json", env=coordinator_env))["plugins"]
            assert not loaded, loaded

            def invoke(name, payload, *, use_output_file=False):
                input_file = coordinator_profile / "invocation.input"
                input_file.write_bytes(payload)
                args = [entangle, "compute", "dispatch", packages[name][0], "--input-file", input_file,
                        "--integrity", "trusted-executor", "--allow", worker_id, "--cpu-cores", "0.01"]
                output_file = coordinator_profile / "invocation.output"
                if use_output_file:
                    output_file.unlink(missing_ok=True)
                    args.extend(["--output-file", output_file])
                else:
                    args.append("--raw")
                deadline = time.monotonic() + 45
                while True:
                    result = subprocess.run(args, cwd=REPO, env=coordinator_env, capture_output=True, timeout=60)
                    if result.returncode == 0:
                        break
                    if b"no live workers" not in result.stderr or time.monotonic() >= deadline:
                        raise RuntimeError(f"remote dispatch failed: {result.stderr.decode(errors='replace')}")
                    time.sleep(0.2)
                assert re.search(rb"(?m)^Chosen:\s*" + worker_id.encode() + rb"(?:\s|$)", result.stderr), result.stderr
                return output_file.read_bytes() if use_output_file else result.stdout

            print(f"Verifying remote workloads on trusted worker {worker_id}", flush=True)
            verify_workloads(invoke)
            assert not json.loads(run(entangle, "plugins", "list", "--json", env=coordinator_env))["plugins"]
        except Exception:
            print(daemon_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()


def main():
    if not __debug__:
        raise RuntimeError("Run the catalog smoke test with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("entangle", type=Path)
    parser.add_argument("entangled", type=Path)
    parser.add_argument("--two-node", action="store_true", help="also dispatch all workloads to a separate worker")
    args = parser.parse_args()
    entangle = args.entangle.resolve(strict=True)
    entangled = args.entangled.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="entangle-catalog-") as directory:
        profile = Path(directory)
        env = {**os.environ, "HOME": str(profile)}
        env.pop("ENTANGLE_ALLOW_LOCAL", None)
        init_output = run(entangle, "init", "--non-interactive", env=env)
        config = profile / ".entangle" / "config.toml"
        config.write_text("[mesh]\ntransports = []\n[security]\nmax_tier_allowed = 1\n", encoding="utf-8")
        packages = build_and_sign(entangle, profile, env)
        coordinator = None
        if args.two_node:
            worker_id, worker_key = identity(profile, init_output)
            coordinator_profile = profile / "coordinator"
            coordinator_profile.mkdir()
            coordinator_env = {**env, "HOME": str(coordinator_profile)}
            coordinator_init = run(entangle, "init", "--non-interactive", env=coordinator_env)
            coordinator_id, coordinator_key = identity(coordinator_profile, coordinator_init)
            run(entangle, "mesh", "trust", coordinator_id, "--public-key-hex", coordinator_key,
                "--display-name", "coordinator", env=env)
            run(entangle, "mesh", "trust", worker_id, "--public-key-hex", worker_key,
                "--display-name", "worker", env=coordinator_env)
            with net_socket.socket(net_socket.AF_INET, net_socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config.write_text(f'[mesh]\ntransports = ["iroh"]\nmulti_node = true\n'
                              f'[scheduler]\nbind = "127.0.0.1:{port}"\nrelay = false\n'
                              '[security]\nmax_tier_allowed = 1\n', encoding="utf-8")
            (coordinator_profile / ".entangle/config.toml").write_text(
                f'[mesh]\ntransports = ["iroh"]\nmulti_node = true\n'
                f'[scheduler]\nbind = "127.0.0.1:0"\nrelay = false\n'
                f'peers = ["{worker_key}@127.0.0.1:{port}"]\n', encoding="utf-8")
            coordinator = (coordinator_profile, coordinator_env, worker_id)
        exercise_daemon(entangle, entangled, profile, env, packages, coordinator)


if __name__ == "__main__":
    main()
