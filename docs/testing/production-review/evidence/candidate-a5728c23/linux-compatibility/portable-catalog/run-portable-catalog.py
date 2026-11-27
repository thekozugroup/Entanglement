#!/usr/bin/env python3
"""Run the frozen native release acceptance using the exact Jammy archive and pinned guests."""

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO = Path("/workspace/Entanglement")
OUTPUT = Path(__file__).resolve().parent
BUILD_RECEIPT = OUTPUT.parent / "jammy-replay/jammy-linux-archive.json"
B3SUM = Path("/tmp/entangle-release-followup/tools/b3sum")
EXPECTED_GUESTS = {
    "compress": "29e190472331647e30aa8eef03b23e8e7f3cce1eb86633385f9d1443d9c31bae",
    "csv-stats": "048934f97be845415ee90a4ded8fab78fd729cf0fcd3cb947fda3034dcd2162d",
    "image-dehaze": "eb0e482edfa642479d5b16caccf39b8e4dac4c4d290699fe6d97ee5d9103b973",
    "image-resize": "b3ad4285a7f71a0377291a4e13676883bb419e815f7fe7e44b9771e615e44983",
    "json-pointer": "ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb",
    "json-query": "7fb8333c7b72cc5f7785c45e8a5eb9f93ad956261f2d348188ac8c6ba1a0a894",
    "markdown-html": "77865dca965cb8bf467d2d9d83b4f877f681828d86cdbd0576673a0564d83245",
    "qr-encode": "697bbf339ce222161a73568099f9bdbe3e6e174b87eceb31bb935b96e77ac9c6",
}
ORACLES = {
    "compress": "Verified gzip interoperability and exact log round trips",
    "csv-stats": "Verified sales CSV statistics with quoted fields and CRLF",
    "image-resize": "Verified decoded 160×90 PNG thumbnail and RGBA pixels",
    "image-dehaze": "Verified 16-bit linear RGB PNG dehazing and atmospheric-light preservation",
    "json-pointer": "Verified RFC 6901 OpenAPI response reference",
    "json-query": "Verified JSON telemetry query and wildcard selection",
    "markdown-html": "Verified release notes render to the expected HTML",
    "qr-encode": "Verified QR URL by decoding the generated symbol with ZXing",
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def get(*argv, cwd=REPO):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=30).strip()


def save(name, value):
    with (OUTPUT / name).open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


release = json.loads(BUILD_RECEIPT.read_bytes())
archive = Path(release["archive_path"])
commit = release["source_commit"]
source = release["source_id"]
assert release["exit_code"] == 0 and release["source_before"] == release["source_after"] == source


def stamp(repo):
    assert get("git", "rev-parse", "HEAD", cwd=repo) == commit
    got = get(sys.executable, "scripts/production_score.py", "--source-id", cwd=repo)
    assert got == source
    return got


started = utc()
assert stamp(REPO) == source
assert sha(archive) == release["sha256"] and archive.stat().st_size == release["size"]
assert get(B3SUM, "--no-names", archive) == release["blake3"]
sidecars = {}
for suffix, digest in (("sha256", release["sha256"]), ("b3", release["blake3"])):
    sidecar = archive.with_name(archive.name + "." + suffix)
    assert sidecar.read_text().split() == [digest, archive.name]
    sidecars[suffix] = sha(sidecar)
dependencies = {name: importlib.metadata.version(name) for name in ("Pillow", "zxing-cpp")}
assert dependencies == {"Pillow": "12.2.0", "zxing-cpp": "2.3.0"}
platform_info = {
    "machine": platform.machine(), "kernel": platform.release(),
    "os": platform.freedesktop_os_release()["PRETTY_NAME"],
    "glibc": get("getconf", "GNU_LIBC_VERSION"), "openssl": get("openssl", "version"),
    "python": sys.version.split()[0], "python_dependencies": dependencies,
}
assert platform_info["machine"] == "x86_64"

with tempfile.TemporaryDirectory(prefix="entangle-pcatalog-", dir="/workspace") as temp:
    work = Path(temp)
    source_dir = work / "source"
    bins = work / "release"
    bins.mkdir()
    tools = work / "tools"
    tools.mkdir()
    with (OUTPUT / "setup.log").open("x") as setup:
        def prepare(*command, cwd=REPO):
            print(json.dumps(list(map(str, command))), file=setup, flush=True)
            subprocess.run(command, cwd=cwd, stdout=setup, stderr=subprocess.STDOUT, timeout=90, check=True)

        prepare("git", "clone", "--shared", "--no-checkout", "--no-tags", REPO, source_dir)
        prepare("git", "sparse-checkout", "set", "--no-cone", "/*", "!/docs/testing/production-review/evidence/",
                "!/docs/testing/production-review/runs/", cwd=source_dir)
        prepare("git", "checkout", "--detach", commit, cwd=source_dir)
        assert stamp(source_dir) == source
        assert not get("git", "status", "--porcelain", cwd=source_dir)

    binaries = {}
    with tarfile.open(archive) as tf:
        prefix = archive.name.removesuffix(".tar.gz") + "/"
        for name in ("entangle", "entangled"):
            member = tf.getmember(prefix + name)
            assert member.isfile()
            executable = bins / name
            with tf.extractfile(member) as old, executable.open("xb") as new:
                shutil.copyfileobj(old, new)
            executable.chmod(0o755)
            assert sha(executable) == release["files_sha256"][name]
            elf = get("readelf", "-h", executable)
            assert re.search(r"Machine:\s+Advanced Micro Devices X86-64", elf)
            imports = get("readelf", "--version-info", executable)
            floor = max(re.findall(r"Name: GLIBC_([\d.]+)", imports), key=lambda v: tuple(map(int, v.split("."))))
            assert floor == "2.34"
            assert get(executable, "--version") == f"{name} 0.1.0"
            binaries[name] = {
                "sha256": sha(executable), "required_glibc": floor, "bytes": executable.stat().st_size,
            }

    fixtures = {}
    for name, expected in EXPECTED_GUESTS.items():
        filename = f"entangle_{name.replace('-', '_')}.wasm"
        path = REPO / "target/catalog-smoke/wasm32-wasip2/release" / filename
        assert sha(path) == expected
        relative = "plugins/" + name
        fixtures[name] = {
            "input": str(path), "wasm_sha256": expected, "archive_bytes": path.stat().st_size,
            "manifest_sha256": sha(source_dir / relative / "Cargo.toml"),
            "lock_sha256": sha(source_dir / relative / "Cargo.lock"),
            "git_tree": get("git", "rev-parse", commit + ":" + relative),
        }
    save("fixtures.json", fixtures)
    assert sha(source_dir / "plugins/smoke_test.py") == sha(REPO / "plugins/smoke_test.py")
    assert sha(source_dir / "scripts/tests/native-release.py") == sha(REPO / "scripts/tests/native-release.py")

    adapter = tools / "cargo"
    stage_script = OUTPUT / "stage-prebuilt-cargo.py"
    adapter.write_bytes(f"#!{sys.executable}\n".encode() + stage_script.read_bytes())
    adapter.chmod(0o755)
    stage_log = OUTPUT / "prebuilt-staging.jsonl"
    env = dict(os.environ)
    for key in ("CARGO_TARGET_DIR", "ENTANGLE_ALLOW_LOCAL", "PYTHONOPTIMIZE", "GITHUB_RUN_ID", "RUNNER_ARCH", "ImageVersion"):
        env.pop(key, None)
    env.update(
        PATH=str(tools) + ":" + env["PATH"],
        CARGO_HOME=str(work / "unused-cargo-home"), RUSTUP_HOME=str(work / "unused-rustup-home"),
        CARGO_NET_OFFLINE="true", TMPDIR="/tmp", PYTHONDONTWRITEBYTECODE="1",
        ENTANGLE_PORTABLE_CATALOG_SOURCE=str(source_dir),
        ENTANGLE_PORTABLE_CATALOG_FIXTURES=str(OUTPUT / "fixtures.json"),
        ENTANGLE_PORTABLE_CATALOG_STAGING_LOG=str(stage_log),
        TOKIO_WORKER_THREADS="2", RAYON_NUM_THREADS="2",
    )
    official_result = OUTPUT / "native-release.json"
    command = [sys.executable, "-B", "scripts/tests/native-release.py", "x86_64-unknown-linux-gnu",
               str(bins), str(official_result)]
    log = OUTPUT / "native-release.log"
    with log.open("xb") as stream:
        run = subprocess.run(command, cwd=source_dir, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=360)
    assert stamp(source_dir) == source and stamp(REPO) == source
    assert sha(archive) == release["sha256"]
    for name in binaries:
        assert sha(bins / name) == binaries[name]["sha256"]
    assert all(sha(Path(row["input"])) == row["wasm_sha256"] for row in fixtures.values())
    report = {
        "source_id": source, "source_before": source, "source_after": source, "source_commit": commit,
        "started_utc": started, "finished_utc": utc(), "exit_code": run.returncode,
        "log": str(log.relative_to(REPO)), "sha256": sha(log), "command": command, "command_cwd": str(source_dir),
        "archive": str(archive), "archive_sha256": release["sha256"], "archive_blake3": release["blake3"],
        "archive_receipt_sha256": sha(BUILD_RECEIPT), "sidecar_sha256": sidecars, "elf": binaries,
        "actual_userspace": platform_info, "native_release_script_sha256": sha(source_dir / command[2]),
        "frozen_smoke_script_sha256": sha(source_dir / "plugins/smoke_test.py"),
        "prebuilt_adapter_sha256": sha(stage_script), "inputs_sha256": sha(OUTPUT / "fixtures.json"),
        "scope": "Both Jammy-built archive executables ran natively on this Debian 13 x86-64 host. The frozen official release smoke and its local and authenticated two-daemon oracles are unchanged. An isolated Cargo adapter staged only the eight existing checksum-pinned WASI inputs. The official CLI signed and installed fresh copies. No Cargo compilation or remote Rust registry was used. This is a loopback two-daemon test on one host.",
    }
    if run.returncode == 0:
        official = json.loads(official_result.read_bytes())
        assert official["source_id"] == source and official["source_commit"] == commit
        assert official["binary_sha256"] == {name: item["sha256"] for name, item in binaries.items()}
        assert official["exit_code"] == 0 and official["command"][-1] == "--two-node"
        assert official["os"] == platform_info["os"] and official["run_id"] is None
        staging = [json.loads(line) for line in stage_log.read_text().splitlines()]
        assert [row["plugin"] for row in staging] == list(EXPECTED_GUESTS)
        assert all(row["fixture_sha256"] == EXPECTED_GUESTS[row["plugin"]] for row in staging)
        raw = log.read_text()
        local = raw.index("Verifying local daemon workloads")
        remote = re.search(r"(?m)^Verifying remote workloads on trusted worker ([a-f0-9]{32})$", raw)
        assert remote and remote.start() > local
        for message in ORACLES.values():
            assert raw.count(message) == 2
            assert message in raw[local:remote.start()] and message in raw[remote.end():]
        report.update(
            official_receipt_sha256=sha(official_result), guest_staging_log_sha256=sha(stage_log),
            local_oracles=list(ORACLES), remote_oracles=list(ORACLES),
            worker_peer_id=remote[1], signed_plugins=8, no_coordinator_plugins=True,
        )
    save("normalized.json", report)
    print(log.read_text(), end="")
raise SystemExit(run.returncode)
