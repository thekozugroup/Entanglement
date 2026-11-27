#!/usr/bin/env python3
"""Package a fresh hello-world WASI component using the canonical exact-release Cargo tool."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
out = args.out.resolve(strict=True)
stage = json.loads((out / "jammy-provision.json").read_text())
canonical = json.loads((out.parent / "linux-archive.json").read_text())
bundle = Path(stage["source_bundle"])
seed = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture")
key = Path("/workspace/entangle-package-seed.2uvRiy/public-repro-fixture-seed.pem")
tool = repo / "target/release/cargo-entangle"
command_log = out / "canonical-hello-world-package.log"

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(item):
    with item.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def get(*command):
    return subprocess.check_output(command, cwd=repo, text=True).strip()

def stamp():
    assert get("git", "rev-parse", "HEAD") == canonical["source_commit"] == stage["source_commit"]
    actual = get("python3", "scripts/production_score.py", "--source-id")
    assert actual == canonical["source_id"] == stage["source_after"]
    return actual

before = stamp()
assert sha(tool) == canonical["tool_sha256"]
assert sha(bundle) == stage["source_bundle_sha256"]
for name, digest in stage["compiler"].items():
    assert sha(seed / "toolchain/bin" / name) == digest
glibc = get("getconf", "GNU_LIBC_VERSION")
os_release = Path("/etc/os-release").read_text()
userspace = re.search(r'^PRETTY_NAME="(.*)"$', os_release, re.M)[1]
with tempfile.TemporaryDirectory(prefix="entangle-debian-hello-", dir="/workspace") as temporary:
    work = Path(temporary)
    source = work / "source with spaces"
    cargo_home = work / "cargo-home"
    config_home = work / "home"
    registry = cargo_home / "registry"
    registry.mkdir(parents=True)
    config_home.mkdir()
    for name in ("cache", "index"):
        shutil.copytree(seed / "registry" / name, registry / name)
    env = {
        "PATH": str(tool.parent) + ":" + str(seed / "toolchain/bin") + ":/usr/bin:/bin",
        "HOME": str(config_home), "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "LC_ALL": "C.UTF-8",
    }
    archive = work / "hello-world-repro.tar.zst"
    cmd = [
        str(seed / "toolchain/bin/cargo"), "entangle", "package", str(source / "examples/hello-world"),
        "--source-url", "https://github.com/thekozugroup/Entanglement.git", "--key", str(key), "--out", str(archive),
    ]
    start = utc()
    with command_log.open("xb") as output:
        subprocess.run(["git", "clone", "--branch", "frozen-compat", str(bundle), str(source)],
                       env=env, check=True, stdout=output, stderr=subprocess.STDOUT, timeout=30)
        assert get("git", "-C", source, "rev-parse", "HEAD") == stage["source_commit"]
        assert not get("git", "-C", source, "status", "--porcelain")
        result = subprocess.run(cmd, cwd=work, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=300)
    actual = sha(archive) if result.returncode == 0 else None
    size = archive.stat().st_size if actual is not None else None
    assert sha(tool) == canonical["tool_sha256"]
    after = stamp()
data = {
    "source_commit": canonical["source_commit"], "source_id": before, "source_before": before, "source_after": after,
    "started_utc": start, "finished_utc": utc(), "command": cmd, "exit_code": result.returncode,
    "tool_sha256": canonical["tool_sha256"], "archive_sha256": actual, "archive_size": size, "userspace": userspace,
    "glibc": glibc, "log": str(command_log.relative_to(repo)), "sha256": sha(command_log), "compiler": stage["compiler"],
    "scope": "Canonical optimized cargo-entangle exact executable, independently compiled WASI guest in a fresh temporary source path using locked local inputs. Private disposable fixture, no publication.",
}
(out / "canonical-hello-world-package.json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({k: data[k] for k in ("userspace", "glibc", "archive_sha256", "archive_size", "exit_code")}))
raise SystemExit(result.returncode)
