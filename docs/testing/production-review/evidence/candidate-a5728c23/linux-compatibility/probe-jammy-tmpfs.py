#!/usr/bin/env python3
"""Prove rootless Jammy provides bounded executable tmpfs and an offline locked Cargo build."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--commit", required=True)
parser.add_argument("--source-id", required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
tools = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture/toolchain")
image = "ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb"

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def get(*argv):
    return subprocess.check_output(argv, text=True, cwd=repo).strip()

def stamp():
    assert get("git", "rev-parse", "HEAD") == args.commit
    value = get("python3", "scripts/production_score.py", "--source-id")
    assert value == args.source_id
    return value

script = """
set -eu
test "$(wc -l </proc/net/route)" -eq 1
export PATH=/frozen-tools/bin:/usr/bin:/bin CARGO_TARGET_DIR=/build-target/result
export CARGO_HOME=/tmp/probe-cargo CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0
cat /etc/os-release
getconf GNU_LIBC_VERSION
df -B1 /build-target
awk '$5=="/build-target" {print; found=1} END {exit !found}' /proc/self/mountinfo
test "$(df -B1 /build-target | awk 'NR==2{print $2}')" = 7516192768
mkdir -p /build-target/probe/src
cd /build-target/probe
printf '%s\n' '[package]' 'name = "entangle-tmpfs-smoke"' 'version = "0.0.0"' 'edition = "2021"' >Cargo.toml
printf '%s\n' 'fn main() { println!("entangle tmpfs offline build"); }' > src/main.rs
cargo generate-lockfile --offline
sha256sum Cargo.lock
cargo build --offline --locked --release --jobs 1 --target wasm32-wasip2
wasm=/build-target/result/wasm32-wasip2/release/entangle-tmpfs-smoke.wasm
test -s "$wasm"
sha256sum "$wasm"
test "$(od -An -N4 -tx1 "$wasm" | tr -d ' \n')" = 0061736d
printf 'Tmpfs used bytes after build: '
df -B1 /build-target | awk 'NR==2{print $3}'
"""
start = utc()
before = stamp()
assert "name=rootless" in json.loads(get("docker", "info", "--format", "{{json .SecurityOptions}}"))
image_id = get("docker", "image", "inspect", image, "--format", "{{.Id}}")
cmd = [
    "docker", "run", "--rm", "--pull=never", "--platform=linux/amd64", "--network=none",
    "--user=65534:65534", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--env", "HOME=/tmp", "--tmpfs", "/build-target:rw,exec,nosuid,nodev,mode=1777,size=7g",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
    "--mount", f"type=bind,src={tools},dst=/frozen-tools,readonly",
    image_id, "/usr/bin/timeout", "--kill-after=5s", "30s", "/bin/sh", "-ec", script,
]
logfile = args.out / "jammy-tmpfs-probe.log"
with logfile.open("xb") as log:
    status = subprocess.run(cmd, cwd=repo, stdout=log, stderr=subprocess.STDOUT, timeout=50).returncode
after = stamp()
data = {
    "source_id": before, "source_before": before, "source_after": after, "source_commit": args.commit,
    "started_utc": start, "finished_utc": utc(), "exit_code": status,
    "scope": "Plain offline locked single-job WASI Cargo release build in a bounded rootless Jammy container-local tmpfs.",
    "tmpfs_limit_bytes": 7516192768, "image": image, "image_id": image_id,
    "runner_sha256": sha(Path(__file__)), "log": str(logfile.resolve().relative_to(repo)),
    "sha256": sha(logfile), "command": cmd,
}
(args.out / "jammy-tmpfs-probe.json").write_text(json.dumps(data, indent=2) + "\n")
print(logfile.read_text(), end="")
raise SystemExit(status)
