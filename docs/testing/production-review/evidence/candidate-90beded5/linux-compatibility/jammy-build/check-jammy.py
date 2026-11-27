#!/usr/bin/env python3
"""Inspect retained Jammy inputs and current staging capacity without starting an independent build."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--commit", required=True)
parser.add_argument("--source-id", required=True)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
seed = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture")
prior = repo / "docs/testing/production-review/evidence/candidate-a0926c6e/glibc-compat"
base = "ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb"

def get(*args):
    return subprocess.check_output(args, cwd=repo, text=True).strip()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def stamp():
    assert get("git", "rev-parse", "HEAD") == args.commit
    value = get("python3", "scripts/production_score.py", "--source-id")
    assert value == args.source_id
    return value

started = utc()
before = stamp()
base_id = get("docker", "image", "inspect", base, "--format", "{{.Id}}")
build_receipt = json.loads((prior / "build.json").read_text())
assert base_id == build_receipt["image_id"]
containers = get("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Image}} {{.Status}}").splitlines()
target_container_state = subprocess.run(
    ["docker", "inspect", build_receipt["container"]], cwd=repo, capture_output=True, text=True, check=False,
)
assert target_container_state.returncode != 0
cache = list((seed / "registry/cache").iterdir())
assert len(cache) == 1
lock = repo / "Cargo.lock"
registry_rows = [entry for entry in tomllib.loads(lock.read_text())["package"] if entry.get("source", "").startswith("registry+")]
for entry in registry_rows:
    crate = cache[0] / f"{entry['name']}-{entry['version']}.crate"
    assert sha(crate) == entry["checksum"]
tools = {name: sha(seed / "toolchain/bin" / name) for name in ("cargo", "rustc")}
assert tools == build_receipt["compiler"]
record = {
    "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": stamp(),
    "started_at_utc": started, "finished_at_utc": utc(), "exit_code": 0,
    "inspection": "Current-source compatibility-build feasibility only.",
    "jammy_base_image": base, "jammy_base_image_id": base_id,
    "prior_completed_build_sha256": sha(prior / "build.json"),
    "prior_builder_container_removed": True, "docker_containers_observed": containers,
    "compiler": tools, "lock_sha256": sha(lock), "locked_registry_tarballs_verified": len(registry_rows),
    "free_workspace_bytes": shutil.disk_usage(repo).free,
    "current_host_release_target_deps_size": get("du", "-sh", repo / "target/release/deps").split()[0],
    "outcome": "same-source Jammy release build unverified",
    "details": "The authenticated dependency inputs and exact Rust tools remain available. The previous optimized Jammy target and installed GCC userspace were removed, leaving a cold compilation and new apt provisioning. The local workspace has limited staging capacity and is shared with the exact-source release and timing checks. No previous ELF was relabelled as this candidate.",
}
args.out.write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({name: record[name] for name in ("outcome", "locked_registry_tarballs_verified", "free_workspace_bytes")}))
