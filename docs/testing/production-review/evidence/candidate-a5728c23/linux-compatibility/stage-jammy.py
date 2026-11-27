#!/usr/bin/env python3
"""Provision an isolated build container and verified source, without running a compiler."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

BASE_URL = "ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb"
SEED = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture")

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--commit", required=True)
ap.add_argument("--source-id", required=True)
ap.add_argument("--out", required=True, type=Path)
args = ap.parse_args()
repo = Path("/workspace/Entanglement")
out = args.out.resolve(strict=True)
work = Path(tempfile.mkdtemp(prefix="entangle-jammy-tmpfs-", dir="/workspace"))
work.chmod(0o755)
commands = []
started = utc()

with (out / "jammy-provision.log").open("x") as log:
    def run(*cmd, timeout=60):
        cmd = [str(item) for item in cmd]
        commands.append(cmd)
        print(json.dumps(cmd), file=log, flush=True)
        proc = subprocess.run(cmd, cwd=repo, text=True, capture_output=True, timeout=timeout)
        print(proc.stdout, end="", file=log)
        print(proc.stderr, end="", file=log)
        print(f"exit={proc.returncode}", file=log, flush=True)
        proc.check_returncode()
        return proc.stdout.strip()

    def stamp():
        assert run("git", "rev-parse", "HEAD") == args.commit
        value = run("python3", "scripts/production_score.py", "--source-id")
        assert value == args.source_id
        return value

    before = stamp()
    feasibility = json.loads((out / "jammy-build-feasibility.json").read_text())
    probe = json.loads((out / "jammy-tmpfs-probe.json").read_text())
    assert feasibility["source_after"] == probe["source_after"] == before
    assert probe["exit_code"] == 0
    assert "name=rootless" in json.loads(run("docker", "info", "--format", "{{json .SecurityOptions}}"))
    base = run("docker", "image", "inspect", BASE_URL, "--format", "{{.Id}}")
    assert base == feasibility["jammy_base_image_id"] == probe["image_id"]
    assert {name: sha(SEED / "toolchain/bin" / name) for name in ("cargo", "rustc")} == feasibility["compiler"]
    assert sha(repo / "Cargo.lock") == feasibility["lock_sha256"]
    objects = work / "objects.git"
    bundle = work / "source.bundle"
    run("git", "clone", "--shared", "--bare", "--no-tags", repo, objects)
    run("git", "--git-dir", objects, "update-ref", "refs/heads/frozen-compat", args.commit)
    run("git", "--git-dir", objects, "bundle", "create", bundle, "refs/heads/frozen-compat")
    run("git", "bundle", "verify", bundle)
    bundle.chmod(0o644)
    cid = None
    sealed = False
    try:
        cid = run(
            "docker", "create", "--pull=never", "--platform=linux/amd64", "--network=bridge",
            "--security-opt=no-new-privileges", "--pids-limit=-1",
            "--tmpfs=/build-target:rw,exec,nosuid,nodev,mode=1777,size=7g",
            "--mount", f"type=bind,src={SEED},dst=/seed,readonly",
            "--mount", f"type=bind,src={bundle},dst=/source.bundle,readonly",
            base, "sleep", "infinity",
        )
        run("docker", "start", cid)
        run(
            "docker", "exec", cid, "/bin/sh", "-ec",
            "apt-get -o Acquire::Retries=1 update && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y --no-install-recommends ca-certificates git gcc libc6-dev make pkg-config "
            "&& apt-get clean",
            timeout=210,
        )
        run("docker", "network", "disconnect", "bridge", cid)
        networks = json.loads(run("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"))
        assert not networks
        run("docker", "exec", cid, "sh", "-ec", '''
            set -eu
            test "$(wc -l </proc/net/route)" -eq 1
            test "$(df -B1 /build-target | awk 'NR==2{print $2}')" = 7516192768
            test -z "$(ls -A /build-target)"
            getconf GNU_LIBC_VERSION
            gcc -v
            ld -v
            sha256sum /source.bundle /seed/toolchain/bin/rustc /seed/toolchain/bin/cargo
        ''')
        dpkg = run("docker", "exec", cid, "dpkg-query", "-W", "-f=${binary:Package} ${Version}\\n")
        (out / "jammy-dpkg.txt").write_text(dpkg + "\n")
        after = stamp()
        sealed = True
    finally:
        if cid is not None and not sealed:
            run("docker", "rm", "-f", cid)

data = {
    "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": after,
    "started_utc": started, "finished_utc": utc(), "exit_code": 0,
    "container": cid, "image": BASE_URL, "image_id": base, "network_for_build": networks, "tmpfs_cap_bytes": 7516192768,
    "source_bundle": str(bundle), "source_bundle_sha256": sha(bundle), "compiler": feasibility["compiler"],
    "lock_sha256": feasibility["lock_sha256"], "locked_registry_tarballs_verified": feasibility["locked_registry_tarballs_verified"],
    "runner_sha256": sha(Path(__file__)), "provision_log_sha256": sha(out / "jammy-provision.log"),
    "system_packages_sha256": sha(out / "jammy-dpkg.txt"), "commands": commands,
}
with (out / "jammy-provision.json").open("x") as stream:
    json.dump(data, stream, indent=2)
    stream.write("\n")
print(f"Provisioned disconnected rootless Jammy builder {cid}; no compiler run.")
