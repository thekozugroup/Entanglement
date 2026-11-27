#!/usr/bin/env python3
"""Generate an independent same-source WASI package in pinned Ubuntu 24.04."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
out = args.out.resolve(strict=True)
original = out.parent
stage = json.loads((original / "jammy-provision.json").read_text())
canonical = json.loads((original.parent / "linux-archive.json").read_text())
bundle = Path(stage["source_bundle"])
seed = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture")
key = Path("/workspace/entangle-package-seed.2uvRiy/public-repro-fixture-seed.pem")
tool = repo / "target/release/cargo-entangle"
script = out / "noble-hello-world-package.sh"
image = "ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b"
archive = "/build-target/hello-world-repro.tar.zst"

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

commands = []
logfile = out / "noble-hello-world-package.log"
archive_sha = None
archive_size = None
status = 1
cid = None
started = utc()
with logfile.open("x") as log:
    def run(*argv, timeout=60, stdin=None, required=True):
        cmd = [str(arg) for arg in argv]
        commands.append(cmd)
        print(json.dumps(cmd), file=log, flush=True)
        result = subprocess.run(cmd, cwd=repo, stdin=stdin, text=True, capture_output=True, timeout=timeout)
        print(result.stdout, end="", file=log)
        print(result.stderr, end="", file=log)
        print(f"exit={result.returncode}", file=log, flush=True)
        if required:
            result.check_returncode()
        return result

    def stamp():
        assert run("git", "rev-parse", "HEAD").stdout.strip() == canonical["source_commit"] == stage["source_commit"]
        source = run("python3", "scripts/production_score.py", "--source-id").stdout.strip()
        assert source == canonical["source_id"] == stage["source_after"]
        return source

    before = stamp()
    assert sha(bundle) == stage["source_bundle_sha256"]
    assert sha(tool) == canonical["tool_sha256"]
    assert {name: sha(seed / "toolchain/bin" / name) for name in stage["compiler"]} == stage["compiler"]
    info = run("docker", "info", "--format", "{{json .SecurityOptions}}").stdout
    assert "name=rootless" in json.loads(info)
    image_id = run("docker", "image", "inspect", image, "--format", "{{.Id}}").stdout.strip()
    try:
        cid = run(
            "docker", "create", "--pull=never", "--platform=linux/amd64", "--network=bridge",
            "--security-opt=no-new-privileges", "--tmpfs=/build-target:rw,exec,nosuid,nodev,mode=1777,size=1g",
            "--mount", f"type=bind,src={seed},dst=/seed,readonly",
            "--mount", f"type=bind,src={bundle},dst=/source.bundle,readonly",
            "--mount", f"type=bind,src={key},dst=/public-repro-fixture.pem,readonly",
            image_id, "sleep", "infinity",
        ).stdout.strip()
        run("docker", "start", cid)
        run("docker", "exec", cid, "sh", "-ec",
            "apt-get -o Acquire::Retries=1 update && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y --no-install-recommends ca-certificates git gcc libc6-dev make pkg-config && apt-get clean",
            timeout=240)
        run("docker", "network", "disconnect", "bridge", cid)
        assert not json.loads(run("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}").stdout)
        run("docker", "exec", cid, "mkdir", "-p", "/packager")
        run("docker", "cp", tool, cid + ":/packager/cargo-entangle")
        run("docker", "exec", cid, "chmod", "0555", "/packager/cargo-entangle")
        assert run("docker", "exec", "--user=65534:65534", cid, "sha256sum", "/packager/cargo-entangle").stdout.split()[0] == canonical["tool_sha256"]
        (out / "noble-hello-world-dpkg.txt").write_text(
            run("docker", "exec", cid, "dpkg-query", "-W", "-f=${binary:Package} ${Version}\\n").stdout
        )
        with script.open("rb") as runner:
            status = run(
                "docker", "exec", "-i", "--user", "65534:65534", cid,
                "/usr/bin/timeout", "--kill-after=10s", "300s", "/bin/sh", "-s", "--", stage["source_commit"],
                timeout=320, stdin=runner, required=False,
            ).returncode
        if status == 0:
            archive_sha = run("docker", "exec", cid, "sha256sum", archive).stdout.split()[0]
            archive_size = int(run("docker", "exec", cid, "stat", "-c", "%s", archive).stdout)
            assert archive_size > 0
    finally:
        if cid:
            run("docker", "rm", "-f", cid)
    assert sha(tool) == canonical["tool_sha256"]
    after = stamp()
data = {
    "source_commit": canonical["source_commit"], "source_id": before, "source_before": before, "source_after": after,
    "started_utc": started, "finished_utc": utc(), "command": commands, "exit_code": status,
    "tool_sha256": canonical["tool_sha256"], "archive_sha256": archive_sha, "archive_size": archive_size,
    "image": image, "image_id": image_id, "userspace": "Ubuntu 24.04", "glibc": "2.39",
    "log": str(logfile.relative_to(repo)), "sha256": sha(logfile), "script_sha256": sha(script),
    "compiler": stage["compiler"],
    "scope": "Canonical optimized cargo-entangle built on Debian 13. Fresh WASI guest build and tar.zst packaging executed in confined Ubuntu 24.04 glibc 2.39, unprivileged and disconnected, with verified offline Cargo inputs. Disposable inner signer only.",
}
(out / "noble-hello-world-package.json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({name: data[name] for name in ("userspace", "glibc", "archive_sha256", "archive_size", "exit_code")}))
raise SystemExit(status)
