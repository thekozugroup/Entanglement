#!/usr/bin/env python3
"""Add the Ubuntu Python runtime required to package inside the existing builder."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
out = args.out.resolve(strict=True)
provision_path = out / "jammy-provision.json"
provision = json.loads(provision_path.read_text())
cid = provision["container"]
commands = []

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as s:
        return hashlib.file_digest(s, "sha256").hexdigest()

started = utc()
log = out / "jammy-archive-tools.log"
with log.open("x") as stream:
    def run(*cmd, timeout=60):
        commands.append(list(cmd))
        print(json.dumps(cmd), file=stream, flush=True)
        result = subprocess.run(cmd, cwd=repo, text=True, capture_output=True, timeout=timeout)
        print(result.stdout, end="", file=stream)
        print(result.stderr, end="", file=stream)
        print(f"exit={result.returncode}", file=stream, flush=True)
        result.check_returncode()
        return result.stdout.strip()

    def stamp():
        assert run("git", "rev-parse", "HEAD") == provision["source_commit"]
        actual = run("python3", "scripts/production_score.py", "--source-id")
        assert actual == provision["source_after"]
        return actual

    before = stamp()
    assert not json.loads(run("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"))
    run("docker", "network", "connect", "bridge", cid)
    try:
        run("docker", "exec", cid, "sh", "-ec",
            "apt-get -o Acquire::Retries=1 update && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y --no-install-recommends python3 && apt-get clean", timeout=210)
    finally:
        run("docker", "network", "disconnect", "bridge", cid)
    assert not json.loads(run("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"))
    run("docker", "exec", cid, "sh", "-ec", 'test "$(wc -l </proc/net/route)" -eq 1 && test -z "$(ls -A /build-target)"')
    python_version = run("docker", "exec", cid, "python3", "--version")
    assert python_version.startswith("Python 3.10.")
    packages = out / "jammy-archive-dpkg.txt"
    packages.write_text(run("docker", "exec", cid, "dpkg-query", "-W", "-f=${binary:Package} ${Version}\\n") + "\n")
    after = stamp()

data = {
    "source_commit": provision["source_commit"], "source_id": before, "source_before": before, "source_after": after,
    "started_utc": started, "finished_utc": utc(), "exit_code": 0, "container": cid,
    "python": python_version, "system_packages_sha256": sha(packages), "provision_receipt_sha256": sha(provision_path),
    "commands": commands, "log_sha256": sha(log), "runner_sha256": sha(Path(__file__)),
}
(out / "jammy-archive-tools.json").write_text(json.dumps(data, indent=2) + "\n")
print(f"{python_version} ready. Jammy builder disconnected and target empty.")
