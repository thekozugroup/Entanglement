#!/usr/bin/env python3
"""Qualify the archived Jammy-native binaries across the same four disconnected userspaces."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
repo = Path("/workspace/Entanglement")
out = args.out.resolve(strict=True)
base = out.parent
receipt = base / "jammy-build/jammy-linux-archive.json"
build = json.loads(receipt.read_text())
archive = Path(build["archive_path"])
b3sum = Path("/tmp/entangle-release-followup/tools/b3sum")
wasm = repo / "target/catalog-smoke/wasm32-wasip2/release/entangle_json_pointer.wasm"

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def get(*command):
    return subprocess.check_output(command, cwd=repo, text=True).strip()

def utc():
    return datetime.now(timezone.utc).isoformat()

def stamp():
    assert get("git", "rev-parse", "HEAD") == build["source_commit"]
    actual = get("python3", "scripts/production_score.py", "--source-id")
    assert actual == build["source_before"] == build["source_after"]
    return actual

started = utc()
before = stamp()
assert build["exit_code"] == 0
assert build["sha256"] == sha(archive)
verifier = ["bash", "scripts/verify-release.sh", "--checksums-only", str(archive)]
environment = dict(os.environ, PATH=str(b3sum.parent) + ":" + os.environ["PATH"])
verification_log = out / "verify-release.log"
with verification_log.open("xb") as output:
    verification = subprocess.run(verifier, cwd=repo, env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=45)
    verification.check_returncode()
cmd = [
    "python3", "-B", str(base / "userspaces.py"), "--repo", str(repo), "--out", str(out),
    "--archive", str(archive), "--archive-receipt", str(receipt),
    "--wasm", str(wasm), "--b3sum", str(b3sum), "--commit", build["source_commit"],
    "--source-id", before, "--max-glibc", "2.35",
]
log = out / "run.log"
with log.open("xb") as output:
    status = subprocess.run(cmd, cwd=repo, stdout=output, stderr=subprocess.STDOUT, timeout=180).returncode
after = stamp()
result_path = out / "userspaces.json"
source_log = result_path if status == 0 else log
record = {
    "source_commit": build["source_commit"], "source_id": before, "source_before": before, "source_after": after,
    "started_utc": started, "finished_utc": utc(), "exit_code": status, "command": cmd, "log": str(source_log.relative_to(repo)),
    "sha256": sha(source_log), "run_log_sha256": sha(log), "verify_release": verifier,
    "verify_release_log_sha256": sha(verification_log), "verify_release_exit": verification.returncode,
    "archive_sha256": sha(archive), "archive_build_receipt_sha256": sha(receipt),
}
if status == 0:
    result = json.loads(result_path.read_bytes())
    assert result["source_before"] == result["source_after"] == before
    assert len(result["cases"]) == 4
    assert all(case["outcome"] == "signed_guest_passed" for case in result["cases"].values())
    record["distro_cases"] = {distro: case["outcome"] for distro, case in result["cases"].items()}
    record["required_glibc"] = {name: row["required_glibc"] for name, row in result["elf"].items()}
(out / "normalized.json").write_text(json.dumps(record, indent=2) + "\n")
print(log.read_text(), end="")
raise SystemExit(status)
