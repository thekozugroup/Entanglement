#!/usr/bin/env python3
"""Retain the exact portable package tool for a separate Ubuntu guest package check."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

proof = Path(__file__).resolve().parent
provision = json.loads((proof / "jammy-provision.json").read_bytes())
container = provision["container"]
commit = provision["source_commit"]
source = provision["source_after"]
binary_name = "/build-target/target/x86_64-unknown-linux-gnu/release/cargo-entangle"
result = Path("/tmp/entangle-f499e3ed-portable-cargo-entangle")

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(item):
    with item.open("rb") as infile:
        return hashlib.file_digest(infile, "sha256").hexdigest()

def stamp():
    rev = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    actual = subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"], text=True).strip()
    assert rev == commit and actual == source
    return actual

before = stamp()
begin = utc()
deadline = time.monotonic() + 35 * 60
pattern = re.compile(r"^([0-9a-f]{64})  " + re.escape(binary_name) + "$", re.M)
while time.monotonic() < deadline:
    assert not (proof / "jammy-build-failure.json").exists()
    found = pattern.search((proof / "jammy-build.log").read_text())
    if found:
        break
    time.sleep(1)
else:
    raise RuntimeError("portable package tool did not finish within the monitored window")
expected = found[1]
command = ["docker", "exec", "--user", "65534:65534", container, "/bin/cat", binary_name]
with result.open("xb") as output:
    subprocess.run(command, check=True, stdout=output, timeout=45)
assert sha(result) == expected
sealed = proof / "jammy-linux-archive.json"
deadline = time.monotonic() + 90
while time.monotonic() < deadline:
    try:
        archive = json.loads(sealed.read_bytes())
        break
    except (OSError, json.JSONDecodeError):
        time.sleep(1)
else:
    raise RuntimeError("portable archive receipt did not seal")
assert archive["source_commit"] == commit and archive["source_before"] == source
assert archive["source_after"] == source and archive["tool_sha256"] == expected and archive["exit_code"] == 0
verify = subprocess.check_output(["readelf", "-h", result], text=True)
assert re.search(r"Machine:\s+Advanced Micro Devices X86-64", verify)
result.chmod(0o755)
assert sha(result) == expected
data = {
    "source_commit": commit, "source_id": source, "source_before": before, "source_after": stamp(),
    "started_utc": begin, "finished_utc": utc(), "exit_code": 0, "command": command,
    "tool_path": str(result), "tool_sha256": expected, "tool_bytes": result.stat().st_size,
    "binary_scope": "Unmodified portable cargo-entangle for private follow-up packaging only",
    "build_log_sha256": sha(proof / "jammy-build.log"), "archive_receipt_sha256": sha(sealed),
}
with (proof / "cargo-entangle-export.json").open("x") as output:
    json.dump(data, output, indent=2)
    output.write("\n")
print(result, expected)
