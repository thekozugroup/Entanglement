#!/usr/bin/env python3
"""Compare the exported native archive with the first build's in-container digest."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parent
initial = root / "jammy-offline/jammy-build.log"
initial_failure = root / "jammy-offline/jammy-build-failure.json"
replay = root / "jammy-replay/jammy-linux-archive.json"

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def cmd(*args):
    return subprocess.check_output(args, text=True).strip()

first = json.loads(initial_failure.read_bytes())
second = json.loads(replay.read_bytes())
source = cmd("python3", "scripts/production_score.py", "--source-id")
commit = cmd("git", "rev-parse", "HEAD")
assert source == first["source_before"] == first["source_after"] == second["source_before"] == second["source_after"]
assert first["source_commit"] == second["source_commit"] == commit
assert first["build_exit_code"] == second["exit_code"] == 0 and first["exit_code"] == 1
assert sha(initial) == first["build_log_sha256"]
actual = sha(Path(second["archive_path"]))
assert actual == second["sha256"]
values = re.findall(r"^([0-9a-f]{64})  /build-target/archive/entanglement-v0\.1\.0-x86_64-unknown-linux-gnu\.tar\.gz$", initial.read_text(), re.M)
assert len(values) == 1
matches = values[0] == actual
after = cmd("python3", "scripts/production_score.py", "--source-id")
assert source == after
data = {
    "source_id": source, "source_before": source, "source_after": after, "source_commit": commit,
    "observed_at_utc": datetime.now(timezone.utc).isoformat(), "exit_code": 0 if matches else 1,
    "same_sha256": matches, "initial_in_container_sha256": values[0], "exported_archive_sha256": actual,
    "initial_build_log_sha256": sha(initial), "initial_failure_receipt_sha256": sha(initial_failure),
    "replay_archive_receipt_sha256": sha(replay),
    "scope": "Two cold Cargo builds in the same disconnected builder at the same paths. The first archive existed only in its tmpfs. Its in-container SHA-256 is compared with the actual exported second archive bytes.",
}
(root / "jammy-native-replay-comparison.json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps(data, indent=2))
raise SystemExit(data["exit_code"])
