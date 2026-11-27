#!/usr/bin/env python3
"""Compare independently rebuilt Ubuntu WASI fixture sizes and SHA-256 digests."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
jammy_path = root / "jammy-replay/jammy-hello-world-package.json"
noble_path = root / "noble-retry/noble-hello-world-package.json"
provision_path = root / "jammy-replay/jammy-provision.json"

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

reports = [json.loads(path.read_text()) for path in (jammy_path, noble_path)]
jammy, noble = reports
before = subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"], text=True).strip()
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
for item in reports:
    assert item["source_before"] == item["source_after"] == before
    assert item["source_commit"] == commit
    assert item["exit_code"] == 0 and item["archive_size"] > 0 and len(item["archive_sha256"]) == 64
assert sha(jammy_path.with_suffix(".log")) == jammy["log_sha256"]
assert sha(noble_path.with_suffix(".log")) == noble["sha256"]
assert jammy["tool_sha256"] != noble["tool_sha256"]
installed_jammy = json.loads(provision_path.read_text())
assert noble["compiler"] == installed_jammy["compiler"]
equal = (jammy["archive_sha256"], jammy["archive_size"]) == (noble["archive_sha256"], noble["archive_size"])
result = {
    "source_commit": commit, "source_id": before, "source_before": before,
    "source_after": subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"], text=True).strip(),
    "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    "archives_match_by_sha256_and_size": equal, "exit_code": 0 if equal else 1,
    "images": {
        "ubuntu_22_04": installed_jammy["image"],
        "ubuntu_24_04": noble["image"],
    },
    "archive_sha256": {"ubuntu_22_04": jammy["archive_sha256"], "ubuntu_24_04": noble["archive_sha256"]},
    "archive_size": {"ubuntu_22_04": jammy["archive_size"], "ubuntu_24_04": noble["archive_size"]},
    "input_receipt_sha256": {"ubuntu_22_04": sha(jammy_path), "ubuntu_24_04": sha(noble_path)},
    "native_packager_sha256": {"ubuntu_22_04": jammy["tool_sha256"], "ubuntu_24_04": noble["tool_sha256"]},
    "scope": "Fresh guest builds and local tar.zst packaging under two Ubuntu versions on one x86_64 Linux host. macOS 14 remains unverified.",
}
assert result["source_after"] == before
(root / "ubuntu-guest-package-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
raise SystemExit(result["exit_code"])
