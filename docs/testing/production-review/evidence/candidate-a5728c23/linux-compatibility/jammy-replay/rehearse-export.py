#!/usr/bin/env python3
"""Reopen the offline Jammy builder and verify an archive-sized binary export."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

out = Path(__file__).resolve().parent
provision = json.loads((out / "jammy-provision.json").read_text())
cid = provision["container"]
source = provision["source_after"]
expected_commit = provision["source_commit"]
commands = []

def utc():
    return datetime.now(timezone.utc).isoformat()

def get(*args):
    commands.append(list(args))
    return subprocess.check_output(args, timeout=50, text=True).strip()

def stamp():
    assert get("git", "rev-parse", "HEAD") == expected_commit
    assert get("python3", "scripts/production_score.py", "--source-id") == source
    return source

start = utc()
before = stamp()
assert get("docker", "inspect", cid, "--format", "{{.State.Running}}") == "false"
assert get("docker", "inspect", cid, "--format", "{{.Image}}") == provision["image_id"]
get("docker", "start", cid)
assert not json.loads(get("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"))
unpriv = ["docker", "exec", "--user", "65534:65534", cid]
assert get(*unpriv, "ls", "-A", "/build-target") == ""
assert len(get(*unpriv, "cat", "/proc/net/route").splitlines()) == 1
path = "/build-target/export-rehearsal"
bytes_expected = 30 * 1024 * 1024
try:
    get(*unpriv, "dd", "if=/dev/urandom", "of=" + path, "bs=1048576", "count=30", "status=none")
    want = get(*unpriv, "sha256sum", path).split()[0]
    cmd = [*unpriv, "/bin/cat", path]
    commands.append(cmd)
    with tempfile.TemporaryFile() as file:
        subprocess.run(cmd, stdout=file, check=True, timeout=60)
        assert file.tell() == bytes_expected
        file.seek(0)
        actual = hashlib.file_digest(file, "sha256").hexdigest()
        assert actual == want
finally:
    get(*unpriv, "rm", "-f", path)
assert get(*unpriv, "ls", "-A", "/build-target") == ""
data = {
    "source_before": before, "source_after": stamp(), "source_id": source, "source_commit": expected_commit,
    "started_utc": start, "finished_utc": utc(), "exit_code": 0, "bytes": bytes_expected, "commands": commands,
    "sha256_from_container": want, "sha256_from_host": actual,
    "scope": "Previously verified offline Jammy system packages were reused. Its build tmpfs started empty. Raw non-PTY docker exec emitted all binary bytes exactly.",
}
(out / "archive-export-rehearsal.json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({"verified_exact_bytes": bytes_expected, "sha256": actual}))
