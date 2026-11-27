#!/usr/bin/env python3
"""Check the exact canonical archive against one recreated by the workflow body."""

import hashlib
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile

here = Path(__file__).resolve().parent
root = here.parents[5]
commit = "c19ef7587a2215ef9434b642413bebd0473caf20"
source = "sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644"
candidate = root / "target/release-candidate" / commit[:12]
archive = json.loads((candidate / "verification.json").read_text())
checkout_receipt = json.loads((here.parent / "linux-archive.json").read_text())
assert checkout_receipt == archive

def out(*args):
    return subprocess.check_output(args, cwd=root, text=True).strip()

def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def stamp():
    assert out("git", "rev-parse", "HEAD") == commit
    assert out(sys.executable, "scripts/production_score.py", "--source-id") == source
    return source

start = stamp()
assert archive["source_commit"] == commit and archive["source_id"] == archive["source_after"] == start
epoch = int(out("git", "log", "-1", "--no-show-signature", "--format=%ct", "HEAD"))
assert archive["source_date_epoch"] == epoch
label = archive["name"]
canonical = candidate / label
independent = Path(sys.argv[1]).resolve(strict=True) / label
hashes = {}
for suffix in ("", ".sha256", ".b3"):
    original = Path(f"{canonical}{suffix}")
    repeat = Path(f"{independent}{suffix}")
    subprocess.run(["cmp", original, repeat], check=True)
    hashes[suffix or ".tar.gz"] = sha(original)
assert hashes[".tar.gz"] == archive["sha256"]
assert sha(root / "scripts/package-native-release.py") == archive["release_helper_sha256"]

with canonical.open("rb") as file:
    header = struct.unpack("<BBBBIBB", file.read(10))
    assert header == (0x1F, 0x8B, 8, 0, epoch, 2, 255)
with gzip.open(canonical) as file:
    assert file.read(512)[257:265] == b"ustar\x0000"
with tarfile.open(canonical, "r:gz") as tar:
    entries = tar.getmembers()
    base = canonical.name.removesuffix(".tar.gz")
    order = ("LICENSE", "README.md", "architecture.md", "entangle", "entangled", "tutorial.md")
    assert [item.name for item in entries] == [base, *(f"{base}/{name}" for name in order)]
    assert entries[0].isdir() and entries[0].mode == 0o755
    for item in entries:
        assert (item.uid, item.gid, item.uname, item.gname, item.mtime) == (0, 0, "", "", epoch)
        assert not item.pax_headers
    for name, item in zip(order, entries[1:], strict=True):
        assert item.isfile() and item.mode == (0o755 if name in ("entangle", "entangled") else 0o644)
        with tar.extractfile(item) as file:
            assert hashlib.file_digest(file, "sha256").hexdigest() == archive["files_sha256"][name]

report = {
    "source_commit": commit,
    "source_id": start,
    "source_after": stamp(),
    "exit_code": 0,
    "command": [sys.executable, *sys.argv],
    "source_date_epoch": epoch,
    "archive_and_sidecars_sha256": hashes,
    "verified_member_order": [item.name for item in entries],
    "verified_member_content_sha256": archive["files_sha256"],
    "log_sha256": sha(here / "test.log"),
    "package_shell_block_sha256": sha(here / "package-shell-block.sh"),
    "smoke_shell_block_sha256": sha(here / "smoke-shell-block.sh"),
    "legacy_comparison_sha256": sha(here.parent / "reproducible-package-engineering/summary.json"),
    "scope": "Byte-identical packaging from fixed release inputs. This comparison uses preserved native executable bytes.",
}
print(json.dumps(report, indent=2))
