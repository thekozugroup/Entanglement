#!/usr/bin/env python3
"""Verify two independent packages per frozen staging variation."""

from datetime import datetime, timezone
import gzip
import hashlib
from itertools import combinations
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile


here = Path(__file__).resolve().parent
root = here.parents[5]
candidate = here.parent
original_runs, repeated_runs = map(Path, sys.argv[1:])
repeat = here / "repeat"
commit = "c19ef7587a2215ef9434b642413bebd0473caf20"
source = "sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644"
canonical_dir = root / "target/release-candidate" / commit[:12]
release = json.loads((canonical_dir / "verification.json").read_text())
original_receipt = candidate / "packaging-metadata-variations.json"
earlier = json.loads(original_receipt.read_text())
control_path = candidate / "packaging-input-controls.json"
controls = json.loads(control_path.read_text())
epoch = release["source_date_epoch"]
filename = release["name"]
suffixes = ("", ".sha256", ".b3")


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def output(*argv):
    return subprocess.check_output(argv, cwd=root, text=True).strip()


def stamp():
    assert output("git", "rev-parse", "HEAD") == commit
    assert output(sys.executable, "scripts/production_score.py", "--source-id") == source
    assert int(output("git", "log", "-1", "--no-show-signature", "--format=%ct", "HEAD")) == epoch
    return source


def artifact(root, suffix=""):
    return root / (filename + suffix)


def verify_tar(path):
    with path.open("rb") as stream:
        assert struct.unpack("<BBBBIBB", stream.read(10)) == (0x1F, 0x8B, 8, 0, epoch, 2, 255)
    with gzip.open(path) as stream:
        assert stream.read(512)[257:265] == b"ustar\x0000"
    label = filename.removesuffix(".tar.gz")
    names = ("LICENSE", "README.md", "architecture.md", "entangle", "entangled", "tutorial.md")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        assert [entry.name for entry in members] == [label, *(f"{label}/{name}" for name in names)]
        assert members[0].isdir() and members[0].mode == 0o755
        for entry in members:
            assert (entry.uid, entry.gid, entry.uname, entry.gname, entry.mtime) == (0, 0, "", "", epoch)
            assert not entry.pax_headers
        for name, entry in zip(names, members[1:], strict=True):
            assert entry.isreg() and entry.mode == (0o755 if name in ("entangle", "entangled") else 0o644)
            with archive.extractfile(entry) as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == release["files_sha256"][name]


def verify_artifacts(directory):
    archive = artifact(directory)
    sha256 = sha(archive)
    blake3 = output("b3sum", "--no-names", archive)
    assert sha256 == release["sha256"] and blake3 == release["blake3"]
    for checksum, suffix in [(sha256, ".sha256"), (blake3, ".b3")]:
        assert artifact(directory, suffix).read_bytes() == f"{checksum}  {filename}\n".encode("ascii")
    verify_tar(archive)
    command = ["bash", str(root / "scripts/verify-release.sh"), "--checksums-only", str(archive)]
    verified = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    return {"archive_sha256": sha256, "archive_blake3": blake3, "checksum_verifier_command": command,
            "checksum_verifier_exit_code": verified.returncode,
            "checksum_verifier_output": verified.stdout + verified.stderr}


started = utc()
before = stamp()
assert controls["source_id"] == controls["source_after"] == before
assert (controls["canonical_archive_sha256"], controls["source_date_epoch"]) == (release["sha256"], epoch)
assert controls["exit_code"] == 0
assert release["source_commit"] == commit and release["source_id"] == release["source_after"] == before
assert sha(root / "scripts/package-native-release.py") == release["release_helper_sha256"]
assert earlier["source_commit"] == commit and earlier["source_id"] == earlier["source_after"] == before
original_paths = [original_runs / member for member in ("stage a/out", "stage b/out", "stage-c")]
repeat_paths = [repeated_runs / member for member in ("atlas and ash/out", "bank of snow/out", "container-output")]
all_paths = original_paths + repeat_paths
seen_input_paths = set()
records = []
for index, letter in enumerate("abc"):
    original = here / f"variation-{letter}.json"
    repeated = repeat / f"variation-{letter}.json"
    assert sha(original) == earlier["variants"][letter]["raw_receipt_sha256"]
    first, second = [json.loads(path.read_text()) for path in (original, repeated)]
    for key in ("variant", "exit_code", "copy_order", "process_uid", "process_gid", "umask", "timezone",
                "source_date_epoch", "python", "zlib", "base_name"):
        assert first[key] == second[key], key
    assert first["exit_code"] == 0 and first["source_date_epoch"] == epoch and first["base_name"] == filename
    assert first["inputs"].keys() == second["inputs"].keys()
    for member, value in first["inputs"].items():
        again = second["inputs"][member]
        for key in ("uid", "gid", "mode", "mtime_ns", "size", "sha256"):
            assert value[key] == again[key], (member, key)
        assert value["sha256"] == release["files_sha256"][Path(member).name]
        assert value["path"] != again["path"]
        for entry in (value, again):
            assert entry["path"] not in seen_input_paths
            seen_input_paths.add(entry["path"])
    for number, receipt, observed, directory in [
        (1, original, first, original_paths[index]), (2, repeated, second, repeat_paths[index]),
    ]:
        for suffix in suffixes:
            subprocess.run(["cmp", artifact(canonical_dir, suffix), artifact(directory, suffix)], check=True)
        result = verify_artifacts(directory)
        records.append({"round": number, "variation": letter, "output_dir": str(directory),
                        "staging_observation_sha256": sha(receipt), "observed_uid": observed["process_uid"],
                        "observed_gid": observed["process_gid"], "umask": observed["umask"],
                        "timezone": observed["timezone"], **result})

pairs = 0
for left, right in combinations(all_paths, 2):
    for suffix in suffixes:
        subprocess.run(["cmp", artifact(left, suffix), artifact(right, suffix)], check=True)
    pairs += 1
assert pairs == 15 and len(records) == 6 and len(seen_input_paths) == 36
repeat_log = repeat / "metadata-repeat.log"
logged_sources = [line for line in repeat_log.read_text().splitlines() if line.startswith("sha256:")]
assert logged_sources[0] == logged_sources[-1] == before
after = stamp()
print(json.dumps({
    "source_commit": commit, "source_id": before, "source_after": after, "source_date_epoch": epoch,
    "started_utc": started, "finished_utc": utc(), "command": [sys.executable, *sys.argv],
    "exit_code": 0, "run_count": len(records), "actual_pairwise_comparison_count": pairs,
    "byte_identical_archive_and_sidecars_sha256": {suffix or ".tar.gz": sha(artifact(canonical_dir, suffix))
                                                 for suffix in suffixes},
    "canonical_archive_fields_and_member_hashes_match_every_run": True,
    "packager_sha256": release["release_helper_sha256"], "seal_helper_sha256": sha(Path(__file__)),
    "b3sum_sha256": sha(Path(shutil.which("b3sum"))),
    "first_group_receipt_sha256": sha(original_receipt), "second_group_log_sha256": sha(repeat_log),
    "input_controls_sha256": sha(control_path), "runs": records,
    "scope": "Two packages per staging variation from the same optimized ELF bytes. No independent compile claim.",
}, indent=2))
