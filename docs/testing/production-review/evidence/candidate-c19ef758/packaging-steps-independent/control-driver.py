#!/usr/bin/env python3
"""Run native packager controls on fresh copies of the six genuine inputs."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


reference, canonical_dir = map(Path, sys.argv[1:])
manifest = json.loads((canonical_dir / "verification.json").read_text())
assert manifest["source_commit"] == "c19ef7587a2215ef9434b642413bebd0473caf20"


def stamp():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    source = subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"],
                                     text=True).strip()
    assert revision == manifest["source_commit"]
    assert source == manifest["source_id"] == manifest["source_after"]
    return source


def invoke(stage, output):
    helper = stage / "scripts/package-native-release.py"
    assert sha(helper) == manifest["release_helper_sha256"]
    command = [sys.executable, "-B", str(helper), "--version", "v0.1.0", "--target",
               "x86_64-unknown-linux-gnu", "--source-date-epoch", str(manifest["source_date_epoch"]),
               "--bin-dir", str(stage / "bin"), "--output-dir", str(output)]
    started = utc()
    result = subprocess.run(command, capture_output=True, text=True, timeout=150)
    return {"command": command, "started_utc": started, "finished_utc": utc(),
            "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


before = stamp()
name = manifest["name"]
canonical = canonical_dir / name
assert sha(canonical) == manifest["sha256"]
members = {"LICENSE", "README.md", "architecture.md", "entangle", "entangled", "tutorial.md"}
assert members == set(manifest["files_sha256"])

with tempfile.TemporaryDirectory(prefix="entangle-c19-controls-") as tmp:
    fixture = Path(tmp)
    unrelated = fixture / "unrelated-sentinel.txt"
    unrelated.write_bytes(b"out-of-tree release qualification sentinel\n")
    unrelated_digest = sha(unrelated)

    changed = fixture / "changed"
    shutil.copytree(reference, changed)
    readme = changed / "README.md"
    with readme.open("ab") as stream:
        stream.write(b"\nControlled packaging content variation.\n")
    changed_sha = sha(readme)
    (changed / "bin/extra-unlisted").write_bytes(b"unlisted input must never enter a release archive\n")
    license_file = changed / "LICENSE"
    regular_copy = shutil.copyfile(license_file, fixture / "trusted-regular-license")
    license_file.unlink()
    os.link(regular_copy, license_file)
    assert license_file.stat().st_nlink == 2
    changed_output = fixture / "changed-output"
    content_changed = invoke(changed, changed_output)
    assert content_changed["exit_code"] == 0, content_changed
    changed_archive = changed_output / name
    changed_archive_digest = sha(changed_archive)
    assert changed_archive_digest != manifest["sha256"]
    blake3 = subprocess.check_output(["b3sum", "--no-names", changed_archive], text=True).strip()
    assert blake3 != manifest["blake3"]
    assert (changed_output / (name + ".sha256")).read_text() == f"{changed_archive_digest}  {name}\n"
    assert (changed_output / (name + ".b3")).read_text() == f"{blake3}  {name}\n"
    with tarfile.open(changed_archive, "r:gz") as archive:
        files = {Path(item.name).name: item for item in archive if not item.isdir()}
        assert set(files) == members
        for base, item in files.items():
            assert item.isreg()
            with archive.extractfile(item) as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == (
                    changed_sha if base == "README.md" else manifest["files_sha256"][base])
    content_changed.update(archive_sha256=changed_archive_digest, archive_blake3=blake3,
                           changed_whitelist_member="README.md", changed_member_sha256=changed_sha,
                           extra_unlisted_member_absent=True, authorized_regular_hardlink_archived_as_regular_file=True)

    invalid = fixture / "invalid"
    shutil.copytree(reference, invalid)
    required = invalid / "LICENSE"
    required.unlink()
    controls = []
    for kind in ("missing", "out_of_tree_symlink", "fifo"):
        if kind == "out_of_tree_symlink":
            required.symlink_to(unrelated)
        if kind == "fifo":
            os.mkfifo(required)
        output = fixture / (kind + "-output")
        result = invoke(invalid, output)
        assert result["exit_code"] == 1 and list(output.iterdir()) == []
        assert str(required) in result["stderr"]
        assert sha(unrelated) == unrelated_digest
        result.update(case=kind, missing_archive_and_sidecars=True, sentinel_preserved=True)
        controls.append(result)
        required.unlink(missing_ok=True)

    destination = fixture / "destination"
    destination.mkdir()
    archive_path = destination / name
    archive_path.symlink_to(unrelated)
    collision = invoke(reference, destination)
    assert collision["exit_code"] == 1
    assert list(destination.iterdir()) == [archive_path]
    assert archive_path.readlink() == unrelated and sha(unrelated) == unrelated_digest
    collision.update(case="archive_destination_symlink_collision", sentinel_preserved=True,
                     symlink_preserved=True, staged_sidecars_removed=True)
    controls.append(collision)

assert sha(canonical) == manifest["sha256"]
print(json.dumps({"source_commit": manifest["source_commit"], "source_id": before, "source_after": stamp(),
                  "canonical_archive_sha256": manifest["sha256"], "source_date_epoch": manifest["source_date_epoch"],
                  "packager_sha256": manifest["release_helper_sha256"], "changed_content": content_changed,
                  "rejections": controls, "exit_code": 0}, indent=2))
