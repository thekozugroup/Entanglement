#!/usr/bin/env python3
"""Replay the unchanged tier conformance controls on the frozen archive's two ELF members."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    evidence = Path(__file__).resolve().parent
    root = next(p for p in evidence.parents if (p / "scripts/production_score.py").is_file())
    reference = evidence.parent / "linux-archive.json"
    record = json.loads(reference.read_bytes())
    controls = evidence.parents[1] / "candidate-42bb9a33/tier-policy-boundary/verify.py"
    if args.archive.name != record["name"] or digest(args.archive) != record["sha256"]:
        raise SystemExit("archive identity mismatch")
    with tempfile.TemporaryDirectory(prefix="ent-tier-final-") as tmp:
        bins = Path(tmp)
        members = {}
        with tarfile.open(args.archive, mode="r|gz") as archive:
            for member in archive:
                name = Path(member.name).name
                if name not in ("entangle", "entangled"):
                    continue
                if not member.isfile() or name in members:
                    raise ValueError(f"unexpected release member {member.name}")
                with (bins / name).open("wb") as output:
                    shutil.copyfileobj(archive.extractfile(member), output)
                (bins / name).chmod(0o700)
                members[name] = digest(bins / name)
        expected = {name: record["files_sha256"][name] for name in ("entangle", "entangled")}
        if members != expected:
            raise SystemExit("extracted CLI or daemon differs from the release manifest")
        cmd = [sys.executable, controls, "--root", root, "--bin-dir", bins, "--reference", reference,
               "--output", evidence]
        rc = subprocess.run(cmd, cwd=root).returncode
    path = evidence / "receipt.json"
    receipt = json.loads(path.read_bytes())
    if receipt["exit_code"] != rc or receipt["release_source_commit"] != record["source_commit"]:
        raise ValueError("release control returned an inconsistent receipt")
    receipt.update(archive_sha256=record["sha256"], archive_members_sha256=members,
                   controls_sha256=digest(controls), archive_verifier_sha256=digest(Path(__file__)))
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
