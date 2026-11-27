"""Check locally built release archives against their source-bound package receipts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent
ROOT = EVIDENCE.parents[4]
COMMIT = "f499e3edf84e20f550312d05df51b9ea4e7cc699"
SOURCE = "sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
sys.path.insert(0, str(ROOT / "scripts"))
from native_release_layout import verify_archive_layout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source():
    return subprocess.check_output(
        [sys.executable, "scripts/production_score.py", "--source-id"], cwd=ROOT, text=True
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("archives", type=Path, nargs="+")
    args = parser.parse_args()
    before = source()
    if before != SOURCE:
        parser.error("checkout differs from the measured source")
    records = {}
    for receipt_name, target, hash_field in (
        ("linux-archive.json", "x86_64-unknown-linux-gnu", "sha256"),
        ("linux-compatibility/jammy-build/jammy-linux-archive.json", "x86_64-unknown-linux-gnu", "sha256"),
        ("linux-compatibility/current-arm64/arm-archive.json", "aarch64-unknown-linux-gnu", "archive_sha256"),
    ):
        path = EVIDENCE / receipt_name
        if path.exists():
            receipt = json.loads(path.read_bytes())
            if receipt["source_commit"] != COMMIT or receipt["source_after"] != SOURCE or receipt["source_before"] != SOURCE:
                parser.error(f"{receipt_name} identifies another source")
            records[receipt[hash_field]] = (receipt_name, target)
    started = datetime.now(timezone.utc).isoformat()
    results = []
    for path in args.archives:
        sha256 = digest(path)
        if sha256 not in records:
            parser.error(f"no matching package receipt for {path.name}")
        receipt_name, target = records[sha256]
        verify_archive_layout(path, target)
        results.append(dict(name=path.name, sha256=sha256, target=target, receipt=receipt_name))
    after = source()
    if before != after:
        parser.error("source changed during verification")
    record = dict(source_commit=COMMIT, source_before=before, source_after=after, started_utc=started,
                  finished_utc=datetime.now(timezone.utc).isoformat(), exit_code=0, archives=results,
                  scope="Exact layout, file types and target architecture of locally built unsigned archives.")
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(f"Verified layout and target of {len(results)} package(s).")


if __name__ == "__main__":
    main()
