#!/usr/bin/env python3
"""Repeat final workspace inference tests without rebuilding test executables."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--unit", type=Path, required=True)
    parser.add_argument("--integration", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    unit, integration, daemon = (p.resolve(strict=True) for p in (args.unit, args.integration, args.daemon))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    log = output / "inference-compatibility.log"
    record = {
        "command": shlex.join([sys.executable, *sys.argv]),
        "host": {"os": platform.system(), "arch": platform.machine(), "kernel": platform.release()},
        "commands": [],
    }

    def watermark():
        return subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"], cwd=root, text=True).strip()

    def hashes():
        return {str(p): sha(p) for p in (unit, integration, daemon)}

    record["source_before"] = watermark()
    record["artifacts_before"] = hashes()
    commands = [
        [unit, "inference::tests", "--nocapture"],
        [integration, "inference::configured_inference_streams_incremental_signed_chunks", "--exact", "--nocapture"],
    ]
    status = int(record["source_before"] != args.expected_source)
    with log.open("x", encoding="utf-8") as evidence:
        evidence.write(f"Source before = {record['source_before']}\n")
        if not status:
            for cmd in commands:
                argv = list(map(str, cmd))
                evidence.write(f"\n$ {shlex.join(argv)}\n")
                evidence.flush()
                completed = subprocess.run(argv, cwd=root, stdout=evidence, stderr=subprocess.STDOUT, timeout=90)
                evidence.write(f"\nExit = {completed.returncode}\n")
                record["commands"].append({"argv": argv, "exit_code": completed.returncode})
                status |= int(completed.returncode != 0)
        record["source_after"] = watermark()
        record["artifacts_after"] = hashes()
        record["source_matches"] = record["source_before"] == record["source_after"] == args.expected_source
        record["artifacts_match"] = record["artifacts_before"] == record["artifacts_after"]
        status |= int(not record["source_matches"] or not record["artifacts_match"])
        evidence.write(f"\nSource after = {record['source_after']}\nBinaries stable = {record['artifacts_match']}\nSuite exit = {status}\n")
    record.update(path=str(log.relative_to(root)), sha256=sha(log), source_id=record["source_before"], exit_code=status, observed_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"), claim="Standard chat and completions SSE interoperability over authenticated two-daemon loopback, with signed progressive chunks, readiness and tier gating, and signed WASI fallback.")
    (output / "inference-compatibility.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record[key] for key in ("path", "exit_code", "source_id", "source_matches", "artifacts_match")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
