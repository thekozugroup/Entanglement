#!/usr/bin/env python3
"""Bind mixed-ISA and pinned Linux userspace smoke checks to one release receipt."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
for name in ("repo", "out", "archive", "archive-receipt", "b3sum", "emulator"):
    parser.add_argument("--" + name, type=Path, required=True)
for name in ("commit", "source-id"):
    parser.add_argument("--" + name, required=True)
args = parser.parse_args()
repo = args.repo.resolve(strict=True)
out = args.out.resolve(strict=True)
evidence = repo / "docs/testing/production-review/evidence"
old = evidence / "candidate-c19ef758/emulated-linux-arm64"
archive = args.archive.resolve(strict=True)
receipt = args.archive_receipt.resolve(strict=True)
arm = repo / "target/release-candidate/c19ef7587a22-aarch64/entanglement-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
wasm = repo / "target/catalog-smoke/wasm32-wasip2/release/entangle_json_pointer.wasm"

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def command(*argv):
    return subprocess.check_output(argv, cwd=repo, text=True).strip()

def stamp():
    assert command("git", "rev-parse", "HEAD") == args.commit
    stamp = command("python3", "scripts/production_score.py", "--source-id")
    assert stamp == args.source_id
    return stamp

def relative(path):
    return str(path.relative_to(repo))

success = True
with tempfile.TemporaryDirectory(dir="/workspace", prefix="entangle-qualify-mixed-") as work:
    folders = {}
    for experiment in ("mixed-release-arm64",):
        folder = out / experiment
        folder.mkdir()
        folders[experiment] = folder
    commands = {
        "mixed-release-arm64": (
            "mixed-verified.py", "--work", work, "--x86", archive, "--x86-receipt", receipt,
            "--arm", arm, "--arm-receipt", old / "arm-archive.json",
            "--emulator", args.emulator.resolve(strict=True),
            "--emulator-provenance", evidence / "candidate-296b427a/mixed-release-arm64",
        ),
    }
    for key, (script, *specific) in commands.items():
        folder = folders[key]
        raw = folder / "run.log"
        argv = [
            "python3", "-B", str(Path(__file__).with_name(script)),
            "--repo", str(repo), "--out", str(folder), "--commit", args.commit,
            "--source-id", args.source_id, "--wasm", str(wasm), "--b3sum",
            str(args.b3sum.resolve(strict=True)), *(str(item) for item in specific),
        ]
        print(shlex.join(argv), flush=True)
        before = stamp()
        started = utc()
        with raw.open("xb") as stream:
            status = subprocess.run(argv, cwd=repo, stdout=stream, stderr=subprocess.STDOUT).returncode
        finished = utc()
        after = stamp()
        result = folder / ("mixed-release-arm64.json" if key == "mixed-release-arm64" else "userspaces.json")
        produced = result if result.is_file() and status == 0 else raw
        data = {
            "source_id": before, "source_commit": args.commit, "source_before": before, "source_after": after,
            "started_utc": started, "finished_utc": finished, "observed_at_utc": finished,
            "command": argv, "log": relative(produced), "sha256": sha(produced), "exit_code": status,
            "run_log": relative(raw), "run_log_sha256": sha(raw),
        }
        if (folder / "commands.jsonl").is_file():
            data["commands_log_sha256"] = sha(folder / "commands.jsonl")
        if status == 0:
            verified = json.loads(result.read_text())
            assert verified["source_before"] == verified["source_after"] == before
            assert verified["exit_code"] == 0
            if key == "mixed-release-arm64":
                data["summary"] = {
                    "architecture": "native x86_64 coordinator and QEMU-emulated AArch64 worker",
                    "worker_source_commit": verified["inputs"]["arm"]["source_commit"],
                    "chosen_peer": verified["dispatch"]["chosen_peer"],
                    "output_sha256": verified["dispatch"]["output_sha256"],
                    "coordinator_invocations": verified["dispatch"]["after"]["x86"]["ok"],
                    "worker_invocations": verified["dispatch"]["after"]["arm"]["ok"],
                }
            else:
                data["summary"] = {
                    "archive_sha256": verified["archive_sha256"],
                    "required_glibc": {name: row["required_glibc"] for name, row in verified["elf"].items()},
                    "outcomes": {os: case["outcome"] for os, case in verified["cases"].items()},
                }
        (folder / "normalized.json").write_text(json.dumps(data, indent=2) + "\n")
        print(f"{key} exit {status}: {raw.read_text().strip()}", flush=True)
        success = success and status == 0
raise SystemExit(0 if success else 1)
