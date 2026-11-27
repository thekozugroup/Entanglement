#!/usr/bin/env python3
"""Run the frozen package compiler in two independent pinned rootless containers."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def hash_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--jammy-container", required=True)
    parser.add_argument("--noble-container", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    out = args.output.resolve(strict=True)
    log = out / "linux-matrix.log"
    record = {"command": shlex.join([sys.executable, *sys.argv]), "started_at_utc": timestamp(), "distros": {}}

    def capture(*cmd):
        return subprocess.check_output(cmd, cwd=root, text=True).strip()

    def watermark():
        return capture(sys.executable, "scripts/production_score.py", "--source-id")

    record["source_before"] = watermark()
    record["commit"] = capture("git", "rev-parse", "HEAD")
    record["docker_security"] = json.loads(capture("docker", "info", "--format", "{{json .SecurityOptions}}"))
    status = int(record["source_before"] != args.expected_source or "name=rootless" not in record["docker_security"])
    with log.open("x", encoding="utf-8") as summary, tempfile.TemporaryDirectory(prefix="entangle Ubuntu archives ", dir="/tmp") as temp:
        summary.write(f"Frozen source before = {record['source_before']}\nSecurity options = {record['docker_security']}\n")
        if not status:
            for version, container in [("22.04", args.jammy_container), ("24.04", args.noble_container)]:
                run_log = out / f"ubuntu-{version}-build.log"
                cmd = ["docker", "exec", container, "/bin/bash", "/fixture/run-in-container.sh", version, record["commit"]]
                result = record["distros"][version] = {
                    "source_before": watermark(),
                    "image_id": capture("docker", "inspect", container, "--format", "{{.Image}}"),
                    "networks": json.loads(capture("docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}")),
                    "command": shlex.join(cmd),
                }
                archive = Path(temp) / f"ubuntu-{version}.tar.zst"
                with run_log.open("x", encoding="utf-8") as evidence:
                    evidence.write(f"Started at {timestamp()}\n$ {shlex.join(cmd)}\n")
                    evidence.flush()
                    if result["networks"] or result["source_before"] != args.expected_source:
                        result["exit_code"] = 1
                        evidence.write("Aborted due to active container networking or a source change.\n")
                    else:
                        result["exit_code"] = subprocess.run(cmd, stdout=evidence, stderr=subprocess.STDOUT).returncode
                    evidence.write(f"\nExit = {result['exit_code']}\n")
                    if result["exit_code"] == 0:
                        copy = ["docker", "cp", f"{container}:/tmp/hello-world.tar.zst", str(archive)]
                        evidence.write(f"$ {shlex.join(copy)}\n")
                        evidence.flush()
                        result["copy_exit_code"] = subprocess.run(copy, stdout=evidence, stderr=subprocess.STDOUT).returncode
                        if result["copy_exit_code"] == 0:
                            result["archive_sha256"] = hash_file(archive)
                            evidence.write(f"Archive SHA-256 copied from the container = {result['archive_sha256']}\n")
                result["source_after"] = watermark()
                result["log"] = str(run_log.relative_to(root))
                result["log_sha256"] = hash_file(run_log)
                summary.write(f"\nUbuntu {version}\n{json.dumps(result, indent=2)}\n")
                summary.flush()
                status |= int(result["exit_code"] != 0 or result.get("copy_exit_code") != 0 or result["source_after"] != args.expected_source)
                if result.get("archive_sha256"):
                    subprocess.run(["docker", "rm", "-f", container], check=True, stdout=summary)
        record["source_after"] = watermark()
        record["source_matches"] = record["source_before"] == record["source_after"] == args.expected_source
        archives = [value.get("archive_sha256") for value in record["distros"].values()]
        record["archive_digests_match"] = len(archives) == 2 and archives[0] is not None and archives[0] == archives[1]
        status |= int(not record["archive_digests_match"] or not record["source_matches"])
        summary.write(f"\nArchive digests match = {record['archive_digests_match']}\nFrozen source after = {record['source_after']}\nSuite exit = {status}\n")
    record.update(path=str(log.relative_to(root)), sha256=hash_file(log), source_id=record["source_before"], exit_code=status, observed_at_utc=timestamp(), claim="Direct reproducibility in separate rootless Ubuntu 22.04 and 24.04 userspaces on one x86_64 Linux host.")
    (out / "linux-matrix.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record[key] for key in ("path", "exit_code", "source_id", "source_matches", "archive_digests_match")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
