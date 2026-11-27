#!/usr/bin/env python3
"""Run catalog workloads using native release binaries and record their identities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["aarch64-apple-darwin", "x86_64-apple-darwin",
                                          "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"])
    parser.add_argument("bin_dir", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    machine = {"arm64": "aarch64"}.get(platform.machine(), platform.machine())
    system = platform.system()
    suffix = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu"}.get(system)
    target = f"{machine}-{suffix}"
    if target != args.target:
        raise RuntimeError(f"target {args.target} requires native execution; current host reports {target}")
    if system == "Darwin":
        translated = subprocess.run(["sysctl", "-in", "sysctl.proc_translated"], capture_output=True, text=True)
        if translated.stdout.strip() == "1":
            raise RuntimeError("translated process cannot provide native workload evidence")
        cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        os_version = platform.mac_ver()[0]
    else:
        lines = Path("/proc/cpuinfo").read_text().splitlines()
        cpu = next((line.split(":", 1)[1].strip() for line in lines
                    if line.startswith(("model name", "Hardware", "CPU part"))), machine)
        os_version = platform.freedesktop_os_release().get("PRETTY_NAME", platform.release())
    bins = [args.bin_dir.resolve(strict=True) / name for name in ["entangle", "entangled"]]
    command = [sys.executable, str(ROOT / "plugins/smoke_test.py"), *map(str, bins), "--two-node"]
    env = dict(os.environ)
    env.setdefault("CARGO_HOME", str(Path.home() / ".cargo"))
    env.setdefault("RUSTUP_HOME", str(Path.home() / ".rustup"))
    if system == "Darwin":
        # Darwin assigns long per-user TMPDIR paths that can exceed sockaddr_un.
        env["TMPDIR"] = "/tmp"
    identity = [sys.executable, str(ROOT / "scripts/production_score.py"), "--source-id"]
    source = subprocess.check_output(identity, cwd=ROOT, text=True).strip()
    result = subprocess.run(command, env=env)
    if subprocess.check_output(identity, cwd=ROOT, text=True).strip() != source:
        raise RuntimeError("source changed during native release validation")
    report = {"source_id": source, "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "target": target, "os": os_version, "machine": platform.machine(), "cpu": cpu,
              "runner_arch": os.environ.get("RUNNER_ARCH"),
              "runner_image": os.environ.get("ImageVersion"), "run_id": os.environ.get("GITHUB_RUN_ID"),
              "binary_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in bins},
              "command": command, "exit_code": result.returncode}
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
