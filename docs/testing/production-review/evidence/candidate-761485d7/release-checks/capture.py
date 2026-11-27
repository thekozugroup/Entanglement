#!/usr/bin/env python3
"""Record frozen release, scaffold and fixed-OCI checks as separate evidence groups."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--group", choices=("release", "agent", "oci"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-test", type=Path)
    args = parser.parse_args()
    root, out = args.root.resolve(strict=True), args.output.resolve(strict=True)
    log = out / "commands.log"
    sha_source = [sys.executable, "scripts/production_score.py", "--source-id"]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    record = {"command": shlex.join([sys.executable, *sys.argv]), "started_at_utc": utc(), "candidate_commit": args.candidate_commit, "stages": []}

    def capture(*command):
        return subprocess.check_output(command, cwd=root, text=True).strip()

    before = capture(*sha_source)
    record["source_before"] = before
    status = 1
    with log.open("x", encoding="utf-8") as evidence:
        evidence.write(f"Frozen commit = {capture('git', 'rev-parse', 'HEAD')}\nSource before = {before}\n")

        def run(*command, expected=0, child_env=env):
            command = list(map(str, command))
            source_before = capture(*sha_source)
            if source_before != before:
                raise RuntimeError("source drift before command")
            evidence.write(f"\n[{utc()}] $ {shlex.join(command)}\nSource before = {source_before}\n")
            evidence.flush()
            result = subprocess.run(command, cwd=root, env=child_env, stdout=evidence, stderr=subprocess.STDOUT, timeout=1200)
            source_after = capture(*sha_source)
            record["stages"].append(dict(command=command, exit_code=result.returncode, source_before=source_before, source_after=source_after))
            evidence.write(f"\nExit = {result.returncode}\nSource after = {source_after}\n")
            evidence.flush()
            if source_after != before or (expected is not None and result.returncode != expected):
                raise RuntimeError(f"unexpected result from {command[0]} with expected exit {expected}")

        try:
            assert before == args.expected_source and capture("git", "rev-parse", "HEAD") == args.candidate_commit
            if args.group == "oci":
                record["evidence_scope"] = "Fixed inert container operator test with observed resource-control limitation. No native adapter registration."
                run("bash", out / "probe.sh")
            elif args.group == "agent":
                binary = args.session_test.resolve(strict=True)
                record["test_binary_sha256"] = sha(binary)
                record["evidence_scope"] = "Session config adapter snapshot and restore scaffold tests."
                run(binary, "--ignored", "--test-threads=1", "--nocapture")
                assert record["test_binary_sha256"] == sha(binary)
            else:
                cosign = Path("/tmp/entanglement-cosign-check.OZB1U0/cosign")
                actionlint = Path("/tmp/entanglement-actionlint.CUzrbA/actionlint")
                assert sha(cosign) == "783b5d6c74105401c63946c68d9b2a4e1aab3c8abce043e06b8510b02b623ec9"
                record["tool_hashes"] = {str(path): sha(path) for path in (cosign, actionlint)}
                env.update(CARGO_HOME="/workspace/.entanglement-dev/cargo", RUSTUP_HOME="/workspace/.entanglement-dev/rustup",
                           RUSTUP_TOOLCHAIN="1.91", CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0",
                           CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true")
                env["PATH"] = str(cosign.parent) + os.pathsep + str(Path(env["CARGO_HOME"]) / "bin") + os.pathsep + env["PATH"]
                record["build_env"] = {k: v for k, v in env.items() if k in ("PATH", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "CARGO_PROFILE_DEV_DEBUG", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE")}
                record["evidence_scope"] = "Installer portability fixtures, locally run release and signature conformance, and observed governance state."
                run("rustc", "--version")
                run(cosign, "version")
                run("openssl", "version")
                run(actionlint, ".github/workflows/release.yml", ".github/workflows/ci.yml")
                run(sys.executable, out / "installer-fixture.py")
                governance = {**env, "GITHUB_REPOSITORY": "thekozugroup/Entanglement"}
                governance.pop("GH_TOKEN", None)
                governance.pop("GITHUB_TOKEN", None)
                run(sys.executable, "scripts/check-release-governance.py", expected=None, child_env=governance)
                run(sys.executable, "scripts/check-release-governance.py", "--bus-factor-only", expected=None, child_env=governance)
                run("test", "-s", "docs/governance/key-ceremony.md", expected=None)
                run("bash", "scripts/tests/release-verify.sh")
                run("cargo", "test", "--locked", "-p", "entangle-cli", "--test", "release_verify")
                with tempfile.TemporaryDirectory(prefix="entangle-promotion-negative-") as temp:
                    promotion = {**env, "GITHUB_REF_NAME": "v1.0.0", "PUBLISHER_SIGNATURES": "{}", "ENTANGLE_RELEASE_PUBLISHER_KEY": ""}
                    run(sys.executable, "scripts/verify-release-promotion.py", temp, expected=1, child_env=promotion)
                    assert not list(Path(temp).iterdir())
            status = 0
        except Exception as error:
            record["error"] = repr(error)
            evidence.write(f"\nFAIL {error!r}\n")
        record["source_after"] = capture(*sha_source)
        if record["source_after"] != before:
            status = 1
        evidence.write(f"\nSuite exit = {status}\nSource after = {record['source_after']}\n")
    record.update(source_id=before, finished_at_utc=utc(), exit_code=status, path=str(log.relative_to(root)), sha256=sha(log))
    (out / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: record.get(k) for k in ("path", "exit_code", "source_id", "source_after", "error")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
