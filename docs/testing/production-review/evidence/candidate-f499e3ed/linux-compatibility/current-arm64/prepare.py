#!/usr/bin/env python3
"""Stage the already qualified build procedures for the final frozen source."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

repo = Path("/workspace/Entanglement")
commit = "f499e3edf84e20f550312d05df51b9ea4e7cc699"
source_id = "sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
previous_commit = "90beded509f93909507c78f2986dea0e085e4f1e"
previous_source = "sha256:f55d4a44e7f128f7e059ecd7c93625be91e7f56484c49f93b7920e9266cf6cbb"
evidence = repo / "docs/testing/production-review/evidence"
old = evidence / "candidate-90beded5/linux-compatibility"
out = evidence / "candidate-f499e3ed/linux-compatibility"
arm_old = Path("/workspace/entangle-emulated-arm-90beded5-slim")
arm = Path("/workspace/entangle-emulated-arm-f499e3ed-slim")

def get(*cmd, cwd=repo):
    return subprocess.check_output(cmd, cwd=cwd, text=True, timeout=40).strip()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def assert_source(path):
    assert get("git", "rev-parse", "HEAD", cwd=path) == commit
    assert get(sys.executable, "scripts/production_score.py", "--source-id", cwd=path) == source_id

def adapt(path, destination):
    text = path.read_text()
    for prior, current in (
        (str(arm_old), str(arm)),
        ("/workspace/entangle-emulated-arm-90beded5", str(arm)),
        (previous_commit, commit),
        (previous_source, source_id),
        (previous_commit[:12], commit[:12]),
        (previous_commit[:8], commit[:8]),
    ):
        text = text.replace(prior, current)
    if destination.suffix == ".py":
        compile(text, str(destination), "exec")
    destination.write_text(text)
    if destination.suffix == ".sh":
        subprocess.run(["sh", "-n", destination], check=True)

assert_source(repo)
assert not get("git", "diff", previous_commit, commit, "--", "Cargo.lock", "rust-toolchain.toml")
assert get("git", "rev-parse", commit + ":plugins/json-pointer") == "14a946aac15de3b9952eebe0bba5c82e47565b6a"
assert shutil.disk_usage(repo).free >= 2048 * 1024**2
out.mkdir(parents=True, exist_ok=False)
(out / "jammy-build").mkdir()
for filename in (
    "build-jammy.sh", "check-jammy.py", "probe-jammy-tmpfs.py", "stage-jammy.py",
    "stage-jammy-archive-tools.py", "portable-jammy.py",
):
    adapt(old / "jammy-build" / filename, out / "jammy-build" / filename)
for filename in (
    "run-arm.sh", "run-jammy.sh", "run-canonical.sh", "portable-smoke.py", "userspaces.py",
):
    adapt(old / filename, out / filename)
shutil.copyfile(Path(__file__), out / "prepare-platforms.py")

arm.mkdir(mode=0o755)
arm.chmod(0o755)
(arm / "proof").mkdir()
source_dir = arm / "frozen"
subprocess.run(["git", "clone", "--shared", "--no-checkout", "--no-tags", repo, source_dir], check=True, timeout=40)
subprocess.run(
    ["git", "sparse-checkout", "set", "--no-cone", "/*", "!/docs/testing/production-review/evidence/",
     "!/docs/testing/production-review/runs/"], cwd=source_dir, check=True, timeout=40,
)
subprocess.run(["git", "checkout", "--detach", commit], cwd=source_dir, check=True, timeout=40)
source_dir.chmod(0o755)
for path in source_dir.rglob("*"):
    if path.is_symlink() or ".git" in path.relative_to(source_dir).parts:
        continue
    path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
assert_source(source_dir)
for filename in ("provision.py", "finish.py",
                 "proof/arm-build-driver.py", "proof/package-arm.py", "proof/signed-workload.py",
                 "proof/standalone-local.py", "proof/cross-build.sh", "proof/provision-tools.sh"):
    adapt(arm_old / filename, arm / filename)
shutil.copyfile(Path(__file__), arm / "prepare.py")
assert_source(repo)
record = {
    "source_commit": commit, "source_before": source_id, "source_after": source_id,
    "arm_workspace": str(arm), "workspace_available_bytes": shutil.disk_usage(repo).free,
    "preparation": "Staging only. Docker waits for the performance and private-topology clearance.",
    "launcher_sha256": {str(path.relative_to(out)): sha(path) for path in sorted(out.rglob("*")) if path.is_file()},
    "arm_input_script_sha256": {
        str(path.relative_to(arm)): sha(path) for path in sorted([*arm.glob("*.py"), *(arm / "proof").iterdir()])
    },
}
(out / "prepared-inputs.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({"evidence": str(out), "arm": str(arm), "free_disk": record["workspace_available_bytes"]}))
