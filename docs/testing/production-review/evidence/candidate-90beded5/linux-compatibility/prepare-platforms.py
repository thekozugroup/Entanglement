#!/usr/bin/env python3
"""Stage previously exercised platform qualifications for a pinned source candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--commit", required=True)
parser.add_argument("--source-id", required=True)
options = parser.parse_args()
repo = Path("/workspace/Entanglement")
evidence = repo / "docs/testing/production-review/evidence"
reference = evidence / "candidate-a5728c23/linux-compatibility"
candidate = evidence / f"candidate-{options.commit[:8]}/linux-compatibility"
portable_reuse = Path("/tmp/entangle-successor-platforms")
work = Path("/workspace") / f"entangle-emulated-arm-{options.commit[:8]}"
proof = work / "proof"
canonical = repo / "target/release-candidate" / options.commit[:12]

def get(*command):
    return subprocess.check_output(command, cwd=repo, text=True).strip()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

assert get("git", "rev-parse", "HEAD") == options.commit
assert get("python3", "scripts/production_score.py", "--source-id") == options.source_id
assert not get("git", "diff", "a5728c23", options.commit, "--", "Cargo.lock", "rust-toolchain.toml")
assert get("git", "rev-parse", options.commit + ":plugins/json-pointer") == "14a946aac15de3b9952eebe0bba5c82e47565b6a"
assert shutil.disk_usage(repo).free >= 1800 * 1024**2

candidate.mkdir(parents=True, exist_ok=True)
jammy = candidate / "jammy-build"
jammy.mkdir()
for filename in (
    "build-jammy.sh", "check-jammy.py", "probe-jammy-tmpfs.py", "stage-jammy.py",
    "stage-jammy-archive-tools.py", "portable-jammy.py",
):
    shutil.copyfile(portable_reuse / filename, jammy / filename)
portable = jammy / "portable-jammy.py"
text = portable.read_text().replace('parser.add_argument("--" + name, required=True)\nargs', 'parser.add_argument("--" + name, required=True)\nparser.add_argument("--package-fixture", action="store_true")\nargs')
text = text.replace('if measure()["builder_tmpfs_free_bytes"] >= GIB // 2:', 'if args.package_fixture and measure()["builder_tmpfs_free_bytes"] >= GIB // 2:')
assert 'parser.add_argument("--package-fixture"' in text
portable.write_text(text)
shutil.copyfile(portable_reuse/"userspaces.py", candidate/"userspaces.py")
shutil.copyfile(Path(__file__), candidate/"prepare-platforms.py")

work.mkdir(mode=0o755)
work.chmod(0o755)
proof.mkdir()
prior_arm = reference / "current-arm64"
def adapt(path, destination, changes=()):
    source = path.read_text()
    for old, new in (
        ("a5728c230e5049556b806cae8597fe823dd67987", options.commit),
        ("sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5", options.source_id),
        ("a5728c230e50", options.commit[:12]),
        ("a5728c23", options.commit[:8]),
        ("entangle-arm64-a572-isolated", f"entangle-arm64-{options.commit[:8]}-isolated"),
        *changes,
    ):
        source = source.replace(old, new)
    if destination.suffix == ".py":
        compile(source, str(destination), "exec")
    destination.write_text(source)

adapt(prior_arm/"provision.py", work/"provision.py",
      (("'--cpus','3','--memory','12g'", "'--cpus','2','--memory','12g'"),))
adapt(prior_arm/"finish.py", work/"finish.py")
for filename in ("package-arm.py", "signed-workload.py", "standalone-local.py", "provision-tools.sh"):
    adapt(prior_arm / filename, proof / filename)
adapt(prior_arm / "cross-build.sh", proof/"cross-build.sh", (("CARGO_BUILD_JOBS=3", "CARGO_BUILD_JOBS=2"),))
adapt(prior_arm / "arm-build-driver.py", proof/"arm-build-driver.py", (
    ("'3000000000 12884901888'", "'2000000000 12884901888'"),
    ("subprocess.run(['docker','cp',c+':'+path,str(out/n)],check=True)",
     "with (out/n).open('xb') as stream:\n        subprocess.run(['docker','exec',c,'/bin/cat',path],stdout=stream,check=True,timeout=120)"),
    ("assert f.read_bytes()[:4]==b'\\x7fELF'", "with f.open('rb') as stream: assert stream.read(4)==b'\\x7fELF'"),
))
arm = proof/"arm-build-driver.py"
text = arm.read_text()
assert "'docker','cp'" not in text and "'/bin/cat',path" in text

record = {
    "source_commit": options.commit, "source_id": options.source_id,
    "launch_waits_for_quiet_window_clearance": True,
    "native_canonical_archive_directory": str(canonical),
    "portable_evidence_directory": str(jammy), "arm_workspace": str(work),
    "portable_script_sha256": {p.name: sha(p) for p in sorted(jammy.iterdir())},
    "arm_script_sha256": {p.name: sha(p) for p in sorted([*work.glob("*.py"), *proof.iterdir()])},
    "unchanged_inputs": {"lockfile": sha(repo/"Cargo.lock"), "toolchain_manifest": sha(repo/"rust-toolchain.toml")},
    "free_host_disk_bytes": shutil.disk_usage(repo).free,
}
(candidate / "prepared-inputs.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({"portable": str(jammy), "arm": str(work), "disk": record["free_host_disk_bytes"]}))
