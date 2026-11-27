"""Reproduce the six signed TinyLlama samples against the exact frozen archive."""
import argparse
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--commit", required=True)
parser.add_argument("--source-id", required=True)
args = parser.parse_args()
COMMIT = args.commit
SOURCE = args.source_id
SERVER = Path("/tmp/entanglement-cpu-server-b6910/bin/llama-server")
MODEL = Path("/tmp/entangle-llama-cpu-model/TinyLlama-1.1B-Chat-v1.0-IQ2_XXS.gguf")
HELPER = Path("/tmp/entangle-peer-fingerprint-relocatable")
HELPER_SHA = "69bfa550e14036e97bdccba4f41b7640b0f8adf7ee6d85952657a4b452f99fe6"
MODEL_SHA = "9ee11adf737960ff06123d5c4fba24d12c5b05ba460a7afa88950fbf2b61add0"
PREVIOUS_COMMIT = "bb70a6193f8879b1feb3e6d3ceb8f2980413ce58"
PREVIOUS_SOURCE = "sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab"

driver = runpy.run_path("/tmp/entangle-successor-release-lan.py")
ROOT = driver["ROOT"]
candidate = driver["Candidate"](argparse.Namespace(commit=COMMIT, source_id=SOURCE,
                                                    evidence=None, archive=None, incident=False))
sha = driver["sha"]
now = driver["now"]
candidate.stamp()
before = candidate.dir.parent / "candidate-bb70a619" / "real-inference"
here = candidate.dir / "real-inference"
here.mkdir(exist_ok=False)
for name in ("MODEL.json", "APACHE-2.0.txt", "model-notice.md", "model-provenance.json",
             "model-tensor-inspection.json", "independent-peer-fingerprint.rs", "verify.py"):
    shutil.copyfile(before / name, here / name)
shutil.copyfile(Path(__file__), here / "replay.py")
with (here / "independent-verify.py").open("x") as stream:
    stream.write((before / "independent-verify.py").read_text()
                 .replace(PREVIOUS_COMMIT, COMMIT).replace(PREVIOUS_SOURCE, SOURCE))

# Work against actual canonical inputs without downloading a new model or server.
assert sha(HELPER) == HELPER_SHA and sha(MODEL) == MODEL_SHA
historical = json.loads((before / "result.json").read_text())
assert sha(SERVER) == historical["server_sha256"]
assert {p.name: sha(p) for p in sorted(SERVER.parent.glob("*.so"))} == historical["server_library_sha256"]


def ready():
    manifest = candidate.ready_archive()
    if not manifest:
        return None
    build = driver["load_if_ready"](candidate.dir / "release-build.json")
    archive = driver["load_if_ready"](candidate.dir / "linux-archive.json")
    if not build or not archive or not (candidate.dir / "auth-live.py").is_file():
        return None
    assert build["exit_code"] == 0 and build["source_id"] == build["source_after"] == SOURCE
    for field in ("source_commit", "source_id", "source_after", "sha256", "files_sha256"):
        assert manifest[field] == archive[field]
    return manifest


manifest = candidate.wait_for(ready)
with tempfile.TemporaryDirectory(prefix="ent-llama-release-extract-", dir="/tmp") as tmp:
    subprocess.run(["tar", "-xzf", candidate.archive, "-C", tmp], check=True)
    bins = Path(tmp) / candidate.archive.name.removesuffix(".tar.gz")
    hashes = {name: sha(bins / name) for name in ("entangle", "entangled")}
    assert all(hashes[name] == manifest["files_sha256"][name] for name in hashes)
    result = here / "result.json"
    command = [sys.executable, "-B", str(here / "verify.py"), "--server", str(SERVER),
               "--model", str(MODEL), "--bin-dir", str(bins), "--output", str(result)]
    code = candidate.command("real-inference-run", command, timeout=330)
    if code:
        sys.exit(code)
    assert hashes == {name: sha(bins / name) for name in hashes}

result = here / "result.json"
command = [sys.executable, "-B", str(here / "independent-verify.py"), str(result),
           "--root", str(ROOT), "--peer-fingerprint", str(HELPER)]
source_before = candidate.stamp()
started = now()
report = here / "independent-verification.json"
errors = here / "independent-verification.stderr.log"
with report.open("xb") as stdout, errors.open("xb") as stderr:
    independent = subprocess.run(command, cwd=ROOT, env=candidate.env, stdout=stdout,
                                 stderr=stderr, timeout=120)
log = report if independent.returncode == 0 else errors
candidate.receipt("real-inference-independent", command, started, source_before, independent.returncode, log)
if independent.returncode:
    sys.exit(independent.returncode)

verification = json.loads(report.read_text())
assert len(verification["samples"]) == 6 and verification["source_after"] == SOURCE
receipt = json.loads((candidate.dir / "real-inference-run.receipt.json").read_text())
receipt.update({"archive_sha256": manifest["sha256"], "binary_sha256": hashes,
                "evidence_root": str(here.relative_to(ROOT)), "result_sha256": sha(result),
                "independent_verification_sha256": sha(report),
                "server_log_sha256": sha(here / "result.server.log"),
                "auth_live_script_sha256": sha(candidate.dir / "auth-live.py"),
                "verified_ed25519_chunks": verification["verified_ed25519_chunks"],
                "verified_direct_completion_tokens": verification["verified_direct_completion_tokens"]})
with (candidate.dir / "real-inference-scorer-receipt.json").open("x") as output:
    json.dump(receipt, output, indent=2)
    output.write("\n")
print(f"Verified {len(verification['samples'])} real-model results and "
      f"{verification['verified_ed25519_chunks']} signed chunks")
