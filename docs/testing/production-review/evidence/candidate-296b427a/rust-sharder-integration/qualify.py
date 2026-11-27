#!/usr/bin/env python3
"""Run one source-bound phase against two explicitly checked executable members."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

def sha(path):
    with path.open("rb") as current:
        return hashlib.file_digest(current, "sha256").hexdigest()

p = argparse.ArgumentParser()
p.add_argument("phase", choices=("identity", "perf"))
p.add_argument("--repo", type=Path, required=True)
p.add_argument("--revision", required=True)
p.add_argument("--source", required=True)
p.add_argument("--fixture-dir", type=Path, required=True)
p.add_argument("--out", type=Path, required=True)
p.add_argument("--old-bin-dir", type=Path)
a = p.parse_args()
repo = a.repo.resolve()
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip() == a.revision
evidence = repo / "docs/testing/production-review/evidence" / ("candidate-" + a.revision[:8])
manifest = evidence / "linux-archive.json"
m = json.loads(manifest.read_text())
assert (m["source_commit"], m["source_id"], m["source_after"]) == (a.revision, a.source, a.source)
archive = repo / "target/release-candidate" / a.revision[:12] / m["name"]
assert sha(archive) == m["sha256"]
assert not a.out.exists()
a.out.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir="/tmp", prefix="entangle-pinned-suite-") as d, tarfile.open(archive, "r:gz") as tar:
    for member in ["entangle", "entangled"]:
        name = m["name"].removesuffix(".tar.gz") + "/" + member
        matched = [item for item in tar.getmembers() if item.name == name]
        assert len(matched) == 1 and matched[0].isfile()
        dest = Path(d) / member
        with dest.open("xb") as sink, tar.extractfile(matched[0]) as src:
            shutil.copyfileobj(src, sink)
        assert sha(dest) == m["files_sha256"][member]
        dest.chmod(0o700)
    cmd = [sys.executable, "-B", str(Path(__file__).parent / (a.phase + ".py")), "--repo", repo, "--reference", manifest, "--bin-dir", d, "--fixture-dir", a.fixture_dir.resolve(), "--out", a.out.resolve()]
    if a.phase == "identity":
        assert a.old_bin_dir is not None
        cmd += ["--old-bin-dir", a.old_bin_dir.resolve()]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    sys.exit(subprocess.run(cmd, env=env, cwd=repo).returncode)
