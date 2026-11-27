"""Bind a size_of query to an exact Linux ELF -> Cargo dependency graph -> host metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import sys

p = argparse.ArgumentParser()
p.add_argument("--repo", type=Path, required=True)
p.add_argument("--release-target", type=Path, required=True, help="Cargo's release profile directory")
p.add_argument("--manifest", type=Path, required=True)
p.add_argument("--archive", type=Path, required=True)
p.add_argument("--rustc", required=True)
p.add_argument("--expected-size", type=int, required=True)
p.add_argument("--out", type=Path, required=True)
args = p.parse_args()
repo = args.repo.resolve()
profile = args.release_target.resolve()
manifest = json.loads(args.manifest.read_text())
def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()
def source():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    sid = subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"], cwd=repo, text=True).strip()
    assert head == manifest["source_commit"] and sid == manifest["source_id"] == manifest["source_after"]
    return sid
def dep(parent, name):
    val, = [row[-1] for row in json.loads(parent.read_text())["deps"] if row[1] == name]
    sig = val.to_bytes(8, "little").hex()
    paths = (profile / ".fingerprint").glob(name.replace("_", "-") + "-*/lib-" + name)
    path, = [p for p in paths if p.read_text() == sig]
    return path
before = source()
assert sha(args.archive) == manifest["sha256"]
file = manifest["name"].removesuffix(".tar.gz") + "/entangled"
with tarfile.open(args.archive, "r:gz") as tar:
    member, = [m for m in tar.getmembers() if m.name == file and m.isreg()]
    with tar.extractfile(member) as f:
        elf = hashlib.file_digest(f, "sha256").hexdigest()
assert elf == manifest["files_sha256"]["entangled"]
candidates = [p for p in (profile / "deps").glob("entangled-*") if p.is_file() and not p.suffix and p.stat().st_size == member.size]
found = [p for p in candidates if sha(p) == elf]
assert len(found) == 1, found
exe = found[0]; ident = exe.name.removeprefix("entangled-")
exe_manifest = profile / ".fingerprint" / ("entangle-bin-" + ident) / "bin-entangled.json"
runtime = dep(exe_manifest, "entangle_runtime")
host = dep(runtime.with_suffix(".json"), "entangle_host")
tag = host.parent.name.rsplit("-", 1)[1]
metadata = profile / "deps" / ("libentangle_host-" + tag + ".rmeta")
src = '#[no_mangle] pub extern "C" fn measured_handle() -> usize { std::mem::size_of::<entangle_host::LoadedPlugin>() }\n'
with tempfile.TemporaryDirectory() as td:
    q = Path(td) / "measure.rs"; q.write_text(src)
    ir = Path(td) / "measure.ll"
    cmd = [args.rustc, "--crate-type=lib", "--edition=2021", "-Copt-level=3", "-Ccodegen-units=1", "-Clto=thin", "--emit=llvm-ir", "-L", "dependency=" + str(profile/"deps"), "--extern", "entangle_host=" + str(metadata), str(q), "-o", str(ir)]
    subprocess.run(cmd, check=True)
    match = re.search(r"@measured_handle\(\)[^{]+\{\s*start:\s*ret i64 (\d+)", ir.read_text())
    assert match, ir.read_text()
    size = int(match[1])
record = dict(commit=manifest["source_commit"], source_before=before, source_after=source(), canonical_archive_sha256=manifest["sha256"], archive_daemon_sha256=elf, cargo_daemon_file=exe.name, cargo_executable_fingerprint=sha(exe_manifest), cargo_runtime_marker=runtime.parent.name, cargo_runtime_fingerprint=runtime.read_text(), cargo_host_marker=host.parent.name, cargo_host_fingerprint=host.read_text(), cargo_host_metadata=metadata.name, cargo_host_metadata_sha256=sha(metadata), sizeof_LoadedPlugin=size, expected_size=args.expected_size, probe=src, command=cmd, llvm_constant=match.group(0), rustc=subprocess.check_output([args.rustc, "-vV"], text=True), exit_code=0 if size==args.expected_size else 1)
with args.out.open("x") as f:
    json.dump(record, f, indent=2);print(file=f)
print(size, elf, record['exit_code'])
sys.exit(record['exit_code'])
