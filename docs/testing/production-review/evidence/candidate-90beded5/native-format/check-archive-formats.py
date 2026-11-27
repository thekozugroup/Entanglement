"""Exercise the production archive-layout check against ELF and cross-linked Mach-O files."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", required=True, type=Path)
parser.add_argument("--fixtures", required=True, type=Path)
parser.add_argument("--linux-x86", required=True, type=Path)
parser.add_argument("--linux-arm", required=True, type=Path)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
layout_file = args.repo / "scripts/native_release_layout.py"
spec = importlib.util.spec_from_file_location("native_release_layout", layout_file)
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)
def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
def stamp():
    return subprocess.check_output(["python3","scripts/production_score.py","--source-id"], cwd=args.repo, text=True).strip()
builder = args.repo / "scripts/package-native-release.py"
darwin_x86 = args.fixtures/"x86_64-minimal"
darwin_arm = args.fixtures/"arm64-minimal"
report = {"source_before": stamp(), "started_utc": datetime.now(timezone.utc).isoformat(),
          "method": "Verify signed-byte archive layout and CPU/OS controls independently of signers, using unmodified Linux review archives and small real LLVM-linked Mach-O programs.",
          "scope": "Static file validation on x86-64 Linux. The Darwin inputs return zero from main and were inspected without running on macOS.",
          "layout_sha256":sha(layout_file),"packager_sha256":sha(builder),"darwin_fixture_build":json.loads((args.fixtures/"build.json").read_bytes()),"universal_fixture":json.loads((args.fixtures/"universal.json").read_bytes()),"cases":[]}
def check(name, path, target, valid, expected=""):
    try:
        layout.verify_archive_layout(path,target)
    except ValueError as exc:
        if valid or expected not in str(exc):
            raise
        message=str(exc)
    else:
        if not valid:
            raise AssertionError(f"mismatched archive accepted: {name}")
        message="accepted"
    report["cases"].append({"case":name,"target":target,"archive_sha256":sha(path),"result":message})
with tempfile.TemporaryDirectory(prefix="entangle-layout-matrix-") as tmp:
    work=Path(tmp)
    for path,target in ((args.linux_x86,"x86_64-unknown-linux-gnu"),(args.linux_arm,"aarch64-unknown-linux-gnu")):
        check("actual earlier Linux candidate archive",path,target,True)
    cases=[
        ("Intel macOS native format", "x86_64-apple-darwin",darwin_x86,darwin_x86,True,""),
        ("Apple Silicon macOS native format","aarch64-apple-darwin",darwin_arm,darwin_arm,True,""),
        ("wrong CPU in CLI","x86_64-apple-darwin",darwin_arm,darwin_x86,False,"/entangle'"),
        ("wrong CPU in daemon","aarch64-apple-darwin",darwin_arm,darwin_x86,False,"/entangled'"),
        ("Linux executable in macOS release","x86_64-apple-darwin",Path("/usr/bin/true"),darwin_x86,False,"/entangle'"),
        ("Intel Linux executable in ARM release","aarch64-unknown-linux-gnu",Path("/usr/bin/true"),Path("/usr/bin/true"),False,"/entangle'"),
    ]
    for name in ("universal32","universal64"):
        for target in ("x86_64-apple-darwin","aarch64-apple-darwin"):
            cases.append((f"two-architecture {name} containing {target}", target, args.fixtures/name, args.fixtures/name, True, ""))
    for index,(label,target,cli,daemon,valid,expected) in enumerate(cases):
        directory=work/str(index); directory.mkdir()
        binaries=directory/"bin";binaries.mkdir()
        shutil.copy2(cli,binaries/"entangle");shutil.copy2(daemon,binaries/"entangled")
        argv=["python3",str(builder),"--version","v0.1.0-check","--target",target,"--bin-dir",str(binaries),"--output-dir",str(directory/"assets"),"--source-date-epoch","1"]
        name=subprocess.check_output(argv,text=True).strip()
        check(label,directory/"assets"/name,target,valid,expected)
report["source_after"]=stamp()
assert report["source_before"]==report["source_after"]
report["finished_utc"]=datetime.now(timezone.utc).isoformat()
report["exit_code"]=0
args.out.write_text(json.dumps(report,indent=2)+"\n")
print(f"{len(report['cases'])} archive controls passed, including genuine Mach-O inputs for both targets.")
