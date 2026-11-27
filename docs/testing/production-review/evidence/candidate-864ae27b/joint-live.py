"""Coordinate two released executable checks after explicit source and build provenance match."""
import argparse
import datetime
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

p=argparse.ArgumentParser()
for arg in ["root","bins","evidence","fixture","fish-tree"]:
    p.add_argument("--"+arg, type=Path, required=True)
p.add_argument("--commit",required=True)
p.add_argument("--source",required=True)
a=p.parse_args()
out=a.evidence.resolve()
bins=a.bins.resolve()
release=json.loads((out/"release-build.json").read_text())
assert int(release["exit_code"])==0 and release.get("source_id",release.get("source_before"))==a.source and release["source_after"]==a.source
def hashfile(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()
def ts():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def state():
    get=lambda *cmd: subprocess.check_output(cmd,cwd=a.root,text=True).strip()
    return dict(commit=get("git","rev-parse","HEAD"),source=get("python3","scripts/production_score.py","--source-id"),
                cli=hashfile(bins/"entangle"), daemon=hashfile(bins/"entangled"))
before=state()
assert before["source"]==a.source and before["commit"]==a.commit
release_stamp=out/"linux-archive.json"
if release_stamp.is_file():
    binaries=json.loads(release_stamp.read_text())["files_sha256"]
    assert before["cli"]==binaries["entangle"] and before["daemon"]==binaries["entangled"]
observations=[]
start=ts()
for key,options in [
    ("auth-live",["--bin-dir",bins]),
    ("wrapper-live",["--cli",bins/"entangle","--fixture",a.fixture.resolve(),"--fish-tree",a.fish_tree.resolve()]),
]:
    result=out/(key+"-linux.json")
    log=out/(key+"-linux.log")
    if result.exists() or log.exists():
        raise RuntimeError(f"existing output for {key}, inspect before rerunning")
    cmd=[sys.executable,"-B",str(out/(key+".py")),*map(str,options),"--out",str(result)]
    began=ts()
    clock=time.monotonic()
    with log.open("x") as f:
        run=subprocess.run(cmd,cwd=a.root,stdout=f,stderr=subprocess.STDOUT,timeout=240)
    row=dict(name=key,command=cmd,started_utc=began,finished_utc=ts(),duration_seconds=round(time.monotonic()-clock,3),
             exit_code=run.returncode,log_sha256=hashfile(log),driver_sha256=hashfile(out/(key+".py")))
    if result.exists():
        row["result_sha256"]=hashfile(result)
    observations.append(row)
    print(json.dumps(row),flush=True)
after=state()
receipt={"started_utc":start,"finished_utc":ts(),"before":before,"after":after,
         "release_build_receipt_sha256":hashfile(out/"release-build.json"),"behavioral_runs":observations,
         "fixture_sha256":hashfile(a.fixture/"hello-world-0.1.0.tar.zst")}
(out/"joint-live-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
if before!=after or any(v["exit_code"]!=0 for v in observations):
    raise SystemExit("failed behavioral check or changed candidate")
