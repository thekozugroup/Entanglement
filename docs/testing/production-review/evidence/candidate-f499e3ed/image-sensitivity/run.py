"""Run the single fixed image series with a separate process group per fresh cluster."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

here=Path(__file__).resolve().parent
root=here.parents[5]
candidate=here.parent
previous=candidate.parent/"candidate-a5728c23"
binroot=Path("/tmp/entangle-link-performance-f499e3ed")
source_id="sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
py=root/"target/catalog-smoke-python/bin/python"
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def source():
    return subprocess.check_output(["python3","scripts/production_score.py","--source-id"],cwd=root,text=True).strip()
def now():return datetime.now(timezone.utc).isoformat()
def cstat():return dict((k,int(v)) for k,v in (row.split() for row in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines()))
def save(path,x):path.write_text(json.dumps(x,indent=2)+"\n")
assert source()==source_id
assert sha(here/"plan.md")=="8eecf2b8e3b03f4dd8b130a92a1d4456a995f239a2fb4b1bb478d6fb28db828a"
assert sha(here/"schedule.json")=="dc096bd728f375b76755f77f9901ff815407a26712bfa80e95787f38eaacfd06"
old=json.loads((previous/"linux-archive.json").read_text())
current=json.loads((candidate/"linux-archive.json").read_text())
reference=json.loads((candidate/"performance.json").read_text())["image"]["candidate"]
stage_dir={k:binroot/("candidate" if k=="B" else "baseline") for k in "ABXY"}
hashes={k:sha(stage_dir[k]/"entangled") for k in stage_dir}
assert all(hashes[k]==(current if k=="B" else old)["files_sha256"]["entangled"] for k in stage_dir)
assert all(sha(p/"entangle")==current["files_sha256"]["entangle"] for p in set(stage_dir.values()))
assert sha(root/"scripts/benchmark_image_batch.py")==json.loads((candidate/"performance.json").read_text())["input_sha256"][str(root/"scripts/benchmark_image_batch.py")]
assert sha(root/"target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm")==reference["wasm_sha256"]
assert sha(Path("/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg"))==reference["source_sha256"]
rows=json.loads((here/"schedule.json").read_text());raw=here/"raw";raw.mkdir(exist_ok=False)
stopped=threading.Event()
# Reuse the first-series monitor's process-statistics sampler, keeping only its definition above the historical script's main program.
namespace={}
monitor_script=candidate/"engineering/monitor.py"
exec(monitor_script.read_text().split("t=Thread(target=monitor)")[0],namespace)
monitor=threading.Thread(target=namespace["monitor"]);monitor.start()
metadata={"source_before":source_id,"candidate_commit":current["source_commit"],"daemons_sha256":hashes,
          "cli_sha256":current["files_sha256"]["entangle"],"cpu_affinity":sorted(os.sched_getaffinity(0)),
          "cpu_budget":Path("/sys/fs/cgroup/cpu.max").read_text().strip(),"cpu_before":cstat(),"started_utc":now(),
          "schedule":rows,"arm_py_sha256":sha(here/"arm.py"),"source_image_driver_sha256":sha(root/"scripts/benchmark_image_batch.py"),
          "original_monitor_sha256":sha(monitor_script),"arms":[]}
clock=time.monotonic()
error=None
try:
    for i,row in enumerate(rows,1):
        for stage in row["order"]:
            if time.monotonic()-clock>=180: raise TimeoutError("fixed cohort elapsed")
            dest=raw/f"{i:02d}-{stage}.json";logs=dest.with_suffix(".log")
            cmd=[str(py),str(here/"arm.py"),"--bin-dir",str(stage_dir[stage]),"--results",str(dest)]
            item={"pair":i,"kind":row["kind"],"stage":stage,"started_utc":now(),"cpu_before":cstat(),"command":cmd}
            metadata["arms"].append(item)
            with logs.open("x") as f:
                child=subprocess.Popen(cmd,cwd=root,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    code=child.wait(timeout=max(.01,180-(time.monotonic()-clock)))
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid,signal.SIGKILL);child.wait()
                    raise TimeoutError("fixed deadline during cluster arm")
                finally:
                    item.update(exit_code=child.returncode,finished_utc=now(),cpu_after=cstat(),log_sha256=sha(logs))
            if code:raise RuntimeError("failed arm "+str(logs))
            out=json.loads(dest.read_text())
            assert out["daemon_sha256"]==hashes[stage]
            assert all(out[k]==reference[k] for k in ("wasm_sha256","source_sha256","input_sha256","png_digest_list_sha256"))
            assert out["images"]==24 and out["concurrency"]==4 and len(out["trials"])==6
            for trial in out["trials"]:
                assert trial["route"] in ("local","one_remote") and len(trial["workers"])==1
                assert sum(trial["workers"].values())==24
            item.update(verified=True,raw=dest.name,raw_sha256=sha(dest))
except BaseException as exc:
    error=repr(exc)
    raise
finally:
    namespace["stopped"].set(); monitor.join()
    save(here/"cpu-samples.json",namespace["rows"])
    metadata.update(finished_utc=now(),elapsed_s=time.monotonic()-clock,cpu_after=cstat(),source_after=source(),
                    error=error,exit_code=0 if error is None and len(metadata["arms"])==20 else 1)
    save(here/"receipt.json",metadata)
    assert metadata["source_after"]==source_id
