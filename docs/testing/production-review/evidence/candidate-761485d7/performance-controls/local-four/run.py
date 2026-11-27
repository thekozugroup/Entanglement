"""Collect all preregistered pairs. Use separate temporary destinations for neutral arm labels."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Event, Thread
import time

p = argparse.ArgumentParser()
for name in ("driver", "baseline", "candidate", "output"):
    p.add_argument(name, type=Path)
a = p.parse_args()
evidence = Path(__file__).resolve().parent
root = next(p for p in evidence.parents if (p / "scripts/production_score.py").exists())
def load(p): return json.loads(p.read_bytes())
def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()
def utc(): return datetime.now(timezone.utc).isoformat()
def canonical():
    return subprocess.check_output(["python3","scripts/production_score.py","--source-id"],cwd=root,text=True).strip()
def processes():
    rows = {}
    for p in Path("/proc").glob("[0-9]*/stat"):
        try:
            line = p.read_text()
            comm = line[line.index("(")+1:line.rindex(")")]
            fields = line[line.rindex(")")+1:].split()
            if fields[0] != "Z":
                rows[int(p.parent.name)] = (comm,int(fields[11])+int(fields[12]))
        except (ValueError, OSError):
            pass
    return rows

before = canonical()
bins = {"baseline":a.baseline.resolve(strict=True),"candidate":a.candidate.resolve(strict=True)}
shas = {k:sha(v)for k,v in bins.items()}
archive = evidence.parents[2]
for k,rev in [("baseline","864ae27b"),("candidate","761485d7")]:
    rec = load(archive / ("candidate-"+rev) / "linux-archive.json")
    assert shas[k]==rec["files_sha256"]["entangled"]
    if k=="candidate": assert before==rec["source_id"]
out = a.output.resolve()
out.mkdir(parents=True,exist_ok=True)
if (out/"run.json").exists(): raise SystemExit("provide an empty output directory")
rows = []
observations = []
stop = Event()
def monitor():
    prev = processes()
    while not stop.wait(.75):
        current = processes()
        active = {f"{pid}:{name}":ticks-prev[pid][1] for pid,(name,ticks) in current.items()
                  if pid in prev and ticks-prev[pid][1]>=4}
        observations.append({"utc":utc(),"active_4plus_ticks":active})
        prev = current
t=Thread(target=monitor)
meta={"source_id":before,"started":utc(),"daemon_sha256":shas,"driver_sha256":sha(a.driver),
      "affinity":{"clients":[0,1],"daemons":[2,3]},"cpu_max":Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
      "clock_ticks_hz":os.sysconf("SC_CLK_TCK"),"pairs":16,"warmup_per_arm":1024,"timed_per_arm":4096}
print("started",meta["started"],flush=True)
t.start()
try:
    with tempfile.TemporaryDirectory(prefix="entangle-localfour-") as tmp:
        tmp=Path(tmp)
        wrap=tmp/"daemon"
        wrap.write_text('#!/bin/sh\nexec taskset -c 2,3 "$ENTANGLE_DIAG_ELF" "$@"\n')
        wrap.chmod(0o700)
        for pair in range(1,17):
            order=["baseline","candidate"]if pair%4 in (0,1)else["candidate","baseline"]
            for i,stage in enumerate(order):
                raw=tmp/f"{pair}-{i}.json"
                env={**os.environ,"ENTANGLE_BENCH_DAEMON":str(wrap),"ENTANGLE_DIAG_ELF":str(bins[stage]),
                     "ENTANGLE_LOCAL_FOUR_DATA":str(raw)}
                start=utc()
                cmd=["taskset","-c","0,1",a.driver.resolve(),"benchmark::measure_dispatch","--exact","--ignored","--nocapture"]
                proc=subprocess.run(cmd,env=env,cwd=root,capture_output=True,text=True,timeout=100)
                rec={"pair":pair,"position":i+1,"stage":stage,"start":start,"finish":utc(),
                     "exit":proc.returncode,"stdout":proc.stdout,"stderr":proc.stderr}
                if raw.exists(): rec["measurements"]=load(raw)
                rows.append(rec)
                assert proc.returncode==0 and "1 passed" in proc.stdout,rec
                m=rec["measurements"]
                assert len(m["latency_ns"])==4096 and m["client_affinity"].endswith("0-1") and m["worker_affinity"].endswith("2-3")
            print("finished pair",pair,utc(),flush=True)
finally:
    stop.set()
    t.join()
    meta.update(finished=utc(),source_after=canonical(),host_activity=observations)
    (out/"raw.json.gz").write_bytes(gzip.compress(json.dumps(rows,separators=(",",":")).encode(),mtime=0))
    meta["raw_gzip_sha256"]=sha(out/"raw.json.gz")
    meta["completed_arms"]=len(rows)
    (out/"run.json").write_text(json.dumps(meta,indent=2)+"\n")
assert before==meta["source_after"] and len(rows)==32
