"""One fixed, bounded supplemental series. Any setup failure or timeout stops collection."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import threading
import time

here = Path(__file__).resolve().parent
root = Path("/workspace/Entanglement")
bins = Path("/tmp/entangle-link-performance-90beded5")
daemons = {k:bins / stage / "entangled" for k,stage in
           {"A":"baseline", "B":"candidate", "X":"baseline", "Y":"baseline"}.items()}
expected = {"A": "a36e6b819089db3d50f2dd70660b131731960a29ad8184b9cf108576a381403e",
            "B": "0071c6daa1eb6f000f3c0ad8b9ecbc6627d37a6cda0d1680b5bedc165b15238a"}
driver = Path("/tmp/entangle-compact-ordinary-perf/greeting-driver")
src = "sha256:f55d4a44e7f128f7e059ecd7c93625be91e7f56484c49f93b7920e9266cf6cbb"
command = [str(driver), "benchmark::measure_dispatch", "--exact", "--ignored", "--nocapture"]
pattern = re.compile(r"(local|remote) concurrency=(1|4) requests=(\d+) p50_ms=([\d.]+) p95_ms=([\d.]+) requests_per_s=([\d.]+)")
def now():
    return datetime.now(timezone.utc).isoformat()
def sha(p):
    with p.open("rb") as f: return hashlib.file_digest(f, "sha256").hexdigest()
def source():
    return subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"], cwd=root, text=True).strip()
def host():
    stats = dict(row.split() for row in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines())
    psi = Path("/sys/fs/cgroup/cpu.pressure")
    pstat = Path("/proc/stat").read_text().splitlines()[0].split()
    return {"utc":now(), "cpu":{k:int(v) for k,v in stats.items()}, "loadavg":Path("/proc/loadavg").read_text().strip(),
            "cgroup_cpu_pressure":psi.read_text().strip() if psi.exists() else None,
            "host_cpu_stat":pstat[1:], "host_stat_fields":"user nice system idle iowait irq softirq steal guest guest_nice"}
def children():
    c = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"user_seconds":c.ru_utime, "sys_seconds":c.ru_stime,
            "voluntary_context_switches":c.ru_nvcsw, "involuntary_context_switches":c.ru_nivcsw,
            "minor_faults":c.ru_minflt,"major_faults":c.ru_majflt}
def save(p, obj):
    p.write_text(json.dumps(obj,indent=2)+"\n")

source_before = source()
assert source_before == src
assert sha(here / "plan.md") == "70fe30a7413b84a40b74ea36eea9ff535542fa599e412c1f7d5b19364b5f893c"
assert sha(here / "schedule.json") == "dda730af9e8e9ba1c89dab00f7107e643c3e3667c275834e0366d1d54db5b054"
assert sha(driver) == "f8392b8aa540ddaa89b81b01eaefb3c5f7b5eee494ea883e7ceb4497b5ffbea0"
assert sha(daemons["A"]) == expected["A"] and sha(daemons["B"]) == expected["B"]
assert daemons["X"] == daemons["Y"] == daemons["A"]
rows = json.loads((here / "schedule.json").read_text())
raw = here / "raw"
raw.mkdir(exist_ok=False)
schedule = [(i, r, label) for i, r in enumerate(rows,1) for label in r["stages"]]
reason = None
count = 0
metadata = {"source_before":src, "driver":str(driver),"driver_sha256":sha(driver),"command":command,
            "daemons_sha256":expected, "stages":{k:str(v) for k,v in daemons.items()},
            "host_before":host(), "cpu_quota":Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
            "cpu_affinity":sorted(os.sched_getaffinity(0)), "started_utc":now(), "script_sha256":sha(Path(__file__))}
stopped = threading.Event()
def process_snapshot():
    snap = {}
    for p in Path("/proc").glob("[0-9]*/stat"):
        try:
            raw = p.read_text()
            name = raw[raw.index("(")+1:raw.rindex(")")]
            fields = raw[raw.rindex(")")+2:].split()
            if fields[0] != "Z":
                snap[int(p.parent.name)] = (name, int(fields[11])+int(fields[12]))
        except (OSError, ValueError, IndexError): pass
    return snap
def watch():
    previous = process_snapshot()
    ts = time.monotonic()
    with (here/"cpu-samples.jsonl").open("x") as f:
        while not stopped.wait(1):
            current=process_snapshot()
            cur=time.monotonic()
            samples=[(round((ticks-previous.get(pid,(name,ticks))[1])/os.sysconf("SC_CLK_TCK")/(cur-ts),3),pid,name)
                     for pid,(name,ticks) in current.items()]
            print(json.dumps({"utc":now(),"active":[{"cores":load,"pid":pid,"name":name} for load,pid,name in
                sorted(samples,reverse=True)[:12] if load>=.02],"period_s":cur-ts}),file=f,flush=True)
            previous,ts=current,cur
monitor = threading.Thread(target=watch)
monitor.start()
start = time.monotonic()
try:
    with (here / "samples.jsonl").open("x") as fp:
        for i, row, stage in schedule:
            if time.monotonic()-start >= 240: raise TimeoutError("fixed series deadline")
            record = {"pair":i, "block":row["block"], "kind":row["kind"], "stage":stage, "started":host(),
                      "child_usage_before":children(), "route_reports":[], "returncode": None}
            stamp = time.monotonic()
            logfile = raw/f"{i:02d}-{stage}.log"
            record["raw_log"]=logfile.name
            p = subprocess.Popen(command, cwd=root, env={**os.environ,"ENTANGLE_BENCH_DAEMON":str(daemons[stage])},
                                 start_new_session=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            recorded = []
            def readlines():
                with logfile.open("x") as log:
                    for line in p.stdout:
                        log.write(line)
                        found = pattern.fullmatch(line.strip())
                        if found:
                            name, clients, cnt, p50, p95, rate = found.groups()
                            recorded.append({"route":name,"clients":int(clients),"requests":int(cnt),"p50_ms":float(p50),
                                             "p95_ms":float(p95),"rate":float(rate),"reported_utc":now(),
                                             "host_at_report":host()})
            reader = threading.Thread(target=readlines)
            reader.start()
            try:
                try:
                    p.wait(timeout=max(.01, 240-(time.monotonic()-start)))
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL)
                    p.wait()
                    raise TimeoutError("fixed series deadline with active driver")
            finally:
                reader.join()
                record.update(returncode=p.returncode,finished=host(),wall_s=time.monotonic()-stamp,
                              child_usage_after=children(),route_reports=recorded,raw_log_sha256=sha(logfile))
                print(json.dumps(record),file=fp,flush=True)
            verified=[(r["route"],r["clients"],r["requests"]) for r in recorded]
            assert p.returncode==0 and verified == [(name,c,1024) for name in ("local","remote") for c in (1,4)]
            assert "test result: ok. 1 passed; 0 failed" in logfile.read_text()
            count+=1
except BaseException as error:
    reason = repr(error)
    raise
finally:
    stopped.set()
    monitor.join()
    metadata.update(finished_utc=now(),timed_elapsed_s=time.monotonic()-start,host_after=host(),arms_complete=count,
                    exit_code=0 if count==36 and reason is None else 1,error=reason,source_after=source())
    assert metadata["source_after"] == src
    save(here/"receipt.json",metadata)
