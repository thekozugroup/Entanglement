"""Recalculate nearest-rank arm p95, median within-pair ratios and pair-bootstrap intervals."""
from collections import Counter
import gzip
import hashlib
import json
from math import ceil
from pathlib import Path
import random
from statistics import median, quantiles
import sys

d = Path(sys.argv[1])
meta = json.loads((d/"run.json").read_bytes())
raw = (d/"raw.json.gz").read_bytes()
assert hashlib.sha256(raw).hexdigest()==meta["raw_gzip_sha256"]
rows = json.loads(gzip.decompress(raw))
assert len(rows)==32
by_pair={}
def ticks(s):
    f=s[s.rindex(")")+1:].split()
    return int(f[11])+int(f[12])
def stat(s): return {a:int(b)for a,b in (x.split()for x in s.splitlines())}
for row in rows:
    assert row["exit"]==0
    m=row["measurements"];lat=sorted(m["latency_ns"])
    assert len(lat)==4096 and all(x>0 for x in lat)
    before,after=m["before_client_worker_cgroup"],m["after_client_worker_cgroup"]
    prev,now=stat(before[2]),stat(after[2])
    arm={"position":row["position"],"p50_ms":lat[ceil(len(lat)*.50)-1]/1e6,"p95_ms":lat[ceil(len(lat)*.95)-1]/1e6,
         "p99_ms":lat[ceil(len(lat)*.99)-1]/1e6,"max_ms":lat[-1]/1e6,"wall_ms":m["wall_ns"]/1e6,
         "throughput":len(lat)*1e9/m["wall_ns"],"client_ticks":ticks(after[0])-ticks(before[0]),
         "worker_ticks":ticks(after[1])-ticks(before[1]),
         "cgroup_deltas":{k:now[k]-v for k,v in prev.items()}}
    by_pair.setdefault(row["pair"],{})[row["stage"]]=arm
assert len(by_pair)==16 and all(set(p)=={"candidate","baseline"} for p in by_pair.values())
metrics=("p95_ms","throughput")
for p in by_pair.values():
    p["ratios"]={m:p["candidate"][m]/p["baseline"][m]for m in metrics}
rng=random.Random(761485)
pairs=list(by_pair.values())
draws={m:[]for m in metrics}
for _ in range(50_000):
    drawn=rng.choices(pairs,k=len(pairs))
    for m in metrics:
        draws[m].append(median(p["ratios"][m]for p in drawn))
stats={}
for m in metrics:
    cuts=quantiles(draws[m],n=40,method="inclusive")
    stats[m]={"paired_ratio_median":median(p["ratios"][m]for p in pairs),"interval95":[cuts[0],cuts[-1]],
              "pairs_ratio_above_1":sum(p["ratios"][m]>1 for p in pairs),
              "median_daemon_by_stage":{s:median(p[s][m]for p in pairs)for s in ["baseline","candidate"]},
              "median_ratio_by_baseline_position":{str(i):median(p["ratios"][m]for p in pairs if p["baseline"]["position"]==i)for i in (1,2)}}
summary={s:{"throttled_periods":sum(p[s]["cgroup_deltas"]["nr_throttled"]for p in pairs),
            "throttled_usec":sum(p[s]["cgroup_deltas"]["throttled_usec"]for p in pairs),
            "elapsed_cgroup_periods":sum(p[s]["cgroup_deltas"]["nr_periods"]for p in pairs),
            "median_worker_ticks":median(p[s]["worker_ticks"]for p in pairs),
            "median_client_ticks":median(p[s]["client_ticks"]for p in pairs),
            "min_p95_ms":min(p[s]["p95_ms"]for p in pairs),"max_p95_ms":max(p[s]["p95_ms"]for p in pairs)}
         for s in ["baseline","candidate"]}
active=Counter()
for sample in meta['host_activity']:
    for k,n in sample['active_4plus_ticks'].items(): active[k.split(':',1)[1]]+=n
result={"validated_timed_calls":len(rows)*4096,"bootstrap":{"replications":50000,"seed":761485,"unit":"matched pairs","method":"percentile, interpolated inclusive 2.5th and 97.5th percentiles"},
        "source_id":meta["source_id"],"stats":stats,"arm_summary":summary,"host_observed_ticks_by_process_name":dict(active),"pairs":by_pair}
(d/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({k:v for k,v in result.items()if k!="pairs"},indent=2))
