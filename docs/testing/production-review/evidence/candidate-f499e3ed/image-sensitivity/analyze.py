"""Compute pairwise ratios of fresh per-cluster medians without replacing the primary seven-route score."""
import collections
import hashlib
import json
from pathlib import Path
from statistics import median

p=Path(__file__).resolve().parent
r=json.loads((p/"receipt.json").read_text())
samples=json.loads((p/"cpu-samples.json").read_text())
busy=sorted({name for row in samples for name in row["known_build_processes"]})
cohorts=collections.defaultdict(dict);pairs={}
for arm in r["arms"]:
    if not arm.get("verified"):continue
    f=p/"raw"/arm["raw"]
    assert hashlib.sha256(f.read_bytes()).hexdigest()==arm["raw_sha256"]
    data=json.loads(f.read_text()); out={}
    for route in ("local","one_remote"):
        obs=[x for x in data["trials"] if x["route"]==route]
        assert len(obs)==3
        out[route]={m:median(v[m] for v in obs) for m in ("p50_ms","p95_ms","images_s")}
    cohorts[arm["pair"]][arm["stage"]]=out
for i,s in enumerate(r["schedule"],1):
    stages=cohorts.get(i,{})
    if len(stages)!=2:continue
    a,b=("A","B") if s["kind"] in ("AB","BA") else ("X","Y")
    pairs[i]={"order":s["kind"],"half":s["half"],"ratios":{
           name:{k:vv/stages[a][name][k] for k,vv in v.items()} for name,v in stages[b].items()}}
complete=len(pairs)==10 and r["exit_code"]==0
table=["# Counterbalanced local and one-remote image observations","",
       f'The first fixed series completed {sum(len(v) for v in cohorts.values())} of 20 fresh arms and {len(pairs)} of 10 matched pairs in {r["elapsed_s"]:.1f} seconds. '
       "Each completed arm rendered 144 verified PNGs, spread across three batches of 24 inputs on each of two routes. "
       "Four clients ran concurrently. Every completed arm checks the same input hashes and ordered PNG outputs as the primary experiment. [Plan](plan.md) · [All raw trials](raw/)","",
       "| Route | Measure | B/A median [range] | Identical A Y/X median [range] | A-first / B-first medians | Adverse B/A | Criterion |",
       "|---|---|---|---|---|---:|---|"]
results={}
for route in ("local","one_remote"):
    results[route]={}
    for metric in ("p50_ms","p95_ms","images_s"):
        d={order:[p["ratios"][route][metric] for p in pairs.values() if p["order"]==order] for order in ("AB","BA","XY","YX")}
        a=d["AB"]+d["BA"];ctrl=d["XY"]+d["YX"]
        limit=(lambda x:x<.95) if metric=="images_s" else (lambda x:x>1.05)
        flagged=(complete and not busy and len(a)==6 and all(limit(val) for val in a) and len(ctrl)==4
                 and min(ctrl)<=1<=max(ctrl) and .95<=median(ctrl)<=1.05) if metric!="p50_ms" else None
        results[route][metric]={"raw_ratios_by_order":d,"median_ab":median(a) if a else None,
                                "median_control":median(ctrl) if ctrl else None,"adverse_ab":sum(limit(v) for v in a),
                                "prespecified_adverse_signal":flagged}
        if a and ctrl and d["AB"] and d["BA"] and metric!="p50_ms":
            table.append(f'| {route} | {metric} | {median(a):.3f} [{min(a):.3f}–{max(a):.3f}] | '
                         f'{median(ctrl):.3f} [{min(ctrl):.3f}–{max(ctrl):.3f}] | {median(d["AB"]):.3f} / {median(d["BA"]):.3f} | '
                         f'{sum(limit(v) for v in a)}/{len(a)} | '+("Met" if flagged else "Open")+" |")
table+=["","B/A compares f499e3ed with a5728c23. Y/X uses the identical a5728c23 executable in two fresh clusters. Each arm value is the median of three trial p95 or rate values. "
        "Ranges show the individual paired extrema, and adverse counts denote B/A past 1.05 for p95 or below 0.95 for rate. "
        "The preregistration required all six adverse B/A pairs, stable same-daemon controls and an absence of observed competing compilers.",
        "",f'Sampler observations {len(samples)}. Active compiler names were '+(", ".join(busy) if busy else "none")+
        f'. The cgroup gained {(r["cpu_after"]["throttled_usec"]-r["cpu_before"]["throttled_usec"])/1e6:.3f} s throttled time. '
        "The independent seven-route primary grade remains four of seven under the original ratio-of-medians limits. "
        "[Ordered pair data](results.json) · [Source and binary identities](receipt.json)"]
(p/"README.md").write_text("\n".join(table)+"\n")
(p/"results.json").write_text(json.dumps({"all_complete":complete,"pairs":pairs,"route_level":results,"observed_compilers":busy},indent=2)+"\n")
print("\n".join(table[5:10]))
