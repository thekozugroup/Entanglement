"""Summarize complete A/B and same-daemon control pairs; keep raw observations."""
from pathlib import Path
import json
import math
import random
from statistics import median

E=Path(__file__).resolve().parent
read=lambda p:json.loads((E/p).read_bytes())
rows=[json.loads(line)for line in (E/'samples.jsonl').read_text().splitlines()]
rc=read('receipt.json')
assert rc['status']=='complete' and len(rows)==rc['rows']==64
def quantile_sorted(xs,p):
    x=p*(len(xs)-1);i=int(x);j=min(i+1,len(xs)-1)
    return xs[i]+(xs[j]-xs[i])*(x-i)
def interval(xs):
    ys=sorted(xs)
    return [quantile_sorted(ys,.025),quantile_sorted(ys,.975)]
rng=random.Random(572428)
samples=[[rng.randrange(8)for _ in range(8)]for _ in range(10_000)]
summary={}
details=[]
for width in (1,4):
    data={r['block']:{}for r in rows}
    rws=[r for r in rows if r['width']==width]
    for row in rws:data[row['block']][row['label']]=row
    assert all(set(d)==set('ABXY')for d in data.values())
    answer={}
    for metric in ('p50_ms','p95_ms','rate'):
        mixed=[d['B'][metric]/d['A'][metric]for d in data.values()]
        ctrl=[d['Y'][metric]/d['X'][metric]for d in data.values()]
        bm=[median(mixed[i]for i in inds)for inds in samples]
        bc=[median(ctrl[i]for i in inds)for inds in samples]
        answer[metric]={'mixed_pairs':mixed,'same_a572_pairs':ctrl,'mixed_median':median(mixed),
            'same_median':median(ctrl),'mixed_ci95':interval(bm),'same_ci95':interval(bc),
            'adjusted_median_ratio':median(mixed)/median(ctrl),'adjusted_ci95':interval([a/b for a,b in zip(bm,bc)]),
            'raw_medians_by_label':{k:median(d[k][metric]for d in data.values())for k in 'ABXY'}}
    answer['persistent_adverse_diagnostic_signal']=answer['p95_ms']['mixed_ci95'][0]>1.05 and answer['p95_ms']['adjusted_ci95'][0]>1
    summary[width]=answer
monitor=read('cpu-samples.json')
active={}
for row in monitor:
    for k,val in row['active_4_ticks_per_second'].items():active[k]=active.get(k,0)+val
out={'source':rc['source_before'],'condition':summary,'elapsed_s':rc['elapsed_s'],'verified_timed_calls':sum(r['count']for r in rows),
     'verified_warmup_calls':128*len(rows),'throttle':{k:rc['cpu_stat_after'][k]-rc['cpu_stat_before'][k]for k in ['nr_throttled','throttled_usec']},
     'highest_observed_cpu_ticks':dict(sorted(active.items(),key=lambda x:x[1],reverse=True)[:15])}
(E/'summary.json').write_text(json.dumps(out,indent=2)+'\n')
for width,results in summary.items():
 print(width, {m:(round(x['mixed_median'],4),[round(v,4)for v in x['mixed_ci95']], round(x['same_median'],4),[round(v,4)for v in x['adjusted_ci95']])for m,x in results.items()if isinstance(x,dict)}, results['persistent_adverse_diagnostic_signal'])
