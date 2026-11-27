"""Use all six registered blocks, preserving A/B order and same-A controls."""
import collections
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
from statistics import median

here = Path(__file__).resolve().parent
receipt=json.loads((here/'receipt.json').read_text())
rows=[json.loads(line) for line in (here/'samples.jsonl').read_text().splitlines()]
assert receipt['arms_complete']==len(rows)==36 and receipt['exit_code']==0
assert all(row['returncode']==0 for row in rows)
schedule=json.loads((here/'schedule.json').read_text())
assert [(i, stage) for i,p in enumerate(schedule,1) for stage in p['stages']]==[(r['pair'],r['stage']) for r in rows]
pairs=collections.defaultdict(dict)
for row in rows:
    path=here/'raw'/row['raw_log']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==row['raw_log_sha256']
    pairs[row['pair']][row['stage']]=row
rng=random.Random(0x90BED)
resamples=collections.Counter(tuple(sorted(rng.randrange(6) for _ in range(6))) for _ in range(20000))
def bounds(per_block):
    counts=collections.Counter()
    for indices,freq in resamples.items():
        counts[median(list(itertools.chain.from_iterable(per_block[i] for i in indices)))]+=freq
    result=[]
    for cut in (math.ceil(.025*20000),math.ceil(.975*20000)):
        total=0
        for value,freq in sorted(counts.items()):
            total+=freq
            if total>=cut:
                result.append(value)
                break
    return result
def fmt_ci(v):return f'{v[0]:.3f}–{v[1]:.3f}'

summary={}
article=['# Supplemental signed greeting replication','',
         'Six scheduled blocks completed in '+f'{receipt["timed_elapsed_s"]:.1f} seconds. Each block contained one A-first pair, one B-first pair and one pair of identical A daemons. '
         'A is the previous a5728c23 release, and B is the 90beded5 release. Each route has 12 B/A and six identical-daemon Y/X comparisons. '
         'All 147,456 measured replies passed the driver’s peer and output checks. Configuration order and warmup match the primary series. '
         'The 95% intervals use 20,000 resamples of the six matched blocks. The primary seven-route grade remains 1/7. '
         '[Registered plan](plan.md) · [All arm measurements](samples.jsonl) · [Observed CPU](cpu-samples.jsonl)','',
         '| Route | Metric | B/A median [95% interval] | Y/X control [95% interval] | A-first / B-first | Slower candidate pairs | Diagnostic criterion |',
         '|---|---|---|---|---|---:|---|']
for index,(route,cc) in enumerate(itertools.product(('local','remote'),(1,4))):
    key=f'{route} / {cc}'
    summary[key]={}
    for metric in ('p95_ms','rate','p50_ms'):
        data={'AB':[[] for _ in range(6)],'AA':[[] for _ in range(6)]}
        orders={'AB':[], 'BA':[]}
        observations=[]
        for i,s in enumerate(schedule,1):
            control=s['kind']=='AA'
            a,b=('X','Y') if control else ('A','B')
            aa=pairs[i][a]['route_reports'][index]
            bb=pairs[i][b]['route_reports'][index]
            assert aa['route']==bb['route']==route and aa['clients']==bb['clients']==cc
            ratio=bb[metric]/aa[metric]
            data['AA' if control else 'AB'][s['block']-1].append(ratio)
            if not control:orders[s['kind']].append(ratio)
            observations.append({'pair':i,'block':s['block'],'order':s['kind'],'ratio':ratio})
        results={}
        for group,blocks in data.items():
            vs=list(itertools.chain.from_iterable(blocks))
            results[group]={'count':len(vs),'median':median(vs),'interval_95':bounds(blocks),'above_one':sum(v>1 for v in vs),
                            'below_one':sum(v<1 for v in vs),'ties':sum(v==1 for v in vs)}
        order_medians={k:median(v) for k,v in orders.items()}
        aa,ab=results['AA'],results['AB']
        ma,mb=order_medians.values()
        ctrl_ok=aa['interval_95'][0]<=1<=aa['interval_95'][1] and .95<=aa['median']<=1.05
        slower=ab['below_one'] if metric=='rate' else ab['above_one']
        trip=(ctrl_ok and (ab['interval_95'][0]>1.05 and ma>1 and mb>1 if metric=='p95_ms'
                           else ab['interval_95'][1]<.95 and ma<1 and mb<1)) if metric!='p50_ms' else None
        summary[key][metric]=dict(**results,order_medians=order_medians,raw_pairs=observations,
                                   control_ok=ctrl_ok,criterion=trip)
        if metric!='p50_ms':
            article.append(f'| {key} | {metric} | {ab["median"]:.3f} [{fmt_ci(ab["interval_95"])}] | '
                           f'{aa["median"]:.3f} [{fmt_ci(aa["interval_95"])}] | {ma:.3f} / {mb:.3f} | {slower}/12 | '
                           +('Met' if trip else 'Open')+' |')
usage=[]
for row in rows:
    x,y=row['child_usage_before'],row['child_usage_after']
    p,q=row['started']['cpu'],row['finished']['cpu']
    cpu=x['user_seconds']+x['sys_seconds']
    usage.append({'block':row['block'],'pair':row['pair'],'kind':row['kind'],'stage':row['stage'],'arm_elapsed_s':row['wall_s'],
                  'child_cpu_s':y['user_seconds']+y['sys_seconds']-cpu,'throttled_usec_delta':q['throttled_usec']-p['throttled_usec'],
                  'periods_delta':q['nr_periods']-p['nr_periods'],'throttled_periods_delta':q['nr_throttled']-p['nr_throttled'],
                  'child_involuntary_switches':y['involuntary_context_switches']-x['involuntary_context_switches']})
mon=[json.loads(x) for x in (here/'cpu-samples.jsonl').read_text().splitlines()]
building={'cargo','rustc','gcc','ld.lld','ninja','make'}
known=sorted({p['name'] for s in mon for p in s['active'] if p['name'] in building})
aggregate={'routes':summary,'arm_resources':usage,'samples_per_arm':4096,'arms':len(rows),'sources':receipt,
           'active_compilers_in_monitor':known,'bootstrap_seed':0x90BED,'bootstrap_repetitions':20000,
           'quantile_method':'nearest rank across all 20,000 sampled block medians'}
(here/'results.json').write_text(json.dumps(aggregate,indent=2)+'\n')
throttle=sum(r['throttled_usec_delta'] for r in usage)
article+=['','Values above 1 indicate a higher candidate latency or throughput, as labeled. The control uses the same executable in both positions. '
          'For a metric to meet the diagnostic criterion, its B/A interval had to lie wholly beyond the engineering bound, the two build-order medians had to show the adverse direction, '
          'and the A/A interval had to include 1 with its median within 5% of parity. With six blocks these intervals are sensitivity estimates.',
          '',f'The CPU monitor collected {len(mon)} samples. Active compilers observed were '+(', '.join(known) if known else 'none')+
          f'. The total cgroup throttled duration across measured arms increased by {throttle/1e6:.3f} s. Kernel CPU pressure stall information '
          +('was available' if receipt['host_before']['cgroup_cpu_pressure'] is not None else 'was unavailable')+
          ' in this VM. The raw samples retain arm and route boundaries, child CPU time, context switches and additional cgroup counters. '
          '[Full analysis](results.json) · [Primary chronology and binary layout](primary-analysis.md)']
(here/'README.md').write_text('\n'.join(article)+'\n')
print('\n'.join(article[4:14]))
