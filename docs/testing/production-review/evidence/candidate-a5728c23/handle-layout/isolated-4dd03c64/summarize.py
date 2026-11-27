from pathlib import Path
import hashlib,json,math,random,statistics
d=Path(__file__).resolve().parent
v=json.loads((d/'results.json').read_text());assert v['exit_code']==0 and v['source_before']==v['source_after']
plan=json.loads((d/'preregistration.json').read_text())
def quant(seq,p):
 seq=sorted(seq);x=(len(seq)-1)*p;a=math.floor(x);k=x-a;return seq[a] if k==0 else (1-k)*seq[a]+k*seq[a+1]
def snap(x,kind,metric,route):
 vals=[s['ratio'] for s in x]
 orders={z['order'] for z in x}
 result={'median_ratio':statistics.median(vals),'range':[min(vals),max(vals)],'median_percent':100*(statistics.median(vals)-1),'favorable_count':sum(r<1 if metric=='p95_ms' else r>1 for r in vals),'within_reference_count':sum(r<=1.05 if metric=='p95_ms' else r>=.95 for r in vals),'total_pairs':len(vals),'by_order_medians':{o:statistics.median(z['ratio'] for z in x if z['order']==o) for o in sorted(orders)},'pair_observations':x}
 if kind=='different_daemons':
  rng=random.Random(int(hashlib.sha256((plan['random_seed_sha256']+route+metric).encode()).hexdigest(),16));bootstrap=[statistics.median(rng.choices(vals,k=len(vals))) for _ in range(20000)];result['paired_percentile_interval95']=[quant(bootstrap,.025),quant(bootstrap,.975)]
 return result
routes=list(v['pairs'][0]['arms'][0]['metrics'])
summary={'source_commit':v['revision'],'source_id':v['source_after'],'elfs':v['daemons'],'started_utc':v['start_utc'],'end_utc':v['end_utc'],'results_sha256':hashlib.sha256((d/'results.json').read_bytes()).hexdigest(),'rows':{},'cpu_delta':{k:v['cpu_after'][k]-v['cpu_before'][k] for k in v['cpu_before']},'cpu_sample_count':len(v['cpu_samples'])};procs={}
for s in v['cpu_samples']:
 for use,name,pid in s['processes_above_0.15_core']:
  c=procs.setdefault(name,dict(process_intervals=0,max_cores=0));c['process_intervals']+=1;c['max_cores']=max(c['max_cores'],use)
summary['observed_processes_above_0.15_core']=procs
for route in routes:
 row={'primary':route in plan['primary_routes']};summary['rows'][route]=row
 for kind,first,second in [('different_daemons','A','B'),('same_daemon','X','Y')]:
  row[kind]={}
  for m,metric in enumerate(('p95_ms','throughput')):
   x=[]
   for p in v['pairs']:
    arms={a['label']:a['metrics'][route] for a in p['arms']}
    if first not in arms: continue
    x.append({'pair':p['pair'],'order':p['order'],'numerator':arms[second][m],'denominator':arms[first][m],'ratio':arms[second][m]/arms[first][m]})
   assert len(x)==(8 if kind=='different_daemons' else 4);row[kind][metric]=snap(x,kind,metric,route)
with (d/'paired-summary.json').open('x') as f:json.dump(summary,f,indent=2);print(file=f)
for key,row in summary['rows'].items():
 print(key,'primary' if row['primary'] else 'descriptive',[(k,[(metric,round(v['median_ratio'],3),v['favorable_count'],v['by_order_medians'],v.get('paired_percentile_interval95')) for metric,v in row[k].items()]) for k in ('different_daemons','same_daemon')])
