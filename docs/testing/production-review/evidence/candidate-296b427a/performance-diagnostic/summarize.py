"""Summarize prespecified adjacent whole-cluster paired observations."""
import hashlib,json,statistics
from pathlib import Path
out=Path(__file__).resolve().parent
data=json.loads((out/'results.json').read_text());assert data['exit_code']==0 and data['source_before']==data['source_after']
primary=json.loads((out.parent/'performance.json').read_text())
summ=dict(source_id=data['source_after'],revision=data['revision'],exit_code=0,results_sha256=hashlib.sha256((out/'results.json').read_bytes()).hexdigest(),rows={})
for route in primary['comparisons']:
 row={};summ['rows'][route]=row
 for kind,first,second in [('different_daemons','A','B'),('same_daemon','C','D')]:
  observed=[]
  for p in data['pairs']:
   arms={x['label']:x['metrics'][route] for x in p['arms']}
   if first not in arms:continue
   observed.append({'pair':p['pair'],'order':p['order'],'p95_ratio':arms[second][0]/arms[first][0],'rate_ratio':arms[second][1]/arms[first][1]})
  assert len(observed)==4
  row[kind]={'paired':observed}
  for k in ['p95_ratio','rate_ratio']:
   v=[z[k] for z in observed]
   row[kind][k]={'median':statistics.median(v),'range':[min(v),max(v)],'pairs_above_one':sum(x>1 for x in v),'pairs_outside_limit':sum((x>1.05 if k=='p95_ratio' else x<.95) for x in v),'by_order_medians':{o:statistics.median(z[k] for z in observed if z['order']==o) for o in sorted({z['order'] for z in observed})}}
  row[kind]['median_inside_primary_reference_limits']=row[kind]['p95_ratio']['median']<=1.05 and row[kind]['rate_ratio']['median']>=.95
  row[kind]['individual_pairs_inside_both_limits']=sum(z['p95_ratio']<=1.05 and z['rate_ratio']>=.95 for z in observed)
 row['primary']={k:primary['comparisons'][route][k] for k in ('p95_ratio','throughput_ratio','meets_engineering_limit')}
summ['cgroup_cpu_delta']={k:data['cpu_after'][k]-data['cpu_before'][k] for k in data['cpu_before']}
names={}
for obs in data['cpu_samples']:
 for usage,name,pid in obs['processes_above_0.15_core']:
  rec=names.setdefault(name,[0,0]);rec[0]+=1;rec[1]=max(rec[1],usage)
summ['cpu_samples']=len(data['cpu_samples']);summ['sampled_processes_over_0_15_core']={k:{'process_intervals':v[0],'max_cores':v[1]} for k,v in names.items()}
with (out/'paired-summary.json').open('x') as fp:json.dump(summ,fp,indent=2);print(file=fp)
for route,row in summ['rows'].items():
 print(route,*[(round(row[k]['p95_ratio']['median'],3),round(row[k]['rate_ratio']['median'],3),row[k]['individual_pairs_inside_both_limits']) for k in ('different_daemons','same_daemon')])
print('cpu',summ['cgroup_cpu_delta'],summ['sampled_processes_over_0_15_core'])
