import hashlib,json,os,re,shutil,statistics,subprocess,sys,threading,time
from pathlib import Path
root=Path('/workspace/Entanglement'); base=Path('/tmp') / ('entangle-link-performance-'+sys.argv[2][:8])
base.mkdir(exist_ok=False)
head=sys.argv[2]; source_id=sys.argv[3]
before=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
assert before==source_id
receipts=root/'docs/testing/production-review/evidence'
previous=json.loads((receipts/'candidate-a5728c23/linux-archive.json').read_text())
current=json.loads((receipts/('candidate-'+head[:8])/'linux-archive.json').read_text())
assert current['source_commit']==head and current['source_id']==source_id
if subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()!=head: raise SystemExit('unexpected candidate revision')
driver=Path(sys.argv[1]).resolve(strict=True)
# Archive measured images and use the same final CLI for out-of-timer setup.
bins={}
for stage,daemon in [('baseline',Path('/tmp/entangle-check-a5728c23-archive/entangled')),('candidate',root/'target/release/entangled')]:
 d=base/stage;d.mkdir(exist_ok=True);shutil.copy2(daemon,d/'entangled');shutil.copy2(root/'target/release/entangle',d/'entangle');bins[stage]=d
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
for stage,rec in [('baseline',previous),('candidate',current)]:
 assert sha(bins[stage]/'entangled')==rec['files_sha256']['entangled']
assert sha(bins['candidate']/'entangle')==current['files_sha256']['entangle']
assert sha(driver)=='f8392b8aa540ddaa89b81b01eaefb3c5f7b5eee494ea883e7ceb4497b5ffbea0'
assert previous['source_commit']=='a5728c230e5049556b806cae8597fe823dd67987'
image_input=Path('/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg')
component=root/'target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm'
old_results=json.loads((receipts/'candidate-a5728c23/performance.json').read_text())
assert sha(image_input)==old_results['image']['candidate']['source_sha256']
assert sha(component)==old_results['image']['candidate']['wasm_sha256']
assert subprocess.check_output(['git','diff',previous['source_commit'],head,'--','scripts/benchmark_image_batch.py','crates/entangle-bin/tests/daemon_compute.rs'],cwd=root)==b''
def cpu_status():
 return {'affinity':sorted(os.sched_getaffinity(0)), 'cpu_max':Path('/sys/fs/cgroup/cpu.max').read_text().strip(), 'cpu_stat':Path('/sys/fs/cgroup/cpu.stat').read_text().strip(),'memory_max':Path('/sys/fs/cgroup/memory.max').read_text().strip(),'loadavg':Path('/proc/loadavg').read_text().strip()}
host_before=cpu_status()
scope={};exec(Path(__file__).with_name('monitor.py').read_text().split('t=Thread(target=monitor)')[0],scope)
m=threading.Thread(target=scope['monitor']);m.start();jobs=[];images={}
start=time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime())
try:
 for i in (1,2,3):
  for stage in (('baseline','candidate') if i%2 else ('candidate','baseline')):
   env={**os.environ,'ENTANGLE_BENCH_DAEMON':str(bins[stage]/'entangled')}
   print(time.strftime('%H:%M:%S',time.gmtime()),i,stage,'signed greeting',flush=True)
   log=base/f'hello-{i}-{stage}.log'
   with log.open('w') as fp:
    subprocess.run([driver,'benchmark::measure_dispatch','--exact','--ignored','--nocapture'],cwd=root,env=env,stdout=fp,stderr=subprocess.STDOUT,check=True)
   lines=log.read_text().splitlines();configs=[]
   for l in lines:
    if mat:=re.fullmatch(r'(local|remote) concurrency=(\d+) requests=(\d+) p50_ms=([\d.]+) p95_ms=([\d.]+) requests_per_s=([\d.]+)',l):
     route,count,number,p50,p95,rate=mat.groups()
     configs.append(dict(route=route,concurrency=int(count),requests=int(number),p50_ms=float(p50),p95_ms=float(p95),requests_per_s=float(rate)))
   if len(configs)!=4 or sum(r['requests']for r in configs)!=4096:raise ValueError(lines)
   jobs.append(dict(stage=stage,pair=i,configurations=configs,cold=re.search(r'first package_load_ms=[^\n]+','\n'.join(lines)).group(0),test=next(l for l in lines if l.startswith('test result: '))))
 for stage in ('candidate','baseline'):
  print(time.strftime('%H:%M:%S',time.gmtime()),stage,'image batches',flush=True)
  path=base/f'image-{stage}.json'
  with (base/f'image-{stage}.log').open('w') as fp:
   code=subprocess.call(['target/catalog-smoke-python/bin/python','scripts/benchmark_image_batch.py','--bin-dir',str(bins[stage]),'--wasm','target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm','--image','/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg','--results',str(path)],cwd=root,stdout=fp,stderr=subprocess.STDOUT)
  if code not in (0,2):raise ValueError('image gate correctness failure')
  images[stage]=json.loads(path.read_text())
 assert images['candidate']['png_digest_list_sha256']==images['baseline']['png_digest_list_sha256']
finally:
 scope['stopped'].set();m.join()
stats={}
for route in ('local','remote'):
 for c in (1,4):
  key=f'{route} / {c}';stats[key]={}
  for stage in bins:
   rows=[r for j in jobs if j['stage']==stage for r in j['configurations'] if r['route']==route and r['concurrency']==c]
   stats[key][stage]={k:statistics.median(r[k] for r in rows) for k in ('p50_ms','p95_ms','requests_per_s')}
for route in ('local','one_remote','three_remote'):
 key='image '+route;stats[key]={}
 for stage in bins:
  rows=[r for r in images[stage]['trials'] if r['route']==route]
  stats[key][stage]={k:statistics.median(r[k] for r in rows) for k in ('p50_ms','p95_ms','images_s')}
for key,cmp in stats.items():
 a,b=cmp['baseline'],cmp['candidate'];speed='images_s' if 'images_s'in a else 'requests_per_s'
 cmp['p95_ratio']=b['p95_ms']/a['p95_ms'];cmp['throughput_ratio']=b[speed]/a[speed];cmp['meets_engineering_limit']=cmp['p95_ratio']<=1.05 and cmp['throughput_ratio']>=0.95
print(json.dumps(stats,indent=2))
out=root/'docs/testing/production-review/evidence'/('candidate-'+head[:8]);out.mkdir(parents=True,exist_ok=True)
r={'candidate_commit':head,'source_id':source_id,'baseline_commit':previous['source_commit'],'host':{'os':'Debian 13, Linux 6.18.57 x86_64','cpu':'Intel Xeon Platinum 8573C, five vCPUs, cpu.max 400000 100000','memory_limit_bytes':34359738368,'rust':'1.91.1','wasmtime':'36.0.23','iroh':'1.5.0'},'start_utc':start,'finish_utc':time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime()),'daemons':{stage:sha(d/'entangled') for stage,d in bins.items()},'driver_sha256':sha(driver),'cli_sha256':sha(bins['candidate']/'entangle'),'design':'3 paired fresh clusters per version (baseline first, candidate first, baseline first) for greetings; one cluster per version with three trials per topology for image batch, candidate first. Limits per topology: p95 candidate/baseline <=1.05 and throughput >=0.95. Four-core shared VM measures neither physical 70B nor 8k RAW.','hello':jobs,'image':images,'comparisons':stats,'cpu_monitor_samples':scope['rows']}
r['source_after']=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
assert r['source_after']==source_id
r['baseline_authorization']='engineering comparison with preceding frozen a5728c23 daemon; production-baseline owner approval outstanding'
r['archives_sha256']={'baseline':previous['sha256'],'candidate':current['sha256']}
r['cpu_before']=host_before
r['cpu_after']=cpu_status()
r['daemon_bytes_identical']=r['daemons']['baseline']==r['daemons']['candidate']
r['input_sha256']={str(p):sha(p) for p in [image_input,component,Path(__file__),root/'scripts/benchmark_image_batch.py']}
r['files_sha256']={p.name:sha(p) for p in base.iterdir() if p.is_file()}
r['source_comparison']=subprocess.check_output(['git','diff','--stat',previous['source_commit'],head,'--','crates'],cwd=root,text=True)
(out/'performance.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
