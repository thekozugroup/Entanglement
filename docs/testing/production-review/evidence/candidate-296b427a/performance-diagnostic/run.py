"""Follow-up to the frozen seven-route sample; the separate primary receipt is read-only."""
import datetime,hashlib,json,os,re,signal,statistics,subprocess,sys,threading,time,traceback
from pathlib import Path
root=Path('/workspace/Entanglement');out=Path(__file__).resolve().parent
baseline=out.parent.parent/'candidate-c19ef758/linux-archive.json'
primary=json.loads((out.parent/'performance.json').read_text())
bins=Path('/tmp/entangle-recovery-performance-296b427a')
driver=(root/'target/debug/deps/daemon_compute-50f134c0d2ccb3e8').resolve()
def sha(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def stamp():return subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
def cpu():return {k:int(v) for k,v in (line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())}
def stats():
 snapshot={}
 for p in Path('/proc').glob('[0-9]*/stat'):
  try:
   raw=p.read_text(); name=raw[raw.index('(')+1:raw.rindex(')')];fields=raw[raw.rindex(')')+2:].split()
   if fields[0]!='Z':snapshot[int(p.parent.name)]=(name,int(fields[11])+int(fields[12]))
  except (OSError,UnicodeError):continue
 return snapshot
def monitor():
 before=stats();start=time.monotonic()
 while not stop.wait(1):
  after=stats();end=time.monotonic();hot=[]
  for pid,(name,ticks) in after.items():
   usage=max(0,ticks-before.get(pid,(name,ticks))[1])/os.sysconf('SC_CLK_TCK')/(end-start)
   if usage>.15:hot.append([round(usage,2),name,pid])
  data['cpu_samples'].append({'utc':utc(),'processes_above_0.15_core':sorted(hot,reverse=True),'cgroup':cpu()});before,start=after,end
def run(argv,env,log):
 with (out/log).open('x') as f:
  p=subprocess.Popen(argv,stdout=f,stderr=subprocess.STDOUT,env=env,cwd=root,start_new_session=True)
  try:return p.wait(timeout=min(45,max(.01,deadline-time.monotonic())))
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(3)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   raise
rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert rev==primary['candidate_commit'] and sha(driver)==primary['driver_sha256']
assert sha(bins/'candidate/entangle')==sha(bins/'baseline/entangle')==primary['cli_sha256']
for stage in ('baseline','candidate'):
 meta=json.loads((baseline if stage=='baseline' else out.parent/'linux-archive.json').read_text())
 assert sha(bins/stage/'entangled')==primary['daemons'][stage]==meta['files_sha256']['entangled']
source=stamp();assert source==primary['source_id'];deadline=time.monotonic()+300
data=dict(revision=rev,source_before=source,start_utc=utc(),primary_sha256=sha(out.parent/'performance.json'),plan_sha256=sha(out/'plan.md'),driver_sha256=sha(driver),daemons=primary['daemons'],cli_sha256=primary['cli_sha256'],cpu_before=cpu(),cpu_samples=[],pairs=[],exit_code=1)
stop=threading.Event();th=threading.Thread(target=monitor);th.start()
try:
 for i,order in enumerate(('AB','CD','BA','DC','BA','DC','AB','CD'),1):
  pair=dict(pair=i,order=order,arms=[]);data['pairs'].append(pair)
  for label in order:
   arm=dict(label=label,start_utc=utc(),metrics={});pair['arms'].append(arm);stage='baseline' if label=='A' else 'candidate';prefix=f'{i}-{label}';env=dict(os.environ,ENTANGLE_BENCH_DAEMON=str(bins/stage/'entangled'))
   assert run([driver,'benchmark::measure_dispatch','--exact','--ignored','--nocapture'],env,prefix+'-hello.log')==0
   for match in re.finditer(r'^(local|remote) concurrency=(\d+) requests=(\d+) p50_ms=([\d.]+) p95_ms=([\d.]+) requests_per_s=([\d.]+)$',(out/(prefix+'-hello.log')).read_text(),re.M):
    route,c,n,p50,p95,rate=match.groups();assert int(n)==1024;arm['metrics'][route+' / '+c]=[float(p95),float(rate)]
   assert len(arm['metrics'])==4
   path=out/(prefix+'-image.json');assert not path.exists()
   code=run(['target/catalog-smoke-python/bin/python','scripts/benchmark_image_batch.py','--bin-dir',str(bins/stage),'--wasm','target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm','--image','/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg','--results',path],os.environ,prefix+'-image.log');assert code in (0,2)
   image=json.loads(path.read_text());ref=primary['image']['candidate']
   for key in ('input_sha256','png_digest_list_sha256','wasm_sha256','source_sha256'):assert image[key]==ref[key]
   assert image['daemon_sha256']==primary['daemons'][stage]
   for route in ('local','one_remote','three_remote'):
    trials=[x for x in image['trials'] if x['route']==route];assert len(trials)==3 and all(len(x['latency_ms_by_input'])==24 for x in trials)
    arm['metrics']['image '+route]=[statistics.median(x[k] for x in trials) for k in ('p95_ms','images_s')]
   arm['end_utc']=utc();print(i,label,utc(),flush=True)
 data['exit_code']=0
except BaseException:
 data['error']=traceback.format_exc()
finally:
 stop.set();th.join();data['end_utc']=utc();data['cpu_after']=cpu();data['source_after']=stamp()
 if data['source_after']!=source:data['exit_code']=1
 with (out/'results.json').open('x') as fp:json.dump(data,fp,indent=2);print(file=fp)
sys.exit(data['exit_code'])
