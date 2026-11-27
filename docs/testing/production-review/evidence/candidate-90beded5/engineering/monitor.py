import json,os,subprocess,time
from pathlib import Path
from threading import Event,Thread
root=Path('/workspace/Entanglement')
out=Path('/tmp')
stopped=Event()
known={'cargo','rustc','clang','cc1','ld.lld','lld','gcc','ctest','wasm-tools','docker-buildx','ninja','make'}
rows=[]
def process_stats():
 result={}
 for p in Path('/proc').glob('[0-9]*/stat'):
  try:
   raw=p.read_text()
   comm=raw[raw.index('(')+1:raw.rindex(')')]
   fields=raw[raw.rindex(')')+2:].split()
   if fields[0]!='Z':
    result[int(p.parent.name)]=(comm,int(fields[11])+int(fields[12]))
  except (FileNotFoundError,ProcessLookupError,PermissionError,UnicodeError): pass
 return result
def monitor():
 previous=process_stats();last=time.monotonic()
 while not stopped.is_set():
  current=process_stats();now=time.monotonic()
  rows.append({'utc':time.strftime('%H:%M:%S',time.gmtime()),'known_build_processes':[name for name,_ in current.values() if name in known],
    'top_live_cpu_cores':{str(pid)+':'+str(name):round(cores,3) for cores,pid,name in sorted([(max(0,ticks-previous.get(pid,(name,ticks))[1])/os.sysconf('SC_CLK_TCK')/max(now-last,0.001),pid,name) for pid,(name,ticks) in current.items()],reverse=True)[:12] if cores>0.02}})
  previous,last=current,now
  stopped.wait(1)
t=Thread(target=monitor);t.start()
try:
 for mode,stage in [('unrestricted','before'),('fixed','after'),('fixed','before'),('unrestricted','after')]:
  flags=['--worker-cpu-affinity'] if mode=='fixed' else []
  cmd=['target/catalog-smoke-python/bin/python','scripts/benchmark_image_batch.py','--bin-dir',f'/tmp/entangle-image-{stage}-bin','--wasm','target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm','--image','/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg','--results',f'/tmp/capacity-{mode}-{stage}.json',*flags]
  print(time.strftime('%H:%M:%S',time.gmtime()),mode,stage,flush=True)
  with open(out/f'capacity-{mode}-{stage}.log','w') as fp:
   proc=subprocess.run(cmd,cwd=root,stdout=fp,stderr=subprocess.STDOUT)
  if proc.returncode not in (0,2): raise SystemExit(proc.returncode)
finally:
 stopped.set();t.join()
 (out/'entangle-capacity-cpu.json').write_text(json.dumps(rows,indent=2))
