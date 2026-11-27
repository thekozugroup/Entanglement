"""Dispatch every Cargo-emitted WASI libtest target from a pinned external workspace."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,tempfile,time,tomllib
from pathlib import Path
from contextlib import ExitStack
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--binaries',type=Path,required=True);p.add_argument('--workspace',type=Path,required=True);p.add_argument('--wasm-artifacts',type=Path,required=True);p.add_argument('--metadata',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args();root=args.root.resolve()
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=module('fixture',root/'scripts/tests/distributed-rust-tests.py')
runner=module('runner',root/'scripts/run-rust-tests.py')
metadata=json.loads(args.metadata.read_text());members=set(metadata['workspace_members']);sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
artifacts={}
for line in args.wasm_artifacts.read_text().splitlines():
 j=json.loads(line)
 if j['reason']!='compiler-artifact' or j['package_id'] not in members or not j['profile']['test'] or not j['executable']:continue
 key=(j['package_id'],j['target']['name'],tuple(j['target']['kind']));artifacts[key]=Path(j['executable'])
assert artifacts
r={'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=args.workspace,text=True).strip(),'upstream':subprocess.check_output(['git','remote','get-url','origin'],cwd=args.workspace,text=True).strip(),'lock_sha256':sha(args.workspace/'Cargo.lock'),'source_diff':subprocess.check_output(['git','diff','HEAD','--stat'],cwd=args.workspace,text=True),'binaries':{n:sha(args.binaries/n) for n in ['entangled','entangle']},'targets':[]}
assert not r['source_diff']
with tempfile.TemporaryDirectory(prefix='ent-upstream-') as tmp,ExitStack() as stack:
 d=Path(tmp);coord=fixture.Node(d/'coord',args.binaries);workers=[fixture.Node(d/('worker'+str(i)),args.binaries) for i in range(2)];packages=[]
 for i,((pkg,target,kind),wasm) in enumerate(sorted(artifacts.items())):
  label=f'suite-{i}';pid,pkgdir=fixture.signed_suite(coord,d,label,wasm);packages.append((pid,pkgdir));r['targets'].append({'package':pkg,'target':target,'kind':kind,'wasm_sha256':sha(wasm),'bytes':wasm.stat().st_size,'plugin':pid})
 routes=[]
 for worker in workers:
  port=fixture.free_port();coord.trust(worker);worker.trust(coord);worker.cli('keyring','add',coord.key,'--name','upstream suite publisher');worker.start(stack,port,[])
  for _,pkg in packages:worker.cli('plugins','load',pkg)
  routes.append(f'{worker.key}@127.0.0.1:{port}')
 coord.start(stack,0,routes);peers=[w.peer for w in workers];r['peers']=peers;r['coordinator']=coord.peer
 for peer in peers:
  end=time.monotonic()+45
  while True:
   try: runner.dispatcher(coord.socket,packages[0][0],30000)(peer,{'operation':'list'});break
   except runner.DispatchError as err:
    if 'no live worker' not in str(err) or time.monotonic()>=end:raise
    time.sleep(.15)
 r['started_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());start=time.perf_counter();args.out.parent.mkdir(parents=True,exist_ok=True)
 for i,(plugin,_) in enumerate(packages):
  opts=argparse.Namespace(peer=peers,socket=coord.socket,timeout_ms=60000,retries=1,filter=None,skip=[],ignored=False,include_ignored=False,exact=False)
  report=runner.run_suite(opts,plugin);r['targets'][i]['report']=report
  print(r['targets'][i]['target'],report['counts'],flush=True)
  args.out.write_text(json.dumps(r,indent=2)+'\n')
 r['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());r['elapsed_s']=time.perf_counter()-start
 r['counts']={k:sum(t['report']['counts'][k] for t in r['targets']) for k in runner.STATUSES}
 args.out.write_text(json.dumps(r,indent=2)+'\n')
