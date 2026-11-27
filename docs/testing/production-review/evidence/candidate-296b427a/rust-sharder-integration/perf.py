"""Run the normal pinned and previous Python entry points alternately on one fresh release cluster."""
import argparse,contextlib,datetime,hashlib,importlib.util,json,os,re,shlex,statistics,subprocess,sys,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--repo',required=True,type=Path);p.add_argument('--bin-dir',required=True,type=Path);p.add_argument('--reference',required=True,type=Path);p.add_argument('--fixture-dir',required=True,type=Path);p.add_argument('--out',required=True,type=Path);args=p.parse_args()
r=args.repo.resolve();bins=args.bin_dir.resolve();f=args.fixture_dir.resolve();m=json.loads(args.reference.read_text());base='a837e6da48b67361b9d2841b6a37e892d7cbf2e3'
def sha(p):
 with p.open('rb') as data:return hashlib.file_digest(data,'sha256').hexdigest()
def stamp():
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()==m['source_commit']
 sid=subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=r,text=True).strip();assert m['source_id']==m['source_after']==sid
 assert all(sha(bins/n)==m['files_sha256'][n] for n in ('entangle','entangled'));return sid
def clock():return datetime.datetime.now(datetime.timezone.utc).isoformat()
sp=importlib.util.spec_from_file_location('nodes',r/'scripts/tests/distributed-rust-tests.py');nodes=importlib.util.module_from_spec(sp);sp.loader.exec_module(nodes)
def guest_occupancy(rows,peers):
 events={}
 for name,attempt in rows.items():
  for t,change in [(attempt['enter_ns'],1),(attempt['exit_ns'],-1)]:events.setdefault(t,[]).append((attempt['peer'],change))
 count=dict.fromkeys(peers,0);peak=count.copy();prev=min(events);idle_double_ns=0
 for t,changes in sorted(events.items()):
  if max(count.values())>1 and min(count.values())==0:idle_double_ns+=t-prev
  for peer,change in sorted(changes,key=lambda e:e[1]):
   count[peer]+=change;peak[peer]=max(peak[peer],count[peer])
  prev=t
 return peak,idle_double_ns/1e6
def exercise(report):
 with tempfile.TemporaryDirectory(prefix='ent-int-perf-',dir='/tmp') as temp,contextlib.ExitStack() as stack:
  root=Path(temp);prev=root/'previous-sharder.py'
  prev.write_bytes(subprocess.check_output(['git','show',base+':scripts/run-rust-tests.py'],cwd=r));cur=r/'scripts/run-rust-tests.py';suites={'before':prev,'after':cur}
  coord=nodes.Node(root/'coordinator',bins);plugin,pkg=nodes.signed_suite(coord,root,'seeded-lengths',f/'seeded.wasm')
  workers=[];routes=[];affinity=sorted(os.sched_getaffinity(0))[-2:];assert len(affinity)==2
  for i,cpu in enumerate(affinity):
   wrapper=root/f'bin-{i}';wrapper.mkdir();(wrapper/'entangle').symlink_to(bins/'entangle');daemon=wrapper/'entangled';daemon.write_text('#!/bin/sh\nexec taskset -c '+str(cpu)+' '+shlex.quote(str(bins/'entangled'))+' "$@"\n');daemon.chmod(0o755)
   w=nodes.Node(root/f'worker-{i}',wrapper);workers.append(w);port=nodes.free_port();coord.trust(w);w.trust(coord);w.cli('keyring','add',coord.key,'--name','disposable seeded suite publisher');w.start(stack,port,[]);w.cli('plugins','load',pkg);routes.append(f'{w.key}@127.0.0.1:{port}')
  coord.start(stack,0,routes);peers=[w.peer for w in workers];report.update(cpu_affinity=affinity,peers=peers,sharder_sha256={k:sha(path) for k,path in suites.items()},results=[],source_signed_suite_id=plugin)
  def run(path,peer_set,extra):
   cmd=[sys.executable,'-B',str(path),plugin,'--socket',str(coord.socket),'--timeout-ms','30000','--retries','0',*extra]
   for peer in peer_set:cmd+=['--peer',peer]
   # The daemon reports actual executors; don't synthesize or edit RPC responses.
   start=time.monotonic_ns();rr=subprocess.run(cmd,capture_output=True,text=True,timeout=40);end=time.monotonic_ns()
   assert rr.returncode==0,(rr.stderr,rr.stdout);return json.loads(rr.stdout),round((end-start)/1e6,3)
  # Excluded warm-up selects a short ordinary test once on each peer.
  for peer in peers:
   rr,_=run(cur,[peer],['--filter','b_short','--exact']);assert rr['counts']['passed']==1
  for label in ['before','after','after','before','after','before','before','after']:
   raw,wall=run(suites[label],peers,[]);suite,=raw['suites'];assert raw['counts']==dict(passed=8,flaky=0,failed=0,ignored=0,error=0)
   guest={}
   for item in suite['results']:
    attempt,=item['attempts'];assert attempt['peer'] in peers and attempt['attempt']==1 and item['status']==attempt['status']=='passed'
    if label=='after': assert attempt['suite_identity']==suite['suite_identity']
    mat=re.search(r'seeded_guest_interval (\d+) (\d+)',attempt['stdout']);enter,leave=map(int,mat.groups());assert enter<leave
    guest[item['name']]={'peer':attempt['peer'],'enter_ns':enter,'exit_ns':leave}
   assert list(guest)==sorted(guest)
   peak,idle=guest_occupancy(guest,peers)
   row=dict(kind=label,suite_elapsed_ms=suite['elapsed_ms'],cli_wall_ms=wall,guest=guest,peak_simultaneous_guest_invocations=peak,ms_double_on_one_worker_other_idle=idle,counts=raw['counts'])
   report['results'].append(row);print(label,suite['elapsed_ms'],idle,flush=True)
  report['summary']={}
  for label in suites:
   rows=[x for x in report['results'] if x['kind']==label];report['summary'][label]={'all_suite_elapsed_ms':[v['suite_elapsed_ms'] for v in rows],'median_suite_elapsed_ms':statistics.median(v['suite_elapsed_ms'] for v in rows),'all_double_one_other_idle_ms':[v['ms_double_on_one_worker_other_idle'] for v in rows],'max_parallel_guest_invocations_per_peer':[max(v['peak_simultaneous_guest_invocations'].values()) for v in rows]}
before=stamp();report=dict(source_commit=m['source_commit'],source_before=before,source_id=before,started_utc=clock(),canonical_archive_sha256=m['sha256'],old_sharder_commit=base,artifact_sha256={n:sha(bins/n) for n in ('entangle','entangled')},fixture_sha256={n:sha(f/n) for n in ('seeded.wasm','seeded.rs')},driver_sha256=sha(Path(__file__)),scope='Same running new archive, product CLI sharder entry point, two same-host single-CPU-pinned real Iroh workers, one ordinary signed seeded WASI suite, mixed-duration controlled workloads; separate from natural flake evidence.')
try:exercise(report);report['exit_code']=0
except Exception as err:
 import traceback
 report.update(exit_code=1,error=repr(err),traceback=traceback.format_exc())
report.update(source_after=stamp(),finished_utc=clock())
with args.out.open('x') as out:json.dump(report,out,indent=2);print(file=out)
print(report['exit_code'],report.get('summary') or report.get('error'));sys.exit(report['exit_code'])
