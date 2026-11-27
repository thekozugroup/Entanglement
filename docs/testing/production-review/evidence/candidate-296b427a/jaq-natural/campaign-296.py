"""Execute the predeclared balanced genuine upstream cohort; never select by wall-clock phase."""
import argparse, collections, datetime, hashlib, importlib.util, json, os, pathlib, subprocess, sys, tempfile, time, traceback
from contextlib import ExitStack
from types import SimpleNamespace
D=pathlib.Path(__file__).resolve().parent
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sha(p):
 with pathlib.Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def put(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def src(root):return subprocess.check_output(['python3',str(root/'scripts/production_score.py'),'--source-id'],cwd=root,text=True).strip()
def exe(name):
 p=D/('original178-'+name+'-artifacts.jsonl')
 return next(pathlib.Path(j['executable']) for j in map(json.loads,p.read_text().splitlines()) if j.get('reason')=='compiler-artifact' and j['target']['name']=='named' and j['profile']['test'] and j['executable'])
def main():
 p=argparse.ArgumentParser()
 for n in ['root','binaries','archive','sharder','fixture','encoder','adapter','out']:p.add_argument('--'+n,type=pathlib.Path,required=True)
 a=p.parse_args()
 a.out.mkdir(exist_ok=False); rec=a.out/'receipt.json';raw=a.out/'blocks.jsonl'
 man=json.loads(a.archive.read_text());assert man['source_id']==man['source_after']==src(a.root)
 assert all(sha(a.binaries/n)==man['files_sha256'][n] for n in ('entangle','entangled'))
 assert not subprocess.check_output(['git','diff','HEAD','--stat'],cwd=D/'upstream')
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=D/'upstream',text=True).strip()=='606164eb26420c892c9bac27f7daf77b7a406b6d'
 stored={'source_before':man['source_id'],'release_commit':man['source_commit'],'archive_sha256':man['sha256'],
         'release_binary_sha256':{n:sha(a.binaries/n) for n in ('entangle','entangled')},'started_utc':utc(),
         'upstream_revision':'606164eb26420c892c9bac27f7daf77b7a406b6d','upstream_lock_sha256':sha(D/'upstream/Cargo.lock'),
         'plan_sha256':sha(D/'plan.md'),'script_sha256':sha(__file__),'sharder_sha256':sha(a.sharder),'fixture_sha256':sha(a.fixture),
         'upstream_case_file_sha256':sha(D/'upstream/jaq-core/tests/named.rs'),'expected_blocks':128,
         'native_executable_sha256':sha(exe('native')),'wasm_module_sha256':sha(exe('wasi')),
         'adapter_sha256':sha(a.adapter),'encoder_sha256':sha(a.encoder)}
 put(rec,stored);sh=load('runner',a.sharder); cl=load('fixture',a.fixture)
 def native():
  rows=[]
  for attempt in range(1,3):
   t=utc();s=time.monotonic()
   res=subprocess.run([exe('native'),'--exact','now','--nocapture'],capture_output=True,text=True,timeout=30)
   txt=res.stdout+res.stderr
   if res.returncode==0 and '1 passed; 0 failed' in txt and 'test now ... ok' in txt: outcome='passed'
   elif res.returncode!=0 and '0 passed; 1 failed' in txt and 'test now ... FAILED' in txt and 'assertion' in txt:outcome='failed'
   else:outcome='error'
   rows.append({'attempt':attempt,'utc':t,'elapsed_s':time.monotonic()-s,'exit':res.returncode,'stdout':res.stdout,'stderr':res.stderr,'outcome':outcome})
   if outcome!='failed':break
  return rows
 blocks=[]
 try:
  with tempfile.TemporaryDirectory(prefix='entangle-jaq-authenticated-')as temp,ExitStack()as stack,raw.open('x') as log:
   temp=pathlib.Path(temp);component=temp/'command.component.wasm'
   subprocess.run([a.encoder,exe('wasi'),a.adapter,component],check=True)
   coord=cl.Node(temp/'coordinator',a.binaries);ws=[cl.Node(temp/f'worker-{i}',a.binaries) for i in range(2)];peers=[w.peer for w in ws]
   plugin,pkg=cl.signed_suite(coord,temp,'jaq-clock',component);routes=[]
   stored.update(coordinator=coord.peer,peers=peers,plugin_id=plugin,signed_manifest_sha256=sha(pkg/'entangle.toml'),signed_component_sha256=sha(component))
   expected={k:subprocess.check_output(['/workspace/.entanglement-dev/release-tools/bin/b3sum',f],text=True).split()[0] for k,f in [('manifest_blake3',pkg/'entangle.toml'),('artifact_blake3',component)]}
   stored['independent_signed_suite_identity']=expected
   for w in ws:
    coord.trust(w);w.trust(coord);w.cli('keyring','add',coord.key,'--name','exact upstream Cargo suite publisher')
    port=cl.free_port();w.start(stack,port,[]);w.cli('plugins','load',pkg);routes.append(f'{w.key}@127.0.0.1:{port}')
   coord.start(stack,0,routes)
   dispatchfactory=sh.dispatcher
   pre=sh.dispatcher(coord.socket,plugin,30_000)
   for peer in peers:
    end=time.monotonic()+80
    while True:
     try:
      initial=pre(peer,{'operation':'list','ignored':False});assert 'now: test' in initial['stdout'];break
     except sh.DispatchError as e:
      if 'no live worker' not in str(e) or time.monotonic()>=end: raise
      time.sleep(.15)
   put(rec,stored);consecutive=0;start=time.monotonic()
   for i in range(128):
    if time.monotonic()-start>=1200:stored['stop_reason']='20-minute bound';break
    record={'block':i+1,'utc':utc(),'order':['native','remote'] if i%2==0 else ['remote','native']}
    order=peers if i%2==0 else peers[::-1];record['remote_peer_order']=order
    for side in record['order']:
     if side=='native':record['native']=native();continue
     trace=[]
     def observed(sock,suite,timeout):
      real=dispatchfactory(sock,suite,timeout)
      def call(peer,op):
       t=utc();s=time.monotonic()
       try:
        result=real(peer,op)
        if op.get('operation')=='test':
         trace.append({'peer':peer,'request':op,'utc':t,'elapsed_s':time.monotonic()-s,'result':result})
        return result
       except Exception as exc:
        trace.append({'peer':peer,'request':op,'utc':t,'error':repr(exc)});raise
      return call
     sh.dispatcher=observed
     opts=SimpleNamespace(socket=coord.socket,peer=order,plugins=[plugin],filter='now' if a.sharder.name=='sharder-c19.py' else ['now'],exact=True,skip=[],ignored=False,include_ignored=False,retries=1,timeout_ms=30_000)
     try:
      report=sh.run_suites(opts)['suites'][0]; record['remote']=report
      assert len(report['results'])==1 and report['results'][0]['name']=='now'
      attempts=report['results'][0]['attempts'];assert [r['peer']for r in attempts]==order[:len(attempts)]
      assert len(trace)==len(attempts)
      for idx,(att,observed_row)in enumerate(zip(attempts,trace)):
       if a.sharder.name!='sharder-c19.py':
        assert observed_row['request']['expected_suite_identity']==observed_row['result']['suite_identity']==report['suite_identity']==expected
       if att['status']=='failed':
        text=observed_row['result']['stdout']+observed_row['result']['stderr']
        if 'assertion' not in text or ('panicked at' not in text and 'test now ... FAILED' not in text):raise ValueError('unrecognized assertion failure')
     except Exception as exc:record['remote_evidence_error']=repr(exc)
     finally:sh.dispatcher=dispatchfactory
     record['remote_raw_test_requests_and_replies']=trace
    failed=bool(record.get('remote_evidence_error')) or any(v['outcome']=='error' for v in record['native']) or any(v['status']=='error' for v in record.get('remote',{}).get('results',[{'status':'error'}]))
    consecutive=consecutive+1 if failed else 0
    log.write(json.dumps(record,sort_keys=True)+'\n');log.flush();blocks.append(record)
    if consecutive>=3:stored['stop_reason']='three successive infrastructure errors';break
 except Exception as e:stored['fatal_error']=repr(e);stored['traceback']=traceback.format_exc()
 stored.update(finished_utc=utc(),source_after=src(a.root),blocks=len(blocks),raw_sha256=sha(raw) if raw.exists()else None)
 stored['native_patterns']=dict(collections.Counter(tuple_to_text(r['outcome']for r in b['native']) for b in blocks))
 stored['remote_patterns']=dict(collections.Counter(tuple_to_text(r['status']for r in b['remote']['results'][0]['attempts']) if b.get('remote',{}).get('results') else 'error' for b in blocks))
 stored['verified_remote_transitions']=[b['block']for b in blocks if not b.get('remote_evidence_error') and [v['status']for v in (b.get('remote',{}).get('results') or [{'attempts':[]}])[0]['attempts']]==['failed','passed']]
 stored['errors']=sum(bool(b.get('remote_evidence_error')) for b in blocks)
 put(rec,stored)
 return int(any([stored.get('fatal_error'),stored['source_after']!=stored['source_before'],len(blocks)!=128,stored['errors']]))
def tuple_to_text(x):return '->'.join(x)
if __name__=='__main__':raise SystemExit(main())
