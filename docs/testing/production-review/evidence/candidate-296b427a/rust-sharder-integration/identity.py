#!/usr/bin/env python3
"""Run the checked-out production sharder, recording its unmodified local RPC traffic."""
import argparse,contextlib,datetime,hashlib,importlib.util,json,os,re,socket,socketserver,struct,subprocess,sys,tempfile,threading,time,tomllib,traceback
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--repo',required=True,type=Path);p.add_argument('--bin-dir',required=True,type=Path);p.add_argument('--reference',required=True,type=Path);p.add_argument('--old-bin-dir',required=True,type=Path);p.add_argument('--fixture-dir',required=True,type=Path);p.add_argument('--out',required=True,type=Path);args=p.parse_args()
r=args.repo.resolve();bn=args.bin_dir.resolve();ob=args.old_bin_dir.resolve();f=args.fixture_dir.resolve();m=json.loads(args.reference.read_text())
old=json.loads((r/'docs/testing/production-review/evidence/candidate-c19ef758/linux-archive.json').read_text());runner=r/'scripts/run-rust-tests.py'
def sha(p):
 with p.open('rb') as data:return hashlib.file_digest(data,'sha256').hexdigest()
def stamp():
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()==m['source_commit']
 sid=subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=r,text=True).strip();assert m['source_id']==m['source_after']==sid
 for bindir,meta in [(bn,m),(ob,old)]:
  assert all(sha(bindir/n)==meta['files_sha256'][n] for n in ('entangle','entangled'))
 return sid
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
sp=importlib.util.spec_from_file_location('nodes',r/'scripts/tests/distributed-rust-tests.py');nodes=importlib.util.module_from_spec(sp);sp.loader.exec_module(nodes)
def forward(node,encoded):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
  sock.settimeout(35);sock.connect(str(node.socket));sock.sendall(encoded)
  with sock.makefile('rb') as stream:return stream.readline(4*1024*1024+1)
def rpc(node,method,params=None):
 return json.loads(forward(node,(json.dumps({'jsonrpc':'2.0','id':17,'method':method,'params':params})+'\n').encode()))
def controlled(peer,plugin,operation):
 return {'plugin_id':plugin,'input':list(json.dumps(operation).encode()),'timeout_ms':12000,'cpu_cores':0.0,'memory_bytes':0,'gpu_required':False,'gpu_vram_min_bytes':0,'integrity':{'kind':'trusted-executor','allowlist':[peer]}}
def pid(node):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.connect(str(node.socket));return struct.unpack('iii',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]
def usage(pid):
 fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split();return int(fields[11])+int(fields[12])
class Proxy(socketserver.ThreadingUnixStreamServer):
 daemon_threads=True
 def __init__(self,path,node):
  self.events=[];self.errors=[];self.phase='';self.node=node;self.before=None
  super().__init__(str(path),Handler)
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  srv=self.server
  try:
   raw=self.rfile.readline(4*1024*1024);req=json.loads(raw);event=None
   if req['method']=='compute/dispatch':
    param=req['params'];allow=param['integrity']['allowlist'];assert len(allow)==1
    op=json.loads(bytes(param['input']));event={'phase':srv.phase,'peer':allow[0],'operation':op,'started_ns':time.monotonic_ns()};srv.events.append(event)
    if srv.before:srv.before(event)
   raw_response=forward(srv.node,raw)
   if event is not None:
    result=json.loads(raw_response);event['finished_ns']=time.monotonic_ns()
    if 'error' in result:event['error']=result['error']
    else:
     reply=result['result'];assert reply['chosen_peer']==event['peer'];value=json.loads(bytes(reply['output']))
     event.update(chosen_peer=reply['chosen_peer'],identity=value.get('suite_identity'),exit_code=value['exit_code'],stdout=value['stdout'],stderr=value['stderr'])
   self.wfile.write(raw_response)
  except Exception as err:
   srv.errors.append(repr(err));self.wfile.write((json.dumps({'jsonrpc':'2.0','id':1,'error':{'code':-32603,'message':'transparent fixture failure'}})+'\n').encode())
def prepare(root,coord):
 src=root/'source';src.mkdir();packages={};identities={}
 for label,artifact,detail in [('a','a','signed ordinary suite'),('b','b','signed ordinary suite'),('manifest','a','signed revised description')]:
  manifest='[plugin]\nid="PUBLISHER_PLACEHOLDER/observed-suite@0.1.0"\nversion="0.1.0"\ntier=1\nruntime="wasm"\ndescription='+json.dumps(detail)+'\n[build]\nwit_world="wasi:cli/command@0.2.0"\ntarget="wasm32-wasip2"\n'
  (src/'entangle.toml').write_text(manifest);pkg=root/('package-'+label);coord.cli('plugins','build',src,'--wasm',f/(artifact+'.wasm'),'--out',pkg)
  plugin=tomllib.loads((pkg/'entangle.toml').read_text())['plugin']['id'];sig=tomllib.loads((pkg/'plugin.wasm.sig').read_text());packages[label]=pkg;identities[label]={k:sig[k] for k in ('artifact_blake3','manifest_blake3')}
 assert identities['a']['artifact_blake3']==identities['manifest']['artifact_blake3'] and identities['a']['manifest_blake3']!=identities['manifest']['manifest_blake3']
 assert identities['a']['artifact_blake3']!=identities['b']['artifact_blake3'] and identities['a']['manifest_blake3']==identities['b']['manifest_blake3']
 return plugin,packages,identities
def exercise(report):
 with tempfile.TemporaryDirectory(prefix='ent-int-suite-',dir='/tmp') as t,contextlib.ExitStack() as stack:
  root=Path(t);coord=nodes.Node(root/'coordinator',bn);workers={k:nodes.Node(root/k,ob if k=='old' else bn) for k in ('one','two','old')}
  plugin,pkgs,ids=prepare(root,coord);report['signed_identities']=ids;report['plugin_id']=plugin
  routes=[]
  for w in workers.values():
   coord.trust(w);w.trust(coord);w.cli('keyring','add',coord.key,'--name','disposable libtest publisher')
   port=nodes.free_port();w.start(stack,port,[]);w.cli('plugins','load',pkgs['a']);routes.append(f'{w.key}@127.0.0.1:{port}')
  coord.start(stack,0,routes);one,two,older=workers.values();report['workers']={n:w.peer for n,w in workers.items()}
  local_control=rpc(coord,'mesh/status')['result'];report['libtest_remote_codes']=local_control.get('libtest_remote_codes');assert report['libtest_remote_codes']==1,local_control
  for w in workers.values():
   limit=time.monotonic()+45
   while True:
    resp=rpc(coord,'compute/dispatch',controlled(w.peer,plugin,{'operation':'list'}))
    if 'result' in resp:break
    assert 'no live workers' in resp['error']['message'] and time.monotonic()<limit,resp;time.sleep(.25)
  path=root/'observe.sock';proxy=Proxy(path,coord);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
  def stop():
   proxy.shutdown();proxy.server_close();thread.join(timeout=5)
  stack.callback(stop);report['events']=proxy.events;report['phases']={};report['operator_actions']=[]
  def swap(w,new):
   v={'peer':w.peer,'new':new,'unload_begin_utc_ns':time.time_ns()};report['operator_actions'].append(v)
   w.cli('plugins','unload',plugin);v['unload_ack_utc_ns']=time.time_ns()
   w.cli('plugins','load',pkgs[new]);v['load_ack_utc_ns']=time.time_ns();return v
  def run(phase,peers,name,status,before=None):
   proxy.phase=phase;proxy.before=before
   cmd=[sys.executable,'-B',str(runner),'--socket',str(path),'--timeout-ms','12000','--filter',name,'--exact','--retries','2']
   for w in peers:cmd+=['--peer',w.peer]
   cmd.append(plugin);reply=subprocess.run(cmd,capture_output=True,text=True,timeout=55)
   calls=[e for e in proxy.events if e['phase']==phase]
   result={'exit_code':reply.returncode,'stderr':reply.stderr,'report':json.loads(reply.stdout) if reply.stdout.strip() else None,'requests':len(calls)}
   report['phases'][phase]=result;assert not proxy.errors,proxy.errors;assert reply.returncode==status,(phase,result)
   if result['report']:
    suite,=result['report']['suites'];row,=suite['results'];return row,calls
   return None,calls
  def checks_clean(row,identity,label):
   a,=row['attempts'];assert row['status']=='passed' and a['suite_identity']==identity and 'observed_component='+label in a['stdout'],row
  def mismatch(row,calls,want):
   attempts=row['attempts'];assert row['status']=='error' and len(attempts)==want
   final=attempts[-1];assert final['status']=='error' and final['error_kind']=='suite_identity' and 'identity' in final['error'].lower(),row
   ops=[e for e in calls if e['operation']['operation']=='test'];assert len(ops)==want
   assert all(e['operation']['expected_suite_identity']==ids['a'] for e in ops)
   assert ops[-1]['error'].get('data',{}).get('remote_code')=='suite-identity-mismatch' and 'stdout' not in ops[-1],ops[-1]
  row,calls=run('matching-control',[one,two],'arithmetic_case',0);checks_clean(row,ids['a'],'A')
  for variant in ['b','manifest']:
   swap(two,variant);row,calls=run('discovery-divergence-'+variant,[one,two],'arithmetic_case',1)
   assert row is None and 'identity mismatch' in report['phases']['discovery-divergence-'+variant]['stderr'].lower()
   assert not any(e['operation']['operation']=='test' for e in calls);swap(two,'a')
  def change_at_test(e):
   if e['operation']['operation']=='test' and e['operation']['attempt']==1:swap(one,'b')
  row,calls=run('change-after-list-before-exact',[one,two],'arithmetic_case',1,change_at_test);mismatch(row,calls,1);swap(one,'a')
  def change_at_retry(e):
   if e['operation']['operation']=='test' and e['operation']['attempt']==2:swap(two,'b')
  row,calls=run('change-after-failure-before-retry',[one,two],'controlled_first_failure',1,change_at_retry);mismatch(row,calls,2)
  assert row['attempts'][0]['status']=='failed' and row['attempts'][0]['peer']==one.peer and row['attempts'][1]['peer']==two.peer;swap(two,'a')
  row,calls=run('matching-retry-control',[one,two],'controlled_first_failure',0);assert row['status']=='flaky' and [a['peer'] for a in row['attempts']]==[one.peer,two.peer]
  future=[];events=[];bg_errors=[]
  def race(e):
   if e['operation']['operation']!='test':return
   process=pid(one);base=usage(process);ticks=os.sysconf('SC_CLK_TCK')
   def alter():
    try:
     limit=time.monotonic()+4
     while usage(process)-base<max(2,int(.15*ticks)):
      assert time.monotonic()<limit,'selected worker CPU did not advance';time.sleep(.008)
     events.append(swap(one,'b'))
    except Exception as err:bg_errors.append(repr(err))
   th=threading.Thread(target=alter);future.append(th);th.start()
  row,calls=run('replace-during-admitted-guest',[one,two],'selected_during_reload',0,race)
  for th in future:th.join(timeout=7)
  assert len(events)==1 and not bg_errors and len(future)==1 and not future[0].is_alive(),(events,bg_errors)
  checks_clean(row,ids['a'],'A');attempt,=row['attempts'];beg,end=map(int,re.search(r'guest_utc_ns=(\d+) (\d+)',attempt['stdout']).groups());action=events[0];assert beg<action['unload_begin_utc_ns']<end<=action['unload_ack_utc_ns'],(beg,end,action)
  report['race']={'guest_interval_ns':[beg,end],**action}
  stale=rpc(coord,'compute/dispatch',controlled(one.peer,plugin,{'operation':'test','name':'arithmetic_case','expected_suite_identity':ids['a']}))
  assert stale['error'].get('data',{}).get('remote_code')=='suite-identity-mismatch',stale;report['stale_after_drain']=stale['error'];row,calls=run('new-fingerprint-after-drain',[one],'arithmetic_case',0);checks_clean(row,ids['b'],'B');swap(one,'a')
  row,calls=run('legacy-worker-upgrade-message',[older,two],'arithmetic_case',1)
  assert row is None and not any(e['operation']['operation']=='test' for e in calls)
  err=report['phases']['legacy-worker-upgrade-message']['stderr'].lower();assert 'upgrade' in err and ('identity' in err or 'fingerprint' in err),err
  row,calls=run('legacy-worker-following-current',[one,older],'arithmetic_case',1)
  assert row is None and not any(e['operation']['operation']=='test' for e in calls)
  second_error=report['phases']['legacy-worker-following-current']['stderr'].lower();assert 'worker daemon' in second_error and ('signed libtest suite' in second_error or 'upgrade' in second_error),second_error
  legacy_cap=rpc(older,'mesh/status')['result'].get('libtest_remote_codes');assert legacy_cap is None,legacy_cap
  old_coordinator=subprocess.run([sys.executable,'-B',str(runner),'--socket',str(older.socket),'--peer',one.peer,plugin],capture_output=True,text=True,timeout=12)
  report['legacy_coordinator']={'exit_code':old_coordinator.returncode,'stderr':old_coordinator.stderr,'stdout':old_coordinator.stdout,'libtest_remote_codes':legacy_cap}
  assert old_coordinator.returncode==1 and not old_coordinator.stdout and 'coordinator' in old_coordinator.stderr.lower() and 'upgrade' in old_coordinator.stderr.lower(),report['legacy_coordinator']
  for policy_change,expected_code in [('unload','plugin-not-loaded'),('revoke','not-authorized')]:
   def change_policy(event):
    if event['operation'].get('attempt')==1 and event['operation']['operation']=='test':
     if policy_change=='unload':one.cli('plugins','unload',plugin)
     else:one.cli('mesh','revoke',coord.peer)
   phase='selected-after-'+policy_change;row,calls=run(phase,[one,two],'arithmetic_case',1,change_policy)
   a,=row['attempts'];assert row['status']=='error' and a['error_kind']=='remote_rejected' and a.get('remote_code')==expected_code,a
   exact,=[e for e in calls if e['operation']['operation']=='test'];assert exact['peer']==one.peer and exact['error'].get('data',{}).get('remote_code')==expected_code and 'stdout' not in exact,exact
   if policy_change=='unload':one.cli('plugins','load',pkgs['a'])
   else:one.trust(coord)
  # Removing the publisher key alone does not unload admitted in-memory code.
  one.cli('keyring','remove',plugin.split('/')[0]);row,calls=run('loaded-suite-after-key-removal',[one],'arithmetic_case',0);checks_clean(row,ids['a'],'A')
  one.cli('plugins','unload',plugin)
  denied=subprocess.run([bn/'entangle','plugins','load',pkgs['a']],env=one.env,capture_output=True,text=True,timeout=10);assert denied.returncode and 'ENTANGLE-E0101' in denied.stderr,denied
  one.cli('keyring','add',coord.key,'--name','re-authorized fixture publisher');one.cli('plugins','load',pkgs['a'])
  row,calls=run('fresh-after-trust-restored',[one,two],'arithmetic_case',0);checks_clean(row,ids['a'],'A');report['retired_publisher_rejected_reload']='ENTANGLE-E0101'
before=stamp();started=utc();report=dict(source_commit=m['source_commit'],source_id=before,source_before=before,started_utc=started,archive_sha256=m['sha256'],candidate_elf_sha256={n:sha(bn/n) for n in ('entangle','entangled')},older_c19_elf_sha256={n:sha(ob/n) for n in ('entangle','entangled')},runner_sha256=sha(runner),driver_sha256=sha(Path(__file__)),fixtures={n:sha(f/n) for n in ('guarded.rs','a.wasm','b.wasm')},scope='Transparent local UDS fixture; actual untouched JSON-RPC, verified archive executables, signed WIT suites, explicit private Iroh pairing. The concurrent case compares real guest wall-clock interval against ordinary worker unload acknowledgement.')
try:exercise(report);report['exit_code']=0
except Exception as err:report.update(exit_code=1,error=repr(err),traceback=traceback.format_exc())
report['source_after']=stamp();report['finished_utc']=utc()
with args.out.open('x') as out:json.dump(report,out,indent=2);print(file=out)
print(report['exit_code'],list(report.get('phases',{})),report.get('error'));sys.exit(report['exit_code'])
