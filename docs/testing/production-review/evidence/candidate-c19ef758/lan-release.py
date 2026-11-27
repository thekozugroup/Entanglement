"""Test mDNS-only discovery with two authentic, manifest-matched Linux release daemons."""
from contextlib import ExitStack
import datetime,hashlib,importlib.util,json,os,secrets,socket,subprocess,tempfile,time,tomllib
from pathlib import Path
here=Path(__file__).resolve().parent;repo=here.parents[4];m=json.loads((here/'linux-archive.json').read_text());bins=Path('/tmp/entangle-check-'+m['source_commit'][:8]+'-archive')
fixture=here.parent/'candidate-a0926c6e/authenticated-hot-load/check-v2.py';sp=importlib.util.spec_from_file_location('mesh_fixture',fixture);f=importlib.util.module_from_spec(sp);sp.loader.exec_module(f)
def sha(p):
 with p.open('rb') as content:return hashlib.file_digest(content,'sha256').hexdigest()
def stamp():
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()==m['source_commit']
 assert subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=repo,text=True).strip()==m['source_id']
 hashes={n:sha(bins/n) for n in ('entangle','entangled')};assert all(m['files_sha256'][n]==s for n,s in hashes.items());return hashes
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def start(n,stack):
 (n.state/'config.toml').write_text('[mesh]\ntransports=["local","iroh"]\nmulti_node=true\n[scheduler]\nbind="0.0.0.0:0"\nrelay=false\npeers=[]\n')
 log=stack.enter_context((n.directory/'daemon.log').open('wb'));p=subprocess.Popen([n.binaries/'entangled','run'],env=n.env,stdout=log,stderr=log)
 def stop():
  if p.poll() is None:p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 stack.callback(stop);end=time.monotonic()+10
 while time.monotonic()<end and not n.socket.is_socket():
  assert p.poll() is None;time.sleep(.05)
 s=f.rpc(n,'mesh/status')['result'];assert s['local_peer_id']==n.peer and set(s['transports_active'])=={'local','iroh'};return p.pid
h=stamp();stime=utc()
with tempfile.TemporaryDirectory(prefix='ent-mdns-final-',dir='/tmp') as temp,ExitStack() as stack:
 root=Path(temp);coord=f.nodes.Node(root/'coordinator',bins);worker=f.nodes.Node(root/'worker',bins);coord.trust(worker);worker.trust(coord)
 worker.cli('keyring','add',coord.key,'--name','isolated fixture publisher')
 pkg=root/'package';coord.cli('plugins','build',repo/'examples/hello-world','--wasm',repo/'crates/entangle-host/tests/fixtures/hello-pong.wasm','--out',pkg)
 plugin=tomllib.loads((pkg/'entangle.toml').read_text())['plugin']['id'];wp=start(worker,stack);worker.cli('plugins','load',pkg);cp=start(coord,stack)
 assert f.rpc(coord,'plugins/list')['result']['plugins']==[]
 nonce=secrets.token_hex(10);end=time.monotonic()+45;miss=0
 while True:
  reply=f.job(coord,worker,plugin,nonce)
  if 'result' in reply:break
  assert f.is_miss(reply) and time.monotonic()<end,reply;miss+=1;time.sleep(.25)
 f.assert_result(reply,worker.peer,nonce)
 def sighting():
  records=f.rpc(coord,'mesh/peers')['result']['peers']
  return next(peer for peer in records if peer['peer_id']==worker.peer)
 seen=sighting();assert seen['trusted'] and seen['addresses']
 coord.cli('mesh','revoke',worker.peer);after=sighting();assert not after['trusted'] and after['addresses']
 denied=f.job(coord,worker,plugin,'after-revocation');assert 'error' in denied and any(s in denied['error']['message'] for s in ['no known network address','no live workers']),denied
 assert f.metric(worker)==1 and f.metric(coord)==0
 assert stamp()==h
 record=dict(source_commit=m['source_commit'],source_id=m['source_id'],source_before=m['source_id'],source_after=m['source_id'],started_utc=stime,finished_utc=utc(),reviewer='/root/tailroute',command=['python3','-B',str(Path(__file__).relative_to(repo))],exit_code=0,scope='Linux-host mDNS announcements and authenticated Iroh over a detected interface; two separate processes, no configured peer addresses, no public relay',artifact_sha256=h,archive_sha256=m['sha256'],driver_sha256=sha(Path(__file__)),fixture_sha256=sha(fixture),worker=worker.peer,coordinator=coord.peer,worker_pid=wp,coordinator_pid=cp,initial_placement_misses=miss,matching_nonce=True,discovered_addresses=len(seen['addresses']),post_revocation_sighting_still_present=True,post_revocation_dispatch_refused=True,total_worker_jobs=1,total_local_jobs=0)
with (here/'lan-mdns-release.json').open('x') as out:json.dump(record,out,indent=2);print(file=out)
print('Release daemon live mDNS dispatch and revocation passed.')
