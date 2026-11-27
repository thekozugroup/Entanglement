#!/usr/bin/env python3
"""Read-only guest filesystem conformance on synthetic local fixtures."""
import hashlib,json,os,pathlib,platform,subprocess,tempfile,time,datetime,tomllib
E=pathlib.Path(__file__).resolve().parent; R=next(p for p in E.parents if (p/'scripts/production_score.py').is_file()); B=R/'target/release'; guest=E/'fs-probe'; wasm=pathlib.Path(os.environ.get('CARGO_TARGET_DIR','/tmp/entangle-fs-probe-target'))/'wasm32-wasip2/release/fs_conformance_probe.wasm'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def source(): return subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=R,text=True).strip()
def fixture_state(p):
 return {'directory_mode':p.stat().st_mode & 0o777,'names':sorted(x.name for x in p.iterdir()),'file_sha256':sha(p/'fixture.txt'),'file_mode':(p/'fixture.txt').stat().st_mode & 0o777,'link_target':os.readlink(p/'fixture-link')}
start=stamp(); src=source(); assert src=='sha256:2a5db79622c3130c68614ca443ad93b86efec77c11bb5b4e84f6ad7c02277c68'
before={k:sha(B/k) for k in ('entangle','entangled')}; expected={'entangle':'dace32646d0a67e08385db6a7d9fd8425a2d530fe966cbc438ace0ba38737895','entangled':'5e11e7af5eae74c8cbec3f140e7322b98b9f5910cdb8cd269b53f9ae6d2b73f9'}; assert before==expected
with tempfile.TemporaryDirectory(prefix='entangle-wasi-fs-conformance-') as t:
 t=pathlib.Path(t); home=t/'home'; home.mkdir(); fixture=t/'host-fixture'; fixture.mkdir(); (fixture/'fixture.txt').write_bytes(b'synthetic public fixture\n'); (fixture/'fixture-link').symlink_to('fixture.txt'); prior=fixture_state(fixture)
 env={**os.environ,'HOME':str(home),'TOKIO_WORKER_THREADS':'2'}; env.pop('ENTANGLE_ALLOW_LOCAL',None)
 def cli(*args):
  p=subprocess.run([str(B/'entangle'),*map(str,args)],env=env,capture_output=True,text=True,timeout=90)
  if p.returncode: raise RuntimeError(f'{args}: exit={p.returncode} stderr={p.stderr}')
  return p.stdout
 cli('init','--non-interactive'); state=home/'.entangle'; (state/'config.toml').write_text('[mesh]\ntransports = []\n'); daemon_log=(t/'daemon.log').open('w'); daemon=subprocess.Popen([str(B/'entangled'),'run'],env=env,stdout=daemon_log,stderr=subprocess.STDOUT)
 try:
  deadline=time.monotonic()+15
  while not (state/'sock').is_socket():
   if daemon.poll() is not None or time.monotonic()>deadline: raise RuntimeError('daemon failed to start')
   time.sleep(.05)
  cli('plugins','install','fs-probe','--catalog',E,'--wasm',wasm)
  pkg=state/'plugins/fs-probe'; plugin=tomllib.loads((pkg/'entangle.toml').read_text())['plugin']['id']; signature_sha256=sha(pkg/'plugin.wasm.sig'); installed_component_sha256=sha(pkg/'plugin.wasm'); assert installed_component_sha256==sha(wasm)
  result=cli('plugins','invoke',plugin,'--input',str(fixture),'--raw'); values=dict(line.split('=',1) for line in result.strip().splitlines())
  assert values['preopen_count']=='0', values
  keys=['root_metadata','root_read_dir','file_metadata','file_read','link_metadata','link_read','trailing_slash_metadata']
  assert all(values[k]=='false' for k in keys),values
  after=fixture_state(fixture); assert prior==after
 finally:
  daemon.terminate()
  try: daemon.wait(timeout=5)
  except subprocess.TimeoutExpired: daemon.kill();daemon.wait()
  daemon_log.close()
end=stamp(); final=source(); hashes={k:sha(B/k) for k in before}; assert final==src and hashes==before
out={'source_before':src,'source_after':final,'started_utc':start,'finished_utc':end,'platform':platform.platform(),'binaries_sha256':hashes,'plugin_id':plugin,'signed_plugin_signature_sha256':signature_sha256,'installed_component_sha256':installed_component_sha256,'runner_sha256':sha(pathlib.Path(__file__)),'guest_wasm_sha256':sha(wasm),'guest_source_sha256':sha(guest/'src/lib.rs'),'guest_lock_sha256':sha(guest/'Cargo.lock'),'fixture_before':prior,'fixture_after':after,'guest_report':values,'operations':'Read-only metadata, directory enumeration, file read, symlink metadata/readlink, trailing slash metadata. No write, rename, escape attempt or credentials.','limitations':'Linux x86_64 optimized candidate only; no filesystem preopens, no granted-root permissions test, no rename test and no macOS. Host fixture path is synthetic.','exit_code':0}
(E/'result.json').write_text(json.dumps(out,indent=2)+'\n'); print(json.dumps(out,indent=2))
