"""Independent POSIX installer and installed-binary checks on older glibc userspaces.

Uses a local-only URL fixture and OpenSSL checksum; requires preloaded Docker images.
The fixture archive is an unsigned supplemental build, not a production release.
"""
import datetime, hashlib, json, os, re, runpy, shutil, subprocess, sys, tarfile, tempfile, time
from pathlib import Path
P=Path(__file__).resolve().parent
R=P.parents[5]
C='bb70a6193f8879b1feb3e6d3ceb8f2980413ce58'
S='sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab'
A=R/'target/release-candidate/bb70a6193f88-ubuntu22/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz'
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def run(args,**kw):return subprocess.run(args,timeout=40,capture_output=True,text=True,**kw)
def get(args):
 r=run(args)
 if r.returncode:raise RuntimeError(f'{args!r}: exit {r.returncode}; stdout={r.stdout!r}; stderr={r.stderr!r}')
 return r.stdout.strip()
def source():
 assert run(['git','-C',str(R),'merge-base','--is-ancestor',C,'HEAD']).returncode==0
 s=run([sys.executable,str(R/'scripts/production_score.py'),'--source-id'],cwd=R,check=True).stdout.strip();assert s==S;return s
start=now(); before=source(); m=json.loads(A.with_name('verification.json').read_text())
assert m['source_commit']==C and m['source_id']==m['source_after']==S and sha(A)==m['sha256']
assert get(['openssl','dgst','-sha256',str(A)]).split()[-1]==m['sha256']
with tarfile.open(A,'r:gz') as t:
 entries={x.name for x in t.getmembers() if x.isfile()}
 assert all(any(x.endswith('/'+n) for x in entries) for n in ('entangle','entangled'))
fixture=R/'docs/testing/production-review/evidence/candidate-bb70a619/installer-fixture.py'
case=runpy.run_path(str(fixture))['case'];reports={}
with tempfile.TemporaryDirectory(prefix='supplemental-installer-',dir='/tmp') as td:
 temp=Path(td);case(temp/'install',R/'scripts/install.sh','linux','x86_64','x86_64-unknown-linux-gnu','openssl','v0.1.0','positive',A)
 bins=temp/'install/home/install/bin'
 for directory in (temp,temp/'install',temp/'install/home',temp/'install/home/install',bins):directory.chmod(0o755)
 sample=temp/'sample';sample.mkdir(mode=0o755);sample.chmod(0o755)
 for name,src in [('entangle.toml',R/'examples/hello-world/entangle.toml'),('hello.wasm',R/'crates/entangle-host/tests/fixtures/hello-pong.wasm')]:
  shutil.copyfile(src,sample/name);(sample/name).chmod(0o444)
 for n in ('entangle','entangled'):assert sha(bins/n)==m['files_sha256'][n]
 for tag,version in [('ubuntu:22.04','22.04'),('debian:bookworm-slim','12')]:
  image=json.loads(get(['docker','image','inspect',tag]))[0]
  cmd=['docker','run','-d','--pull=never','--network=none','--cap-drop=ALL','--read-only','--security-opt=no-new-privileges','--env','HOME=/tmp/home','--env','TOKIO_WORKER_THREADS=2','--env','RAYON_NUM_THREADS=2','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=256m','--mount',f'type=bind,src={bins},dst=/installed,readonly','--mount',f'type=bind,src={sample},dst=/sample,readonly',image['Id'],'sleep','infinity']
  container=get(cmd);daemon=None
  def ex(*args):return ['docker','exec',container,*args]
  try:
   assert get(ex('sh','-ec','. /etc/os-release; echo "$VERSION_ID"'))==version
   assert get(['docker','inspect',container,'--format','{{.HostConfig.NetworkMode}}'])=='none'
   for n in ('entangle','entangled'):
    assert get(ex('/installed/'+n,'--version'))==n+' 0.1.0'
    assert get(ex('sha256sum','/installed/'+n)).split()[0]==m['files_sha256'][n]
   get(ex('mkdir','-m','700','/tmp/home'));cli='/installed/entangle';get(ex(cli,'init','--non-interactive'))
   get(ex('sh','-ec','printf "[mesh]\\ntransports=[]\\n" > "$HOME/.entangle/config.toml"'))
   out=get(ex(cli,'plugins','build','/sample','--wasm','/sample/hello.wasm','--out','/tmp/signed'))
   key=re.search(r'entangle keyring add ([a-f0-9]{64}) --name',out)[1];plugin=re.search(r'entangle plugins invoke ([^ ]+) --input',out)[1]
   daemon=subprocess.Popen(ex('sh','-ec','echo $$ >/tmp/daemon.pid; exec /installed/entangled run'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   deadline=time.monotonic()+15
   while run(ex('test','-S','/tmp/home/.entangle/sock')).returncode:
    assert daemon.poll() is None and time.monotonic()<deadline;time.sleep(.05)
   status=json.loads(get(ex(cli,'mesh','status','--json')));assert re.fullmatch(r'[a-f0-9]{32}',status['local_peer_id'])
   denied=run(ex(cli,'plugins','load','/tmp/signed'));assert denied.returncode and re.search(r'trust|publisher|keyring|verification key',denied.stderr,re.I)
   get(ex(cli,'keyring','add',key,'--name','independent disposable key'));get(ex(cli,'plugins','load','/tmp/signed'))
   nonce='independent-supplemental-check'; result=get(ex(cli,'plugins','invoke',plugin,'--input',nonce,'--raw'));assert result=='Hello, '+nonce+'!'
   get(ex('sh','-ec','kill -TERM "$(cat /tmp/daemon.pid)"'));assert daemon.wait(15)==0
   reports[tag]=dict(image_id=image['Id'],version=version,network='none',post_install_binary_sha256=m['files_sha256'],denied_before_trust_exit=denied.returncode,nonce=nonce,output=result,daemon_exit=0)
  finally:
   subprocess.run(['docker','rm','-f',container],capture_output=True)
   if daemon and daemon.poll() is None:daemon.wait(15)
res=dict(started_utc=start,finished_utc=now(),source_before=before,source_after=source(),source_commit=C,review_head=get(['git','-C',str(R),'rev-parse','HEAD']),archive_sha256=sha(A),installer_sha256=sha(R/'scripts/install.sh'),fixture_sha256=sha(fixture),runner_sha256=sha(Path(__file__)),openssl_sha256=sha(Path(shutil.which('openssl'))),archive_files=sorted(entries),userspaces=reports,scope='One x86-64 host, two isolated older GNU/Linux userlands, supplemental unsigned local archive; no production release authentication or independent hardware claim.',exit_code=0)
with (P/'independent-install-check.json').open('x') as f:json.dump(res,f,indent=2);f.write('\n')
print(json.dumps(res,indent=2))
