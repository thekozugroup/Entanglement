"""Run an ordinary signed Wasm plugin with both archive executables in disconnected userspaces."""
import datetime,hashlib,json,os,re,secrets,shutil,subprocess,tempfile,time
from pathlib import Path
proof=Path(__file__).resolve().parent
state=json.loads((proof/'provision.json').read_text());manifest=json.loads((proof/'linux-archive.json').read_text())
work=Path(state['workspace']);frozen=work/'frozen';bins=work/'archive-bins'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def cap(cmd,**kwargs):return subprocess.run(cmd,timeout=30,capture_output=True,text=True,**kwargs)
def get(cmd):return cap(cmd,check=True).stdout.strip()
def stamp():
    val=get(['git','-C',str(frozen),'rev-parse','HEAD'])
    assert val==manifest['source_commit']
    s=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=frozen,text=True).strip()
    assert s==manifest['source_id'];return s
before=stamp();start=utc()
sample=work/'sample';sample.mkdir();sample.chmod(0o755)
for name,p in [('entangle.toml',frozen/'examples/hello-world/entangle.toml'),('hello.wasm',frozen/'crates/entangle-host/tests/fixtures/hello-pong.wasm')]:
    shutil.copyfile(p,sample/name);(sample/name).chmod(0o444)
floors={};dependencies={}
for exe in ('entangle','entangled'):
    assert sha(bins/exe)==manifest['files_sha256'][exe]
    table=get(['readelf','--version-info',str(bins/exe)])
    syms=get(['readelf','--dyn-syms','--wide',str(bins/exe)])
    versions=re.findall(r'Name: GLIBC_([\d.]+)',table)
    floors[exe]=max(versions,key=lambda x:tuple(map(int,x.split('.'))))
    assert tuple(map(int,floors[exe].split('.')))<=(2,35)
    dependencies[exe]=dict(pidfd_imports=[s.strip() for s in syms.splitlines() if 'pidfd_spawnp' in s or 'pidfd_getpid' in s],
                           needed=[s.strip() for s in get(['readelf','-d',str(bins/exe)]).splitlines() if 'NEEDED' in s])
reports={}
for tag,version,lib in [('ubuntu:22.04','22.04','2.35'),('debian:bookworm-slim','12','2.36')]:
    im=json.loads(get(['docker','image','inspect',tag]))[0]
    create=['docker','run','-d','--pull=never','--network=none','--cap-drop=ALL','--read-only','--security-opt=no-new-privileges',
            '--env','HOME=/tmp/entangle-home','--env','ENTANGLE_ALLOW_LOCAL=0','--env','TOKIO_WORKER_THREADS=2','--env','RAYON_NUM_THREADS=2',
            '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=256m','--mount',f'type=bind,src={bins},dst=/candidate,readonly','--mount',f'type=bind,src={sample},dst=/input,readonly',
            im['Id'],'sleep','infinity']
    c=get(create)
    def ex(*args):return ['docker','exec',c,*args]
    daemon=None
    try:
        assert get(ex('sh','-ec','. /etc/os-release && echo "$VERSION_ID" && getconf GNU_LIBC_VERSION'))==version+'\nglibc '+lib
        assert get(['docker','inspect',c,'--format','{{.HostConfig.NetworkMode}}'])=='none'
        for exe in ('entangle','entangled'):
            assert get(ex('/candidate/'+exe,'--version'))==exe+' 0.1.0'
            assert get(ex('sha256sum','/candidate/'+exe)).split()[0]==manifest['files_sha256'][exe]
        cli='/candidate/entangle'
        get(ex('mkdir','-m','700','/tmp/entangle-home'))
        get(ex(cli,'init','--non-interactive'))
        get(ex('sh','-ec','printf "[mesh]\\ntransports=[]\\n" > "$HOME/.entangle/config.toml"'))
        created=get(ex(cli,'plugins','build','/input','--wasm','/input/hello.wasm','--out','/tmp/signed-hello'))
        public=re.search(r'entangle keyring add ([a-f0-9]{64}) --name',created)[1]
        plugin=re.search(r'entangle plugins invoke ([^ ]+) --input',created)[1]
        log=proof/(tag.replace(':','-')+'-daemon.log')
        with log.open('x') as fout:
            daemon=subprocess.Popen(ex('sh','-ec','echo $$ >/tmp/daemon.pid; exec /candidate/entangled run'),stdout=fout,stderr=subprocess.STDOUT)
            for _ in range(150):
                if cap(ex('test','-S','/tmp/entangle-home/.entangle/sock')).returncode==0:break
                assert daemon.poll() is None;time.sleep(.05)
            else:raise RuntimeError('no UDS')
            status=json.loads(get(ex(cli,'mesh','status','--json')))
            assert re.fullmatch(r'[a-f0-9]{32}',status['local_peer_id'])
            denied=cap(ex(cli,'plugins','load','/tmp/signed-hello'))
            assert denied.returncode and re.search(r'(trust|publisher|keyring|verification key)',denied.stderr,re.I),denied
            get(ex(cli,'keyring','add',public,'--name','disposable fixture publisher'))
            load=get(ex(cli,'plugins','load','/tmp/signed-hello'))
            nonce=secrets.token_hex(16)
            expected='Hello, '+nonce+'!'
            raw=cap(ex(cli,'plugins','invoke',plugin,'--input',nonce,'--raw'),check=True)
            assert raw.stdout==expected,raw
            get(ex('sh','-ec','kill -TERM "$(cat /tmp/daemon.pid)"'))
            assert daemon.wait(15)==0
        reports[tag]=dict(image_id=im['Id'],digest=im['RepoDigests'],version=version,glibc=lib,command=create,network='none',versions=['entangle 0.1.0','entangled 0.1.0'],daemon_log_sha256=sha(log),local_rpc=status,denied_before_trust=dict(exit_code=denied.returncode,stderr=denied.stderr),publisher_public=public,plugin=plugin,success_load=load,input=nonce,expected=expected,actual=raw.stdout,graceful_exit=daemon.returncode)
    finally:
        subprocess.run(['docker','rm','-f',c],capture_output=True)
        if daemon and daemon.poll() is None:daemon.wait(15)
record=dict(source_id=before,source_before=before,source_after=stamp(),source_commit=state['commit'],archive_sha256=manifest['sha256'],
            cli_sha256=manifest['files_sha256']['entangle'],daemon_sha256=manifest['files_sha256']['entangled'],sample_wasm_sha256=sha(sample/'hello.wasm'),
            started=start,finished=utc(),highest_required_glibc=floors,dynamic_link_details=dependencies,scope='one x86-64 Linux host, distinct disconnected Jammy and Bookworm userspaces',distro_workloads=reports,exit_code=0)
with (proof/'workload.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(floors,list(reports))
