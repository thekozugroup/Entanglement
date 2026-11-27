"""Exercise signed Iroh jobs in both directions on an internal rootless Docker bridge."""
import datetime,hashlib,json,re,secrets,subprocess,time
from contextlib import ExitStack
from pathlib import Path
proof=Path(__file__).resolve().parent
state=json.loads((proof/'provision.json').read_text())
manifest=json.loads((proof/'linux-archive.json').read_text())
work=Path(state['workspace'])
bins,sample,frozen=work/'archive-bins',work/'sample',work/'frozen'
archive=Path('/workspace/Entanglement/target/release-candidate/a0926c6ef347-ubuntu22')/manifest['name']
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def stamp():
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=frozen,text=True).strip()==state['commit']
    value=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=frozen,text=True).strip()
    assert value==manifest['source_id']
    return value
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def call(argv,check=True,**kw):
    return subprocess.run(argv,check=check,text=True,capture_output=True,timeout=30,**kw)
def get(*argv):return call(list(argv)).stdout.strip()
before=stamp();started=utc();token=secrets.token_hex(5);network='ent-glibc-'+token
assert sha(archive)==manifest['sha256']
for f in ('entangle','entangled'):assert sha(bins/f)==manifest['files_sha256'][f]
assert 'name=rootless' in json.loads(get('docker','info','--format','{{json .SecurityOptions}}'))
reports={};directions=[];cleanup=[];processes={}
def release(command):
    result=call(command,check=False);cleanup.append(dict(command=command,exit_code=result.returncode,stderr=result.stderr.strip()))
def ex(role,*args):return ['docker','exec',reports[role]['container'],*args]
def cli(role,*args):return ex(role,'/candidate/entangle',*args)
with ExitStack() as stack:
    net_id=get('docker','network','create','--internal','--driver=bridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false',network)
    stack.callback(release,['docker','network','rm',network])
    net=json.loads(get('docker','network','inspect',network))[0]
    assert net['Id']==net_id and net['Internal'] and net['Driver']=='bridge' and not net['EnableIPv6']
    for role,tag,version,libc in [('jammy','ubuntu:22.04','22.04','2.35'),('bookworm','debian:bookworm-slim','12','2.36')]:
        image=json.loads(get('docker','image','inspect',tag))[0]
        c=get('docker','run','--pull=never','-d','--network',network,'--cap-drop=ALL','--security-opt=no-new-privileges','--read-only',
            '--env','HOME=/tmp/home','--env','ENTANGLE_ALLOW_LOCAL=0','--env','TOKIO_WORKER_THREADS=2','--env','RAYON_NUM_THREADS=2',
            '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=256m','--mount',f'type=bind,src={bins},dst=/candidate,readonly',
            '--mount',f'type=bind,src={sample},dst=/input,readonly',image['Id'],'sleep','infinity')
        stack.callback(release,['docker','rm','-f',c])
        inspected=json.loads(get('docker','inspect',c))[0];ns=inspected['NetworkSettings']
        assert set(ns['Networks'])=={network} and not ns['Ports'] and not inspected['HostConfig']['PortBindings']
        node=reports[role]=dict(image=image['RepoDigests'],container=c,ip=ns['Networks'][network]['IPAddress'],published_ports=ns['Ports'],version=version,glibc=libc)
        assert get(*ex(role,'sh','-ec','. /etc/os-release && echo "$VERSION_ID" && getconf GNU_LIBC_VERSION'))==version+'\nglibc '+libc
        routes=get(*ex(role,'cat','/proc/net/route'))
        assert not any(line.split()[1]=='00000000' for line in routes.splitlines()[1:]),routes
        node['kernel_ipv4_routes']=routes
        node['executables']={}
        for name in ('entangle','entangled'):
            dig=get(*ex(role,'sha256sum','/candidate/'+name)).split()[0]
            assert dig==manifest['files_sha256'][name]
            node['executables'][name]=dig
        get(*ex(role,'mkdir','-m','700','/tmp/home'))
        get(*cli(role,'init','--non-interactive'))
        build=get(*cli(role,'plugins','build','/input','--wasm','/input/hello.wasm','--out','/tmp/hello-signed'))
        node['public']=re.search(r'entangle keyring add ([a-f0-9]{64}) --name',build)[1]
        node['plugin']=re.search(r'entangle plugins invoke ([^ ]+) --input',build)[1]
        node['peer']=node['plugin'].split('/')[0]
        assert re.fullmatch(r'[a-f0-9]{32}',node['peer'])
        get(*cli(role,'keyring','add',node['public'],'--name','Local fixture publisher'))
    assert reports['jammy']['peer']!=reports['bookworm']['peer']
    def supervise(role):
        handle=processes[role]
        if handle.poll() is None:
            release(ex(role,'sh','-ec','kill -TERM "$(cat /tmp/daemon.pid)"'))
            handle.wait(12)
        reports[role]['graceful_exit']=handle.returncode
    for role,other in [('jammy','bookworm'),('bookworm','jammy')]:
        node,peer=reports[role],reports[other]
        get(*cli(role,'mesh','trust',peer['peer'],'--public-key-hex',peer['public'],'--display-name',other))
        node['config']='[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nrelay=false\nbind='+json.dumps(node['ip']+':7443')+'\npeers='+json.dumps([peer['public']+'@'+peer['ip']+':7443'])+'\n'
        call(['docker','exec','-i',node['container'],'sh','-ec','cat > "$HOME/.entangle/config.toml"'],input=node['config'])
        log=stack.enter_context((proof/('cross-'+role+'-daemon.log')).open('x'))
        processes[role]=subprocess.Popen(ex(role,'sh','-ec','echo $$ >/tmp/daemon.pid; exec /candidate/entangled run'),stdout=log,stderr=subprocess.STDOUT)
        stack.callback(supervise,role)
        deadline=time.monotonic()+45
        while True:
            assert processes[role].poll() is None,'daemon exited'
            s=call(cli(role,'mesh','status','--json'),check=False)
            if s.returncode==0:
                initial=json.loads(s.stdout)
                if initial['transports_active']==['iroh']:break
            assert time.monotonic()<deadline,(role,s.returncode,s.stderr)
            time.sleep(.15)
        assert initial['local_peer_id']==node['peer'] and initial['trusted_peer_count']==1,initial
        node['initial_mesh_status']=initial
    for coord,worker in [('jammy','bookworm'),('bookworm','jammy')]:
        target=reports[worker];plugin=target['plugin'];nonce=secrets.token_hex(16)
        empty=json.loads(get(*cli(coord,'plugins','list','--json')))
        assert empty['plugins']==[],(coord,empty)
        initial_worker=json.loads(get(*cli(worker,'plugins','list','--json')))
        assert initial_worker['plugins']==[]
        def calls():
            metrics=get(*cli(worker,'metrics'))
            return sum(int(value) for value in re.findall(r'(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$',metrics))
        initial_count=calls()
        unavailable=call(cli(coord,'compute','dispatch',plugin,'--raw','--input','before-load','--timeout-ms','5000','--cpu-cores','0.01','--integrity','trusted-executor','--allow',target['peer']),check=False)
        assert unavailable.returncode!=0 and ('no live workers' in unavailable.stderr or 'no worker satisfies' in unavailable.stderr),unavailable.stderr
        assert initial_count==calls()
        get(*cli(worker,'plugins','load','/tmp/hello-signed'))
        inventory=json.loads(get(*cli(worker,'plugins','list','--json')))
        assert len(inventory['plugins'])==1 and plugin in str(inventory)
        cmd=cli(coord,'compute','dispatch',plugin,'--raw','--input',nonce,'--timeout-ms','5000','--cpu-cores','0.01','--integrity','trusted-executor','--allow',target['peer'])
        retries=[];t0=time.monotonic()
        while True:
            run=call(cmd,check=False)
            if run.returncode==0:break
            raise AssertionError(f'initial dispatch failed: {run.returncode} {run.stderr!r}')
        chosen=re.search(r'^Chosen: ([a-f0-9]{32}) ',run.stderr,re.M)[1]
        assert chosen==target['peer'] and run.stdout=='Hello, '+nonce+'!'
        remote_log=(proof/('cross-'+worker+'-daemon.log')).read_text()
        assert plugin in remote_log
        count_after=calls()
        assert count_after==initial_count+1
        directions.append(dict(before_load_error=unavailable.stderr,before_load_exit=unavailable.returncode,worker_completions_before=initial_count,worker_completions_after=count_after,worker_initial_inventory=initial_worker,coordinator=coord,worker=worker,coordinator_inventory=empty,worker_inventory=inventory,command=cmd,
                               input=nonce,expected='Hello, '+nonce+'!',actual=run.stdout,selected_peer=chosen,expected_peer=target['peer'],
                               cli_diagnostic=run.stderr,elapsed_s=round(time.monotonic()-t0,4),retries=retries))
        get(*cli(worker,'plugins','unload',plugin))
    assert all(p.poll() is None for p in processes.values())
assert all(c['exit_code']==0 for c in cleanup) and all(n['graceful_exit']==0 for n in reports.values()),cleanup
assert not get('docker','network','ls','--filter','id='+net_id,'--format','{{.ID}}')
for node in reports.values():assert not get('docker','ps','-aq','--filter','id='+node['container'])
r=dict(source_before=before,source_id=before,source_after=stamp(),source_commit=state['commit'],archive_sha256=manifest['sha256'],wasm_sha256=sha(sample/'hello.wasm'),
       started_utc=started,finished_utc=utc(),scope='two rootless amd64 Linux containers on one physical host, direct authenticated Iroh on an isolated bridge',
       network=dict(name=network,id=net_id,internal=net['Internal'],options=net['Options']),nodes=reports,dispatches=directions,cleanup=cleanup,
       daemon_log_sha256={role:sha(proof/('cross-'+role+'-daemon.log')) for role in reports},exit_code=0)
with (proof/'cross-userspace.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
print([(d['coordinator'],d['selected_peer'],d['actual']) for d in directions])
