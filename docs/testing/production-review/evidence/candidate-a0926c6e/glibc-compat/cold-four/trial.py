"""Exercise signed Iroh jobs in both directions on an internal rootless Docker bridge."""
import datetime,hashlib,json,re,secrets,subprocess,time
from contextlib import ExitStack
from pathlib import Path
proof=Path(__file__).resolve().parents[1]
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
before=stamp();started=utc();token=secrets.token_hex(5);network='ent-cold4-'+token
assert sha(archive)==manifest['sha256']
for f in ('entangle','entangled'):assert sha(bins/f)==manifest['files_sha256'][f]
assert 'name=rootless' in json.loads(get('docker','info','--format','{{json .SecurityOptions}}'))
reports={};directions=[];cleanup=[];processes={}
def release(command):
    result=call(command,check=False);cleanup.append(dict(command=command,exit_code=result.returncode,stderr=result.stderr.strip()))
def ex(role,*args):return ['docker','exec',reports[role]['container'],*args]
def cli(role,*args):return ex(role,'/candidate/entangle',*args)
trial=int(__import__('sys').argv[1])
assert 1<=trial<=4
trialdir=Path(__file__).resolve().parent/('trial-'+str(trial));trialdir.mkdir()
catalogs={}
def record(phase,**data):
    with (trialdir/'events.jsonl').open('a') as f:f.write(json.dumps(dict(utc=utc(),monotonic_ns=time.monotonic_ns(),phase=phase,**data))+'\n')
def catalog_stop(role):
    obs=catalogs[role]
    data=call(['docker','logs',obs],check=False)
    (trialdir/(role+'-catalog.jsonl')).write_text(data.stdout)
    (trialdir/(role+'-catalog.stderr')).write_text(data.stderr)
    release(['docker','rm','-f',obs])
with ExitStack() as stack:
    net_id=get('docker','network','create','--internal','--driver=bridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false',network)
    stack.callback(release,['docker','network','rm',network])
    net=json.loads(get('docker','network','inspect',network))[0]
    assert net['Id']==net_id and net['Internal'] and net['Driver']=='bridge' and not net['EnableIPv6']
    for role,tag,version,libc in [('jammy','ubuntu:22.04','22.04','2.35'),('bookworm','debian:bookworm-slim','12','2.36')]:
        image=json.loads(get('docker','image','inspect',tag))[0]
        c=get('docker','run','--pull=never','-d','--network',network,'--cap-drop=ALL','--security-opt=no-new-privileges','--read-only',
            '--env','RUST_LOG=info,entangle_bin::capabilities=debug,entangle_scheduler=debug','--env','HOME=/tmp/home','--env','ENTANGLE_ALLOW_LOCAL=0','--env','TOKIO_WORKER_THREADS=2','--env','RAYON_NUM_THREADS=2',
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
        obsimage=json.loads(get('docker','image','inspect','python:3.12-slim-trixie'))[0]
        private=Path(__file__).resolve().with_name('catalog.py')
        observer=get('docker','run','-d','--pull=never','--read-only','--network','container:'+c,'--cap-drop=ALL','--security-opt=no-new-privileges',
                     '--mount',f'type=bind,src={private},dst=/catalog.py,readonly',obsimage['Id'],'python3','-B','-u','/catalog.py')
        catalogs[role]=observer;node['catalog_image_id']=obsimage['Id'];node['catalog_container']=observer
        stack.callback(catalog_stop,role)
        limit=time.monotonic()+12
        while 'ready' not in get('docker','logs',observer):
            assert time.monotonic()<limit
            time.sleep(.03)
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
        node['config']+='[security]\nmax_tier_allowed=5\n[runtime.inference]\nendpoint="http://127.0.0.1:18678/v1/chat/completions"\nmodel="cold-empty-catalog-observer"\n'
        call(['docker','exec','-i',node['container'],'sh','-ec','cat > "$HOME/.entangle/config.toml"'],input=node['config'])
        log=stack.enter_context((trialdir/(role+'-daemon.log')).open('x'))
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
        node['initial_mesh_status']=initial;node['listener_ready_ns']=time.monotonic_ns();node['listener_ready_utc']=utc();record('listener_confirmed',role=role,mesh=initial)
    coord,worker='jammy','bookworm'
    target=reports[worker];plugin=target['plugin']
    initial={}
    for role in (coord,worker):
        initial[role]=json.loads(get(*cli(role,'plugins','list','--json')))
        assert initial[role]['plugins']==[]
    def counts():
        text=get(*cli(worker,'metrics'))
        return sum(int(n) for n in re.findall(r'(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$',text))
    def dispatch(phase,nonce):
        cmd=cli(coord,'compute','dispatch',plugin,'--raw','--input',nonce,'--timeout-ms','5000','--cpu-cores','0.01','--integrity','trusted-executor','--allow',target['peer'])
        start=time.monotonic_ns();start_utc=utc()
        record('request_start',label=phase,nonce=nonce)
        response=call(cmd,check=False)
        finish=time.monotonic_ns();end_utc=utc()
        chosen=re.search(r'^Chosen: ([a-f0-9]{32}) ',response.stderr,re.M)
        r=dict(phase=phase,input=nonce,expected='Hello, '+nonce+'!',expected_peer=target['peer'],chosen=chosen[1] if chosen else None,command=cmd,
               start_ns=start,stop_ns=finish,start_utc=start_utc,stop_utc=end_utc,elapsed_ms=(finish-start)/1e6,
               listener_age_start_ms={r:(start-x['listener_ready_ns'])/1e6 for r,x in reports.items()},exit_code=response.returncode,stdout=response.stdout,stderr=response.stderr)
        r['verified']=r['exit_code']==0 and r['chosen']==r['expected_peer'] and r['stdout']==r['expected']
        record('request_end',label=phase,result=r)
        return r
    initial_count=counts()
    pre=dispatch('missing-before-load','before-load')
    assert pre['exit_code']!=0 and any(m in pre['stderr'] for m in ('no live workers','no worker satisfies')),pre
    assert counts()==initial_count
    load_start=time.monotonic_ns();load_start_utc=utc()
    loaded=get(*cli(worker,'plugins','load','/tmp/hello-signed'))
    load_stop=time.monotonic_ns();load_stop_utc=utc()
    record('load_finished',start_ns=load_start,stop_ns=load_stop,start_utc=load_start_utc,stop_utc=load_stop_utc,stdout=loaded)
    inventory=json.loads(get(*cli(worker,'plugins','list','--json')))
    assert len(inventory['plugins'])==1 and plugin in str(inventory)
    first=dispatch('first-after-load',secrets.token_hex(16))
    after=counts()
    if first['exit_code']==0:
        assert first['verified'] and after==initial_count+1
    else:
        assert first['stdout']=='' and after==initial_count
    recovery=None
    if first['exit_code']!=0:
        # Only failed first jobs get one separate nonce, scheduled relative to the first attempt.
        deadline=first['start_ns']/1e9+10
        time.sleep(max(0,deadline-time.monotonic()))
        second_nonce=secrets.token_hex(16);assert second_nonce!=first['input']
        recovery=dispatch('distinct-after-failure',second_nonce)
        assert recovery['verified'] or recovery['exit_code']!=0
        assert counts()==after+int(recovery['verified'])
    directions.append(dict(preload_control=pre,initial_inventories=initial,loaded_workers=inventory,load_start_ns=load_start,load_stop_ns=load_stop,load_start_utc=load_start_utc,load_stop_utc=load_stop_utc,
                           load_stop_to_first_start_ms=(first['start_ns']-load_stop)/1e6,load_stop_to_first_end_ms=(first['stop_ns']-load_stop)/1e6,first_submission=first,
                           remote_executions_before=initial_count,remote_executions_after_first=after,followup=recovery))
    assert all(p.poll() is None for p in processes.values())
assert all(c['exit_code']==0 for c in cleanup) and all(n['graceful_exit']==0 for n in reports.values()),cleanup
assert not get('docker','network','ls','--filter','id='+net_id,'--format','{{.ID}}')
for container in [*(node['container'] for node in reports.values()),*catalogs.values()]:
    assert not get('docker','ps','-aq','--filter','id='+container)
r=dict(source_before=before,source_id=before,source_after=stamp(),source_commit=state['commit'],archive_sha256=manifest['sha256'],wasm_sha256=sha(sample/'hello.wasm'),
       started_utc=started,finished_utc=utc(),scope='Two rootless amd64 Linux application containers on one host, each with a loopback-only empty models observer sharing its network namespace; direct authenticated Iroh on an internal bridge',
       network=dict(name=network,id=net_id,internal=net['Internal'],options=net['Options']),nodes=reports,dispatches=directions,cleanup=cleanup,
       daemon_log_sha256={role:sha(trialdir/(role+'-daemon.log')) for role in reports},exit_code=0)
r.update(trial=trial,whole_pair_first_submission_passed=directions[0]['first_submission']['verified'],catalog_sha256={r:sha(trialdir/(r+'-catalog.jsonl')) for r in catalogs},catalog_observation='Only one trusted peer on each node. GET /v1/models on its private loopback is called after authorized capability request and plugin inventory snapshot, before QUIC report acknowledgement; proves server-side request handling only.')
with (trialdir/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
print(trial,r['whole_pair_first_submission_passed'],flush=True)
