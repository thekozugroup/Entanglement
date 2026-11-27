"""Release black box with three network-disabled Linux namespaces and two user-space links."""
import argparse, hashlib, importlib.util, json, os, re, secrets, subprocess, tempfile, time
from contextlib import ExitStack
from pathlib import Path
import concurrent.futures, datetime, socket, threading
proof=Path(__file__).resolve().parent
stream=proof/'attempts.jsonl'
writer_lock=threading.Lock()
def stamp_event(kind, **data):
    item={'event':kind,'mono_ns':time.monotonic_ns(),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**data}
    with writer_lock, stream.open('a') as out:
        out.write(json.dumps(item)+'\n')
    return item
def peer_snapshot(node, label):
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.settimeout(2);c.connect(str(node.socket))
            c.sendall(json.dumps({'jsonrpc':'2.0','id':1,'method':'mesh/peers','params':None}).encode()+b'\n')
            with c.makefile('rb') as f: response=json.loads(f.readline(1024*1024))
        rows=[{k:peer.get(k) for k in ('peer_id','trusted','addresses','port','version')} for peer in response['result']['peers']]
        stamp_event('mesh_snapshot',label=label,peers=rows)
    except Exception as problem:
        stamp_event('mesh_snapshot_error',label=label,error=str(problem))

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--bin-dir',type=Path,required=True)
ap.add_argument('--repo',type=Path,required=True)
ap.add_argument('--pacer',type=Path,required=True)
args = ap.parse_args()
repo=args.repo.resolve(strict=True)
bins=args.bin_dir.resolve(strict=True)
tools=importlib.util.spec_from_file_location('nodes',repo/'scripts/tests/distributed-rust-tests.py')
nodes=importlib.util.module_from_spec(tools)
tools.loader.exec_module(nodes)
image='python:3.12-slim-trixie'
wasm=repo/'plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm'

def run(*args,**kw):
    result = subprocess.run(args,capture_output=True,text=True,timeout=kw.pop('timeout',45),**kw)
    if result.returncode: raise RuntimeError(f'{args[:3]} exited {result.returncode}: {result.stderr[:1200]}')
    return result
def hash_file(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()
def exercise(root,stack):
    common=root/'routers';common.mkdir()
    names={r:'ent-upload-'+secrets.token_hex(6)+'-'+r for r in ('coordinator','fast','slow')}
    all_nodes={r:nodes.Node(root/r,bins) for r in names}
    c=all_nodes['coordinator']
    workers={r:all_nodes[r] for r in ('fast','slow')}
    c.cli('plugins','build',repo/'plugins/json-pointer','--wasm',wasm,'--out',root/'package')
    import tomllib
    package=tomllib.loads((root/'package/entangle.toml').read_text())['plugin']['id']
    for node in workers.values():
        c.trust(node)
        node.trust(c)
        node.cli('keyring','add',c.key,'--name','upload test publisher')
    for role,name in names.items():
        node=all_nodes[role]
        routes=[f"{n.key}@127.0.0.1:{port}" for n,port in zip(workers.values(),(17443,27443))] if role=='coordinator' else []
        (node.state/'config.toml').write_text('[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\n'
            +'bind="127.0.0.1:7443"\nrelay=false\npeers='+json.dumps(routes)+'\n')
        owner = run('docker','run','--rm','--network=none','--pull=never','-v',f'{node.directory}:/check:ro',image,'stat','-c','%u:%g','/check').stdout.strip()
        run('docker','create','--name',name,'--user',owner,'--pull=never','--network=none','--cap-drop','ALL',
            '--security-opt','no-new-privileges','-e','HOME=/home/test','-e','TOKIO_WORKER_THREADS=2',
            '-v',f'{node.directory}:/home/test','-v',f'{common}:/ipc','-v',f'{args.pacer.resolve()}:/pacer.py:ro',
            '-v',f'{root}/package:/package:ro','-v',f'{bins}/entangle:/usr/bin/entangle:ro',
            '-v',f'{bins}/entangled:/usr/bin/entangled:ro',image,'entangled','run')
        stack.callback(subprocess.run,['docker','rm','-f',name],capture_output=True)
        run('docker','start',name)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline and not node.socket.is_socket():time.sleep(.1)
        assert json.loads(node.cli('mesh','status','--json'))['local_peer_id']==node.peer
        if role!='coordinator':run('docker','exec',name,'entangle','plugins','load','/package')
    for role,port,rate in [('fast',17443,0),('slow',27443,8_000_000)]:
        for side,device in [('front','coordinator'),('back',role)]:
            run('docker','exec','-d',names[device],'python3','/pacer.py',side,role,'/ipc',str(port),str(rate))
    def topology():
        result={}
        for role,name in names.items():
            state=json.loads(run('docker','inspect',name).stdout)[0]
            assert state['State']['Running'] and state['HostConfig']['NetworkMode']=='none'
            assert state['State']['Pid']>0 and state['RestartCount']==0
            result[role]={'id':state['Id'],'daemon_pid':state['State']['Pid'],'mode':state['HostConfig']['NetworkMode']}
        return result
    initial_topology=topology()
    stamp_event('topology', topology=initial_topology, peers={r:n.peer for r,n in all_nodes.items()}, archive_members={n:hash_file(bins/n) for n in ('entangle','entangled')}, wasm_sha256=hash_file(wasm))
    events=[]
    def task(label,eligible,bytes_):
        nonce=secrets.token_hex(12)
        content=json.dumps({'data':{'value':nonce,'padding':'x'*bytes_},'pointer':'/value'})
        path=root/(nonce+'.json');path.write_text(content)
        argv=['compute','dispatch',package,'--input-file',str(path),'--raw','--timeout-ms','10000','--cpu-cores','0.01','--integrity','trusted-executor']
        for node in eligible:argv+=['--allow',node.peer]
        start=time.monotonic()
        ctx={'phase':label,'allowed':[n.peer for n in eligible],'input_bytes':len(content.encode()),'nonce':nonce}
        opened=stamp_event('dispatch_start',**ctx)
        try:
            result=subprocess.run([bins/'entangle',*argv],text=True,capture_output=True,env=c.env,timeout=30)
        except (OSError, subprocess.TimeoutExpired) as err:
            stamp_event('dispatch_exception',**ctx,start_ns=opened['mono_ns'],finish_ns=time.monotonic_ns(),error=repr(err))
            raise
        received=time.monotonic_ns()
        stamp_event('cli_reply',**ctx,start_ns=opened['mono_ns'],finish_ns=received,exit_code=result.returncode,raw_cli_stderr=result.stderr.strip(),output=result.stdout.strip())
        if result.returncode:
            stamp_event('dispatch_result',**ctx, start_ns=opened['mono_ns'],finish_ns=received,exit_code=result.returncode,actual_cli_stderr=result.stderr.strip(),no_workers=('no live workers' in result.stderr or 'no worker satisfies' in result.stderr))
            if 'no live workers' in result.stderr or 'no worker satisfies' in result.stderr:
                return None
            raise RuntimeError(result.stderr)
        assert result.stdout==json.dumps(nonce)
        chosen=re.search(r'^Chosen: ([a-f0-9]{32}) ',result.stderr,re.M)[1]
        assert chosen in {n.peer for n in eligible}
        reason=re.search(r'^Reason: (.*)$',result.stderr,re.M)[1]
        found=re.search(r'measured_upload_bps=(\d+|unknown)',reason)
        value=found[1] if found else None
        event={'phase':label,'chosen':chosen,'reason':reason,'measured_bps':int(value) if value and value!='unknown' else value,
               'input_bytes':len(content.encode()),'nonce':nonce,'output':result.stdout,'wall_s':round(time.monotonic()-start,4)}
        stamp_event('dispatch_result',**ctx,start_ns=opened['mono_ns'],finish_ns=received,exit_code=result.returncode,no_workers=False,chosen=chosen,reason=reason,raw_cli_stderr=result.stderr.strip(),measured_bps=event['measured_bps'],matching_nonce=True)
        events.append(event)
        print(label,chosen,event['measured_bps'],event['wall_s'],file=__import__('sys').stderr,flush=True)
        return event
    rates={}
    for role,worker in workers.items():
        deadline=time.monotonic()+35
        while not task(role+'-initial-small',[worker],100):
            if time.monotonic()>deadline:raise RuntimeError('no authenticated worker inventory')
            time.sleep(.5)
        first=task(role+'-train',[worker],768*1024)
        assert first and first['measured_bps']=='unknown', first
        for index in range(4):
            measured=task(role+'-measure',[worker],768*1024)
            if measured and isinstance(measured['measured_bps'],int):
                rates[role]=measured['measured_bps']
                break
        assert role in rates, events
    assert rates['fast']>2*rates['slow']>0, rates
    peer_snapshot(c, 'before-first-both-eligible')
    chosen=task('both-eligible',list(workers.values()),768*1024)
    peer_snapshot(c, 'after-first-both-eligible')
    good=bool(chosen and chosen['chosen']==workers['fast'].peer and isinstance(chosen['measured_bps'],int))
    stamp_event('first_open_choice_assertion',passed=good,chosen=chosen,previous_measured_rates=rates)
    if not good:
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            def after_failure(pair):
                name,worker=pair
                try:
                    return task('post-failure-pinned-'+name,[worker],768*1024)
                except Exception as err:
                    stamp_event('post_failure_diagnostic_error',role=name,error=repr(err))
            list(ex.map(after_failure,workers.items()))
    assert chosen and chosen['chosen']==workers['fast'].peer and isinstance(chosen['measured_bps'],int), chosen
    # Reverse only this fixture's userspace datagram timers. No route, advertised
    # hardware, worker, trust relationship, input size or container is changed.
    for role,new_rate in [('fast',8_000_000),('slow',0)]:
        cfg = common / (role + '.rate')
        cfg.with_suffix('.tmp').write_text(str(new_rate))
        cfg.with_suffix('.tmp').replace(cfg)
    start=time.monotonic()
    for role,new_rate in [('fast',8_000_000),('slow',0)]:
        observed=common/(role+'.observed')
        while not observed.is_file() or observed.read_text()!=str(new_rate):
            if time.monotonic()-start>8:raise RuntimeError('private pacing update did not apply')
            time.sleep(.1)
    reversed_rates={}
    switched=None
    for index in range(12):
        for role in ('fast','slow'):
            value=task(role+'-after-swap',[workers[role]],768*1024)['measured_bps']
            if isinstance(value,int): reversed_rates[role]=value
        if len(reversed_rates)==2 and reversed_rates['slow']>2*reversed_rates['fast']:
            switched=task('both-eligible-after-swap',list(workers.values()),768*1024)
            if switched and switched['chosen']==workers['slow'].peer: break
    assert switched and switched['chosen']==workers['slow'].peer, (switched,reversed_rates)
    tiny=task('tiny-both',list(workers.values()),100)
    assert tiny and tiny['measured_bps'] is None, tiny
    final_topology=topology()
    assert initial_topology==final_topology
    return {'initial_nodes':initial_topology,'final_nodes':final_topology,'scope':'three Linux network-disabled Docker namespaces on one host; no qdisc or host network changes',
        'initial_upload_rate_limits_bps':{'fast':None,'slow':8_000_000},'measured_upload_bps':rates,
        'reversed_upload_rate_limits_bps':{'fast':8_000_000,'slow':None},'reversed_measured_upload_bps':reversed_rates,
        'peer_ids':{r:n.peer for r,n in all_nodes.items()},'jobs':events,'plugin':package,'wasm_sha256':hash_file(wasm),
        'binary_sha256':{n:hash_file(bins/n) for n in ('entangle','entangled')},
        'network_mode':{r:run('docker','inspect','--format','{{.HostConfig.NetworkMode}}',name).stdout.strip() for r,name in names.items()}}
if stream.exists():
    raise SystemExit('Refusing to replace an earlier attempt journal')
stamp_event('diagnostic_start',original_driver_sha256=hash_file(repo/'docs/testing/production-review/evidence/candidate-a0926c6e/link-test.py'),original_failed_receipt_sha256=hash_file(proof.parent/'bandwidth-live-scorer-receipt.json'))
with tempfile.TemporaryDirectory(prefix='ent-up-') as temp,ExitStack() as stack:
    print(json.dumps(exercise(Path(temp),stack),indent=2))
