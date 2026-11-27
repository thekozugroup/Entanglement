"""Supplemental marker, ordinary RPC denials, and worker invocation counts on a disposable pair."""
import hashlib, json, secrets, socket, time
from pathlib import Path
from phase import mark

def wire(node,method,params):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(16)
        s.connect(str(node['home']/'.entangle/sock'))
        s.sendall(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()+b'\n')
        line=s.makefile('rb').readline(65537)
        if len(line)>65536:raise RuntimeError('too-large acceptance response')
        return json.loads(line)

def call(coord,worker,plugin,phase):
    nonce=secrets.token_hex(12)
    marker=plugin.endswith('/hello-world@0.1.0')
    inp=nonce.encode() if marker else json.dumps({'data':{'v':nonce},'pointer':'/v'}).encode()
    want=f'Hello, {nonce}!'.encode() if marker else json.dumps(nonce).encode()
    begin=time.monotonic()
    reply=wire(coord,'compute/dispatch',{'input':list(inp),'plugin_id':plugin,'timeout_ms':1000,
        'cpu_cores':0.01,'memory_bytes':0,'gpu_required':False,'gpu_vram_min_bytes':0,
        'integrity':{'kind':'trusted-executor','allowlist':[worker['peer']]}})
    error=reply.get('error')
    if error is not None:
        assert 'result' not in reply
        code=(error.get('data') or {}).get('remote_code')
        mark('supplemental-error',phase=phase,begin=begin,target=worker['peer'],rpc_code=error.get('code'),
             remote_code=code,diagnostic=error.get('message',''))
        return code,error.get('message','')
    result=reply['result']
    assert result['chosen_peer']==worker['peer'] and bytes(result['output'])==want
    mark('supplemental-output',phase=phase,begin=begin,chosen_peer=result['chosen_peer'],nonce=nonce,bytes=want.hex())
    return True,None

def supplemental(nodes,app,run,worker_count,echo):
    worker,coord=nodes['worker'],nodes['coordinator']
    marker=worker['peer']+'/hello-world@0.1.0'
    original=worker['peer']+'/json-pointer@0.1.0'
    assert marker not in wire(worker,'plugins/list',{})['result']['plugins']
    assert not wire(coord,'plugins/list',{})['result']['plugins']
    start_count=worker_count()
    t=time.monotonic()
    package=worker['home']/'revocation-marker'
    manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in package.iterdir() if p.is_file()}
    assert {'entangle.toml','plugin.wasm','plugin.wasm.sig'}<=manifest.keys()
    mark('supplemental-marker-load',target=worker['peer'],previous_count=start_count,signed_package_sha256=manifest)
    app(worker,'plugins','load','/ent-home/revocation-marker')
    while time.monotonic()<t+15:
        code,_=call(coord,worker,marker,'new signed marker')
        if code is True:break
        time.sleep(.25)
    else:raise RuntimeError('no fresh compatible inventory witnessed in 15s')
    assert worker_count()==start_count+1
    ts=['docker','exec',worker['name'],'tailscale']
    run(*ts,'down')
    assert echo(nodes,run,7444)!=0
    app(worker,'mesh','revoke',coord['peer'])
    mark('supplemental-revoked',by=worker['peer'],peer=coord['peer'])
    run(*ts,'up','--accept-dns=false','--login-server=https://hs.test','--netfilter-mode=off','--timeout=20s')
    while time.monotonic()<t+35 and echo(nodes,run,7444)!=0:time.sleep(.25)
    assert time.monotonic()<t+35
    before=worker_count()
    while time.monotonic()<t+35:
        code,message=call(coord,worker,original,'authenticated refusal on fresh inventory')
        assert code is not True and worker_count()==before==start_count+1
        if code=='not-authorized' and 'ENTANGLE-E0403' in message and worker['peer'] in message:
            break
        time.sleep(.25)
    else:raise RuntimeError('missing explicit worker task refusal on fresh inventory')
    assert time.monotonic()<t+35
    mark('supplemental-authenticated-refusal',seconds_since_marker_load=time.monotonic()-t,
         previous_count=before,after_count=worker_count())
    app(worker,'mesh','trust',coord['peer'],'--public-key-hex',coord['pub'],'--display-name','repaired disposable peer')
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if call(coord,worker,original,'repair after supplemental refusal')[0] is True:break
        time.sleep(.25)
    else:raise RuntimeError('no repair confirmation')
    assert worker_count()==before+1
