"""Check a signed catalog plugin on emulated ARM64 and verified x86→ARM64 Iroh dispatch."""
import datetime
import hashlib
import json
import re
import secrets
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path

ROOT = Path('/workspace/Entanglement')
WORK = Path('/workspace/entangle-emulated-arm-a5728c23')
PROOF = WORK / 'proof'
CID = json.loads((PROOF / 'container.json').read_bytes())['id']
EXPECTED = json.loads((PROOF / 'inputs.json').read_bytes())
ARM = '/private/archive-arm/'
X86 = '/private/canonical/'
QEMU = ['/emu/qemu-aarch64','-L','/usr/aarch64-linux-gnu']


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def stamp():
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=WORK/'frozen',text=True).strip()==EXPECTED['commit']
    got=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=WORK/'frozen',text=True).strip()
    assert got==EXPECTED['source_before']
    return got


def run(argv, *, check=True, data=None, timeout=100):
    result=subprocess.run(argv,input=data,capture_output=True,text=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'command {argv[0:2]} exited {result.returncode}: {result.stderr.strip()[-1800:]} {result.stdout.strip()[-500:]}')
    return result


def raw(*args, **kwargs):
    return run(['docker','exec','-i',CID,*args],**kwargs)


def exe(role, binary, *args):
    prefix=QEMU if role=='arm' else []
    folder=ARM if role=='arm' else X86
    return ['docker','exec','-e','HOME=/private/home-'+role,'-e','TOKIO_WORKER_THREADS=2','-e','RAYON_NUM_THREADS=2','-e','ENTANGLE_ALLOW_LOCAL=0',CID,*prefix,folder+binary,*args]


def cli(role,*args,**kwargs):
    return run(exe(role,'entangle',*args),**kwargs)


def write(name,data):
    with (PROOF/name).open('x') as file:
        json.dump(data,file,indent=2);file.write('\n')


def signed_workload():
    started=utc();before=stamp()
    manifest=json.loads((ROOT/'docs/testing/production-review/evidence/candidate-a5728c23/linux-archive.json').read_bytes())
    build=json.loads((PROOF/'arm-build.json').read_bytes());assert build['exit_code']==0
    expected_arm=build['executables_sha256']; expected_x86={n:manifest['files_sha256'][n] for n in ('entangle','entangled')}
    assert manifest['source_commit']==EXPECTED['commit'] and manifest['source_id']==before
    for role, artifacts in [('arm',expected_arm),('x86',expected_x86)]:
        for n,hash_ in artifacts.items():
            path=(ARM if role=='arm' else X86)+n
            assert raw('sha256sum',path).stdout.split()[0]==hash_
            assert run(exe(role,n,'--version')).stdout.strip()==n+' 0.1.0'
    assert raw('sh','-ec','wc -l </proc/net/route').stdout.strip()=='1'
    nodes={}; audit={}
    for role in ['arm','x86']:
        raw('mkdir','-m','700','/private/home-'+role)
        cli(role,'init','--non-interactive')
        build_out=cli(role,'plugins','build','/src/plugins/json-pointer','--wasm','/private/json-pointer.wasm','--out','/private/signed-'+role).stdout
        public=re.search(r'entangle keyring add ([a-f0-9]{64}) --name',build_out)[1]
        plugin=re.search(r'entangle plugins invoke ([^ ]+) --input',build_out)[1]
        assert re.fullmatch(r'[a-f0-9]{32}/json-pointer@0.1.0',plugin)
        nodes[role]={'public':public,'peer':plugin.split('/')[0],'plugin':plugin,'home':'/private/home-'+role,'port':18443 if role=='arm' else 28443}
    assert nodes['arm']['public']!=nodes['x86']['public']
    processes={}
    with ExitStack() as stack:
        for role,other in [('arm','x86'),('x86','arm')]:
            node=nodes[role];peer=nodes[other]
            cli(role,'mesh','trust',peer['peer'],'--public-key-hex',peer['public'],'--display-name',other)
            config='[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nrelay=false\nbind="127.0.0.1:'+str(node['port'])+'"\npeers=["'+peer['public']+'@127.0.0.1:'+str(peer['port'])+'"]\n'
            raw('sh','-ec','cat > "$1"','write-config',node['home']+'/.entangle/config.toml',data=config)
            plain=exe(role,'entangled','run'); idx=plain.index(CID)+1;proc_argv=plain[:idx]+['sh','-ec','echo $$ > "$1"; shift; exec "$@"','start',node['home']+'/daemon.pid',*plain[idx:]]
            log=stack.enter_context((PROOF/(role+'-workload-daemon.log')).open('x'))
            processes[role]=subprocess.Popen(proc_argv,stdout=log,stderr=subprocess.STDOUT)
            def halt(r=role):
                proc=processes[r]
                if proc.poll() is None:
                    raw('sh','-ec','kill -TERM "$(cat "$1")"','stop-daemon',nodes[r]['home']+'/daemon.pid',check=False)
                nodes[r]['daemon_exit']=proc.wait(45)
                assert nodes[r]['daemon_exit']==0, (r,nodes[r])
            stack.callback(halt)
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                if raw('test','-S',node['home']+'/.entangle/sock',check=False).returncode==0:break
                assert processes[role].poll() is None;time.sleep(.1)
            else:raise RuntimeError('no local RPC socket on '+role)
            status=json.loads(cli(role,'mesh','status','--json').stdout)
            assert status['local_peer_id']==node['peer'] and status['trusted_peer_count']==1 and 'iroh' in status['transports_active'],status
            node['initial_status']=status
        role='arm'; target=nodes[role];plugin=target['plugin']
        denied=cli(role,'plugins','load','/private/signed-'+role,check=False)
        assert denied.returncode and re.search(r'(trust|publisher|keyring|verification key)',denied.stderr,re.I),denied
        assert json.loads(cli(role,'plugins','list','--json').stdout)=={'plugins':[]}
        cli(role,'keyring','add',target['public'],'--name','Emulated ARM catalog publisher')
        loaded=cli(role,'plugins','load','/private/signed-'+role)
        local_nonce=secrets.token_hex(16)
        def args_for(nonce):return json.dumps({'pointer':'/items/0/value','data':{'items':[{'value':nonce}]}})
        direct=cli(role,'plugins','invoke',plugin,'--input',args_for(local_nonce),'--raw')
        assert direct.stdout==json.dumps(local_nonce)
        audit['arm_signed_local']={'publisher_before_trust_exit':denied.returncode,'before_trust_diagnostic':denied.stderr.strip(),'plugin':plugin,'load_output':loaded.stdout,'input_json':args_for(local_nonce),'output':direct.stdout,'expected':json.dumps(local_nonce)}
        assert json.loads(cli('x86','plugins','list','--json').stdout)=={'plugins':[]}
        def count(role):
            observed=cli(role,'metrics').stdout
            return sum(int(v) for v in re.findall(r'^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$',observed,re.M))
        native_to_arm_before={r:count(r) for r in nodes}
        assert native_to_arm_before=={'x86':0,'arm':1}
        remote_nonce=secrets.token_hex(16);allow=target['peer']
        remote=cli('x86','compute','dispatch',plugin,'--raw','--input',args_for(remote_nonce),'--timeout-ms','30000','--cpu-cores','0.01','--integrity','trusted-executor','--allow',allow)
        chosen=re.search(r'^Chosen: ([a-f0-9]{32}) ',remote.stderr,re.M)[1]
        assert chosen==allow and remote.stdout==json.dumps(remote_nonce)
        audit['x86_to_emulated_arm']={'coordinator_loaded_plugins':[],'allowlist':[allow],'selected_peer':chosen,'remote_reason':remote.stderr.strip(),'plugin':plugin,'input_json':args_for(remote_nonce),'output':remote.stdout,'expected':json.dumps(remote_nonce)}

        # The emulated worker serviced exactly one direct and one x86-origin call.
        assert count('arm')==2 and count('x86')==0
        audit['x86_to_emulated_arm'].update(worker_counts_before=native_to_arm_before,worker_counts_after={r:count(r) for r in nodes})
        other=nodes['x86']; xplugin=other['plugin']
        assert xplugin!=plugin
        assert xplugin not in json.loads(cli('arm','plugins','list','--json').stdout)['plugins']
        cli('x86','keyring','add',other['public'],'--name','Native test publisher')
        cli('x86','plugins','load','/private/signed-x86')
        value=secrets.token_hex(16); before_counts={r:count(r) for r in nodes}
        req=['compute','dispatch',xplugin,'--raw','--input',args_for(value),'--timeout-ms','30000','--cpu-cores','0.01','--integrity','trusted-executor','--allow',other['peer']]
        remote=cli('arm',*req)
        chosen=re.search(r'^Chosen: ([a-f0-9]{32}) ',remote.stderr,re.M)[1]
        after_counts={r:count(r) for r in nodes}
        assert chosen==other['peer'] and remote.stdout==json.dumps(value)
        assert after_counts=={'x86':before_counts['x86']+1,'arm':before_counts['arm']}
        audit['arm_to_x86']={'allowlist':[other['peer']],'selected_peer':chosen,'plugin':xplugin,'input_json':args_for(value),'output':remote.stdout,'expected':json.dumps(value),'worker_counts_before':before_counts,'worker_counts_after':after_counts,'unloaded_on_coordinator':True}
    wasm_hash=raw('sha256sum','/private/json-pointer.wasm').stdout.split()[0]
    assert wasm_hash=='ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb'
    receipt={'source_before':before,'source_after':stamp(),'source_commit':EXPECTED['commit'],'scope':'Actual AArch64 GNU ELF CLI, daemon, Wasmtime JIT and signed catalog Wasm under explicit QEMU Linux user-mode on one x86_64 Linux host; direct loopback QUIC with native x86_64 coordinator, in the same disconnected container. No physical ARM hardware.', 'started_utc':started,'finished_utc':utc(),'exit_code':0,'arm_executables_sha256':expected_arm,'native_archive_sha256':manifest['sha256'],'native_executables_sha256':expected_x86,'wasm_sha256':wasm_hash,'nodes':nodes,'assertions':audit,'harness_sha256':sha(Path(__file__))}
    write('signed-workload.json',receipt)
    print('local ARM and x86 to ARM signed JSON-pointer passed',chosen)

if __name__=='__main__':signed_workload()
