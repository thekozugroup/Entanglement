"""Time a real Tailnet linking CLI against an offline, explicitly counted status helper."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import time
import tomllib

BASE=Path(__file__).resolve().parent
PEER='bba6177d17bd52008d632375409f2e1c'
KEY='db206f06a577ef984df02312a5af4b8d7cd9b163ff51b84a50a6361142cc7c3c'
NODE='n12345678901'
PORT=7443
CONFIG='''# Standalone operator qualification. No daemon runs.
[mesh]
transports = ["local", "tailscale"]
multi_node = true

[scheduler]
bind = "0.0.0.0:7440"
relay = false

[runtime]
bus_capacity = 256
'''
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def save(path,v):path.write_text(json.dumps(v,indent=2)+'\n')
def proc(args,env,cwd,timeout=12):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,env=env,cwd=cwd,timeout=timeout)
def source(root):
    return subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
def probe(args):
    root=args.root.resolve(strict=True);binary=args.binary.resolve(strict=True);out=args.output
    out.mkdir(exist_ok=False)
    ctx={**os.environ,'PATH':str(BASE),'ENTANGLE_TEST_STATUS':str(BASE/'status.json'),'LC_ALL':'C','TOKIO_WORKER_THREADS':'2'}
    manifest={'started_utc':now(),'source_before':source(root),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
              'cli_path':str(binary),'cli_sha256':sha(binary),'status_runner_sha256':sha(BASE/'tailscale'),
              'status_fixture_sha256':sha(BASE/'status.json'),'protocol_sha256':sha(BASE/'preregistration.md'),
              'script_sha256':sha(Path(__file__)), 'command_implementation_sha256':{str(p.relative_to(root)):sha(p) for p in [root/'crates/entangle-cli/src/cmd/mesh/tailnet.rs',root/'crates/entangle-cli/src/cmd/mesh.rs',root/'crates/entangle-mesh-tailscale/src/lib.rs',root/'crates/entangle-bin/src/remote/routes.rs']},'filesystem_mode':'temporary isolated HOME; no daemon; offline helper only','timing':'monotonic elapsed including process spawn and teardown','cpu_quota':Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'affinity':sorted(os.sched_getaffinity(0))}
    def compilers():
        rows=[]
        for entry in Path('/proc').glob('[0-9]*/stat'):
            try:
                st=entry.read_text();name=st[st.index('(')+1:st.rindex(')')]; fields=st[st.rindex(')')+1:].split()
                if name in ('cargo','rustc') and fields[0]!='Z':rows.append(dict(pid=entry.parent.name,name=name))
            except (OSError,ValueError,IndexError):pass
        return rows
    manifest['active_cargo_rustc_before']=compilers()
    manifest['system_load_before']=Path('/proc/loadavg').read_text().strip()
    assert (expected:=args.expected_cli_sha256) is None or manifest['cli_sha256']==expected
    with tempfile.TemporaryDirectory(prefix='entangle-tailnet-link-')as t:
        t=Path(t);template=t/'template';template.mkdir();state=template/'.entangle'
        env={**ctx,'HOME':str(template)}
        init=proc([binary,'init','--non-interactive'],env,root);assert init.returncode==0,(init.stdout,init.stderr)
        (state/'config.toml').write_text(CONFIG)
        command=[binary,'mesh','trust',PEER,'--public-key-hex',KEY,'--display-name','local-approved-operator-target']
        trust=proc(command,env,root);assert trust.returncode==0,(trust.stdout,trust.stderr)
        before_pairing=sha(state/'peers.toml')
        sub=[binary,'mesh','tailnet','link',NODE,'--peer',PEER,'--port',str(PORT),'--json']
        help_=proc([binary,'mesh','tailnet','link','--help'],env,root);assert help_.returncode==0,(help_.stdout,help_.stderr)
        (out/'help.txt').write_text(help_.stdout);manifest.update(setup_command=list(map(str,command)),timed_command=list(map(str,sub)),stable_peer=PEER,stable_node_id=NODE,expected_port=PORT,peer_store_sha256=before_pairing)
        save(out/'receipt.json',manifest)
        vals=[]
        with (out/'commands.jsonl').open('x')as log:
            for i in range(13):
                h=t/f'pair-{i}';shutil.copytree(template,h)
                config=h/'.entangle/config.toml';peers=h/'.entangle/peers.toml';calls=h/'status-calls.log';calls.touch()
                prior=None
                for kind in ['first','idempotent']:
                    preconf=sha(config);ns=config.stat().st_mtime_ns;inode=config.stat().st_ino
                    oldq=calls.read_text().splitlines()
                    env={**ctx,'HOME':str(h),'ENTANGLE_TEST_QUERY_LOG':str(calls),'ENTANGLE_TEST_INVOCATION_UTC':now()}
                    t0=time.perf_counter_ns();p=proc(sub,env,root);end=time.perf_counter_ns()
                    cfg=config.read_bytes()
                    newq=calls.read_text().splitlines()[len(oldq):]
                    row=dict(pair=i,kind=kind,warmup=i==0,utc=env['ENTANGLE_TEST_INVOCATION_UTC'],elapsed_ns=end-t0,command=list(map(str,sub)),exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr,
                             status_calls=len(newq),status_calls_raw=newq,config_sha256_before=preconf,
                             config_sha256_after=hashlib.sha256(cfg).hexdigest(),config_inode_changed=config.stat().st_ino!=inode,
                             config_mtime_changed=config.stat().st_mtime_ns!=ns,peer_store_sha256_after=sha(peers))
                    print(json.dumps(row),file=log,flush=True)
                    assert p.returncode==0,(p.stderr,p.stdout)
                    reply=json.loads(p.stdout);assert reply['node_id']==NODE and reply['peer_id']==PEER and reply['public_key']==KEY and reply['port']==PORT and reply['changed']==(kind=='first') and reply['tailscale_enabled'] is True
                    routes=tomllib.loads(cfg.decode())['scheduler']['tailnet_peers']
                    assert routes==[{'node_id':NODE,'public_key':KEY,'port':PORT}],routes
                    assert all(s.split('\t')[1]=='status --json'for s in newq),newq
                    assert row['peer_store_sha256_after']==before_pairing
                    assert kind=='first' or cfg==prior,'idempotent invocation changed config bytes'
                    prior=cfg
                    if i:vals.append(row)
        # Separate offline fixture floor. This is not real Tailscale timing and we do not subtract unmatched quantiles.
        fixture_rows=[]
        calls=t/'control-calls.log';calls.touch()
        control_cmd=[BASE/'tailscale','status','--json']
        for i in range(12):
            e={**ctx,'HOME':str(template),'ENTANGLE_TEST_QUERY_LOG':str(calls),'ENTANGLE_TEST_INVOCATION_UTC':now()}
            ts=time.perf_counter_ns();p=proc(control_cmd,e,root);elapsed=time.perf_counter_ns()-ts
            assert p.returncode==0 and json.loads(p.stdout)==json.loads((BASE/'status.json').read_bytes())
            fixture_rows.append(elapsed/1e6)
        assert len(calls.read_text().splitlines())==12
        control=sorted(fixture_rows)
        manifest['direct_fixture_only_control_ms']=dict(count=12,p50_ms=statistics.median(control),p95_ms=control[-1],range_ms=[control[0],control[-1]],all_ms=fixture_rows)
        manifest['active_cargo_rustc_after']=compilers()
        manifest['system_load_after']=Path('/proc/loadavg').read_text().strip()
        manifest['replicates']=12
        for k in ['first','idempotent']:
            rows=[r for r in vals if r['kind']==k];ms=sorted(r['elapsed_ns']/1e6 for r in rows)
            manifest[k]=dict(count=len(ms),p50_ms=statistics.median(ms),p95_ms=ms[math.ceil(len(ms)*.95)-1],range_ms=[ms[0],ms[-1]],status_calls_each=[r['status_calls']for r in rows],
                             config_replacements=sum(r['config_inode_changed'] for r in rows),config_changed=sum(r['config_mtime_changed'] for r in rows))
    manifest.update(finished_utc=now(),source_after=source(root),cli_sha256_after=sha(binary),raw_sha256=sha(out/'commands.jsonl'),exit_code=0)
    manifest['same_workspace_source_before_after']=manifest['source_after']==manifest['source_before']
    manifest['same_command_sources_before_after']=all(sha(root/name)==value for name,value in manifest['command_implementation_sha256'].items())
    assert manifest['cli_sha256_after']==manifest['cli_sha256'] and manifest['same_command_sources_before_after']
    save(out/'receipt.json',manifest)
    print(json.dumps({k:manifest[k] for k in ('first','idempotent','source_before','source_after','cli_sha256')},indent=2))
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ['root','binary','output']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--expected-cli-sha256')
    probe(parser.parse_args())
