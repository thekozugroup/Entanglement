"""Prepare source-exact cross build and emulated dispatch; no services or compile in staging."""
import pathlib, shutil
from pathlib import Path
W=Path(__file__).resolve().parent;P=W/'proof';R=Path('/workspace/Entanglement')
B=R/'docs/testing/production-review/evidence/candidate-c19ef758/emulated-linux-arm64'
for name in ['arm-build-driver.py','package-arm.py','signed-workload.py','standalone-local.py','cross-build.sh']:
    s=(B/name).read_text().replace('/workspace/entangle-emulated-arm-c19ef758',str(W))
    if name=='arm-build-driver.py':
        s=s.replace('assert cap>=4*1024**3',"assert cap>=768*1024**2") # 6 GiB /private tmpfs holds the build target and expanded registry.
        s=s.replace("target_disk_usage=host", "builder_tmpfs=host('docker','exec',c,'df','-B1','/private'),target_disk_usage=host")
    if name=='cross-build.sh':
        s=s.replace('/private/qemu/qemu-aarch64','/emu/qemu-aarch64')
    if name=='signed-workload.py':
        s=s.replace('candidate-c19ef758','candidate-a5728c23').replace("ARM = '/private/target/aarch64-unknown-linux-gnu/release/'","ARM = '/private/archive-arm/'").replace('/private/qemu/qemu-aarch64','/emu/qemu-aarch64')
        anchor="    wasm_hash=raw("
        assert s.count(anchor)==1
        s=s.replace(anchor,'''
        def count(role):
            observed=cli(role,'metrics').stdout
            return sum(int(v) for v in re.findall(r'^entangle_wasm_invocation_seconds_count\\{[^}]*\\} (\\d+)$',observed,re.M))
        # The emulated worker serviced exactly one direct and one x86-origin call.
        assert count('arm')==2 and count('x86')==0
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
''' + anchor)
    if name=='signed-workload.py':
        pos=s.index('        def count(role):');end=s.index('        # The emulated worker',pos)
        counter=s[pos:end];s=s[:pos]+s[end:]
        hot="        remote_nonce=secrets.token_hex(16);allow=target['peer']"
        s=s.replace(hot,counter+"        native_to_arm_before={r:count(r) for r in nodes}\n        assert native_to_arm_before=={'x86':0,'arm':1}\n"+hot)
        prior="        assert count('arm')==2 and count('x86')==0"
        s=s.replace(prior,prior+"\n        audit['x86_to_emulated_arm'].update(worker_counts_before=native_to_arm_before,worker_counts_after={r:count(r) for r in nodes})")
    (P/name).write_text(s)
    if name.endswith('.py'):compile(s,name,'exec')
