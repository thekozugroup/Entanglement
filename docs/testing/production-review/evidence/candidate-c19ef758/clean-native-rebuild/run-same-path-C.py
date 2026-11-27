"""Post-primary conditional C arm, same A lexical target path, independently empty."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
D=Path('/workspace/Entanglement/docs/testing/production-review/evidence/candidate-c19ef758/clean-native-rebuild')
ROOT=Path('/workspace/Entanglement')
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
def source():
    return subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=ROOT,text=True).strip()
def snap(obj):
    p=D/'same-path-C.json';q=p.with_suffix('.part')
    q.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n');q.replace(p)
j=json.loads((D/'results.json').read_text());a,b=j['arms']
assert all(r['build_exit']==0 and r['private_target_reaped'] for r in [a,b])
assert j['between_clean_builds'] and not j['both_binaries_identical_across_empty_target_dirs']
assert not (D/'same-path-C.json').exists() and source()==j['source_before']==j['source_after']
path=Path(a['empty_target_path'])
assert path.parent==Path('/tmp') and path.name.startswith('entangle-c19-clean-target-') and not path.exists()
kept=Path(j['retained_binaries_and_archives']);out=kept/'C';out.mkdir()
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','SCCACHE','CCACHE'))}
env.update(j['build_env'])
env['CARGO_TARGET_DIR']=str(path)
env['PATH']=str(Path(j['tools']['cargo']['path']).parent)+':'+j['build_env']['CARGO_HOME']+'/bin:'+env['PATH']
info={'commit':j['commit'],'source_before':source(),'label':'Supplemental actual fixed-lexical-path A/C experiment, after primary A/B',
      'trigger_primary_sha256':sha(D/'results.json'),'script_sha256':sha(Path(__file__)),'started_utc':utc(),
      'command':a['argv'],'build_env':j['build_env'],'target_path':str(path),'declared_reference':'A',
      'free_bytes_before':shutil.disk_usage('/tmp').free,'tools':j['tools'],'cargo_lock_sha256':j['cargo_lock_sha256']}
path.mkdir(mode=0o700)
inode=path.stat().st_ino;device=path.stat().st_dev
try:
    assert not any(path.iterdir())
    info['starting_entries']=[];info['fresh_device_inode']=[device,inode];snap(info)
    s=time.monotonic();log=D/'build-C.log'
    with log.open('xb') as f:
        p=subprocess.run(a['argv'],env=env,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    info.update(build_exit=p.returncode,build_seconds=time.monotonic()-s,build_log_sha256=sha(log))
    if p.returncode==0:
        for n in a['binary_sha256']:shutil.copy2(path/'release'/n,out/n)
        info['binary_sha256']={n:sha(out/n) for n in a['binary_sha256']}
        info['member_equals_A']={k:a['binary_sha256'][k]==v for k,v in info['binary_sha256'].items()}
finally:
    assert path.is_dir() and not path.is_symlink() and path.stat().st_ino==inode and path.stat().st_dev==device
    shutil.rmtree(path)
    info['target_reaped']=not path.exists()
    info['build_finished_utc']=utc()
    snap(info)
if info['build_exit']==0:
    pkg=kept/'C'/'packaged';m=json.loads((D.parent/'linux-archive.json').read_text());cmd=list(m['command'])
    cmd[cmd.index('--bin-dir')+1]=str(out);cmd[cmd.index('--output-dir')+1]=str(pkg)
    tools=Path('/workspace/.entanglement-dev/release-tools/bin');penv={**env,'PATH':str(tools)+':'+env['PATH']}
    plog=D/'package-C.log'
    with plog.open('xb')as f:r=subprocess.run(cmd,cwd=ROOT,env=penv,stdout=f,stderr=subprocess.STDOUT)
    info.update(packager_argv=cmd,package_exit=r.returncode,package_log_sha256=sha(plog),b3sum_sha256=sha(tools/'b3sum'))
    if r.returncode==0:
        ar=pkg/m['name'];hs=sha(ar)
        bl=subprocess.check_output([tools/'b3sum',ar],text=True).split()[0]
        assert (Path(str(ar)+'.sha256').read_text().split()[0],Path(str(ar)+'.b3').read_text().split()[0])==(hs,bl)
        import tarfile
        with tarfile.open(ar)as tf:
            assert {n:hashlib.sha256(tf.extractfile(m['name'].removesuffix('.tar.gz')+'/'+n).read()).hexdigest() for n in a['binary_sha256']}==info['binary_sha256']
        a2=json.loads((D/'package-A-corrected.json').read_text())
        info.update(archive_sha256=hs,archive_blake3=bl,archive_equal_to_A=hs==a2['archive_sha256'] and bl==a2['archive_blake3'],archive_equal_to_canonical=hs==m['sha256'])
info['source_after']=source();info['finished_utc']=utc();snap(info)
sys.exit(0 if info['source_after']==info['source_before'] and info.get('build_exit')==0 and info.get('package_exit')==0 and all(info.get('member_equals_A',{}).values()) and info.get('archive_equal_to_A') else 1)
