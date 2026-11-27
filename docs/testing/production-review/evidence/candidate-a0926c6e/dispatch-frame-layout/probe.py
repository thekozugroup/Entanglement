import hashlib, json, os, subprocess
from pathlib import Path
import sys,time
ROOT=Path('/workspace/Entanglement')
W=Path(__file__).resolve().parent
R=Path('/workspace/.entanglement-dev/rustup/toolchains/1.91-x86_64-unknown-linux-gnu/bin/rustc')
D=ROOT/'target/release/deps'
F=D.parent/'.fingerprint'
fp={'entangle_scheduler':F/'entangle-scheduler-c39f3f6711efe14b/lib-entangle_scheduler.json','entangle_bin':F/'entangle-bin-0634e200f4d53f7e/lib-entangle_bin.json'}
index={}
for f in F.glob('*/lib-*'):
    if not f.suffix:
        index[(f.name[4:],f.read_text())]=f.parent.name.rsplit('-',1)[-1]
def dependencies(crate):
    out={}
    for _,name,_,fingerprint in json.loads(fp[crate].read_text())['deps']:
        suffix=index[(name,int(fingerprint).to_bytes(8,'little').hex())]
        for ext in ('so','rlib','rmeta'):
            p=D/f'lib{name}-{suffix}.{ext}'
            if p.exists():
                out[name]=p
                break
        else: raise ValueError(name)
    return out
def externs(deps): return [s for k,v in deps.items() for s in ('--extern',f'{k}={v}')]
def run(args, env):
    print(' '.join(str(s) for s in args),flush=True)
    subprocess.run(args,env=env,check=True)
for side,src,rev in [('baseline',W.parent/'source-bb70','bb70a619'),('candidate',ROOT,'a0926c6e')]:
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=src,text=True).startswith(rev)
    subprocess.check_call(['git','diff','--quiet',rev,'--','crates/entangle-bin','crates/entangle-scheduler','Cargo.lock'],cwd=src)
    s=W/side;s.mkdir(exist_ok=True)
    compiled={}
    common=[R,'--edition=2021','-Copt-level=3','-Cdebug-assertions=no','-Cpanic=unwind','-L',f'dependency={s}','-L',f'dependency={D}']
    for crate in fp:
        base=src/'crates'/crate.replace('_','-')
        env={**os.environ,'CARGO_PKG_VERSION':'0.1.0','CARGO_MANIFEST_DIR':str(base)}
        ds=dependencies(crate)
        if crate=='entangle_bin': ds.update(compiled)
        result=s/f'lib{crate}-probe.rmeta'
        run([*common,'--crate-type=rlib','--crate-name',crate,'--emit=metadata','-Cmetadata=release_probe',
             base/'src/lib.rs','-o',result,*externs(ds)],env)
        compiled[crate]=result
    compiled['entangle_types']=dependencies('entangle_bin')['entangle_types']
    run([*common,'--crate-type=lib','--emit=llvm-ir','--crate-name','frame_probe',W/'probe.rs',
         '-o',s/'probe.ll',*externs(compiled),*(['--cfg','candidate'] if side=='candidate' else [])],os.environ)
