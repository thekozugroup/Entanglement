"""Request rustc's compiler layout audit of the unmodified private spawn site."""
import subprocess, os
from pathlib import Path
w=Path(__file__).resolve().parent
log=(w/'probe.log').read_text().splitlines()
for side in ('baseline','candidate'):
    cmd=next(s.split() for s in log if '--crate-name entangle_bin --emit=metadata' in s and '/'+side+'/libentangle_bin-probe.rmeta' in s)
    cmd[cmd.index('--emit=metadata')]='--emit=llvm-ir'
    cmd[cmd.index('-o')+1]='/dev/null'
    cmd.extend(['-Zprint-type-sizes','-Cno-prepopulate-passes'])
    env={**os.environ,'RUSTC_BOOTSTRAP':'1','CARGO_PKG_VERSION':'0.1.0','CARGO_MANIFEST_DIR':str(Path(next(v for v in cmd if v.endswith('/entangle-bin/src/lib.rs'))).parents[1])}
    scheduler=next(s.split() for s in log if '--crate-name entangle_scheduler --emit=metadata' in s and '/'+side+'/libentangle_scheduler-probe.rmeta' in s)
    scheduler.extend(['-Zalways-encode-mir'])
    subprocess.run(scheduler,env=env,check=True)
    with (w/side/'compiler-layout.log').open('w') as sink:
       subprocess.run(cmd,env=env,stdout=sink,stderr=subprocess.STDOUT,check=True)
