"""Build two independent successor fixture trees, using frozen inputs for the compatibility gate."""
import json, shutil, subprocess, sys
from pathlib import Path
repo=Path('/workspace/Entanglement')
previous=Path('/tmp/entangle-296b-reconvergence-phase17')
private=Path(__file__).parent
commit,source= sys.argv[1:3]
assert len(commit)==40 and source.startswith('sha256:') and len(source)==71
for name in ['two-phase','fresh-marker']:
    d=private/(commit[:8]+'-'+name)
    d.mkdir(exist_ok=False)
    for filename in ['stage.py','run.py','phase.py','status.py','analyze.py','analyze_partial.py','PROTOCOL.md']:
        shutil.copy2(previous/filename,d/filename)
    def change(p,a,b):
        s=p.read_text();assert s.count(a)==1,(p,a);p.write_text(s.replace(a,b))
    # Initial baseline fixture content is pinned to its original Git object. Successor qualification
    # checks that the upstream private-recovery scripts have not changed unreviewed.
    old='296b427a3bb2d60615ea3c56b9779f97039c6e24'
    for fixture in ['private-tailnet.py','private_recovery.py']:
        args=['git','rev-parse']
        assert subprocess.check_output(args+[old+':scripts/tests/'+fixture],cwd=repo)==subprocess.check_output(args+[commit+':scripts/tests/'+fixture],cwd=repo),'review fixture changes before running'
    change(d/'stage.py',old,commit)
    run=d/'run.py';change(run,old,commit)
    change(run,'sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b',source)
    change(run,"E=R/'docs/testing/production-review/evidence/candidate-296b427a'","E=R/'docs/testing/production-review/evidence'/('candidate-'+COMMIT[:8])")
    change(run,"b=Path('/tmp/entangle-check-296b427a-archive')","b=Path(sys.argv[1]).resolve()")
    change(run,"json.loads((E/'private-recovery-scorer-receipt.json').read_bytes())","json.loads((E.parent/'candidate-296b427a/private-recovery-scorer-receipt.json').read_bytes())")
    change(run,"assert before['source']==SOURCE","assert before=={'source':SOURCE,'head':COMMIT}")
    subprocess.run([sys.executable,'-B',str(d/'stage.py')],check=True)
    change(d/'private-tailnet.py','"-e", "HOME=/ent-home",','"-e", "RUST_LOG=warn,entangle_bin::capabilities=debug", "-e", "HOME=/ent-home",')
    change(d/'phase.py',"'scheduler rebind pending' in r]","'scheduler rebind pending' in r or 'worker capability query unavailable' in r or 'refused task from a peer' in r]")
    if name=='fresh-marker':
        shutil.copy2(private/'control.py',d/'control.py')
        start=d/'private-tailnet.py'
        hook='    if recovery:\n        # These enrolled'
        change(start,hook,"    cli(worker,'plugins','build',REPO/'examples/hello-world','--wasm',REPO/'crates/entangle-host/tests/fixtures/hello-pong.wasm','--out',worker['home']/'revocation-marker')\n"+hook)
        p=d/'private_recovery.py'
        a=p.read_text()
        x=a.index('    for arm, offset in');y=a.index('    require(identities() == initial',a.index('    wait_for("repaired trust"'))
        # Independent topology: keep cold publication and positive controls, then exercise
        # only the time-bounded fresh marker test. Main two-phase fixture keeps primary intact.
        p.write_text(a[:x]+'    from control import supplemental\n    supplemental(nodes,app,run,worker_count,echo)\n'+a[y:])
        shutil.copy2(private/'PROTOCOL.md',d/'SUPPLEMENT.md')
    for p in d.glob('*.py'):compile(p.read_bytes(),str(p),'exec')
    print(d)
