"""Compare the built-in status and dispatch paths to the pre-feature operator baseline."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
root=Path(sys.argv[1]).resolve()
dest=Path(sys.argv[2])
base='84aa663'
def old(p):return subprocess.check_output(['git','show',f'{base}:{p}'],cwd=root)
def sha(b):return hashlib.sha256(b).hexdigest()
def function(src,name):
    pattern=rb'\bfn\s+'+name.encode()+rb'\s*\('
    m=re.search(pattern,src)
    if not m:raise ValueError(name)
    start=src.index(b'{',m.end());balance=0
    for i in range(start,len(src)):
        if src[i:i+1]==b'{':balance+=1
        elif src[i:i+1]==b'}':
            balance-=1
            if not balance:return src[m.start():i+1]
    raise ValueError(name)
def compact(b):return re.sub(rb'\s+',b'',b)
checks={}
for p in ['crates/entangle-scheduler/src/dispatcher.rs','crates/entangle-scheduler/src/worker.rs','crates/entangle-scheduler/src/placement.rs','crates/entangle-scheduler/src/remote.rs','crates/entangle-bin/src/remote/routes/supervisor.rs','crates/entangle-bin/src/remote/routes/demand.rs']:
    wasm=(root/p).read_bytes();before=old(p)
    checks[p]=dict(identical=wasm==before,sha256=sha(wasm))
    assert wasm==before,p
p='crates/entangle-bin/src/remote/routes.rs';a=(root/p).read_bytes();b=old(p)
fns=['lookup_for_dispatch','refresh_missing_route','online_status','snapshot_routes','tailnet_bind']
for f in fns:
    before=function(b,f);after=function(a,f)
    checks[p+'::'+f]={'identical':before==after,'sha256':sha(after)}
    assert before==after
mesh='crates/entangle-mesh-tailscale/src/lib.rs';m=(root/mesh).read_bytes()
same=function(m,'status')==function(old(mesh),'status')
checks[mesh+'::status']={'identical':same,'sha256':sha(function(m,'status'))};assert same
assert compact(function(b,'is_tailnet_ip'))==compact(function(m,'is_tailnet_ip'))
checks['moved_address_policy']={'original':p,'new':mesh,'same_body_whitespace_insensitive':True}
link=(root/'crates/entangle-cli/src/cmd/mesh/tailnet.rs').read_text()
assert link.count('MeshTailscale::default().status().await?')==1
obj={'baseline_commit':subprocess.check_output(['git','rev-parse',base],cwd=root,text=True).strip(),'checked_tree_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'operator_status_callsite_count':1,'checks':checks}
dest.write_text(json.dumps(obj,indent=2)+'\n')
