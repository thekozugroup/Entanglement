import sys, tempfile, shutil, os, subprocess, json, hashlib, socket, tomllib, time, argparse
from contextlib import ExitStack
from pathlib import Path
root=Path(__file__).resolve().parents[6]
sys.path.insert(0,str(root/'scripts'))
from benchmark_image_batch import Node
from benchmark_raw_batch import main as bench
from importlib.util import spec_from_file_location, module_from_spec
s=spec_from_file_location('batchqa',root/'scripts/tests/image-dehaze-batch.py')
qa=module_from_spec(s);s.loader.exec_module(qa)
p=argparse.ArgumentParser()
p.add_argument('--report',type=Path,required=True)
p.add_argument('--bin-dir',type=Path,default=root/'target/release')
p.add_argument('--wasm',type=Path,default=root/'target/catalog-smoke/wasm32-wasip2/release/entangle_image_dehaze.wasm')
p.add_argument('--fixture-dir',type=Path,default=Path('/tmp/entangle-raw-cc0'))
p.add_argument('--edge',type=int,default=1024)
p.add_argument('--synthetic',action='store_true')
a=p.parse_args()
cli=a.bin_dir/'entangle'; daemon=a.bin_dir/'entangled'
with tempfile.TemporaryDirectory(dir='/tmp',prefix='rdh-') as td, ExitStack() as stack:
 d=Path(td)
 source=d/'sources'; source.mkdir()
 if a.synthetic: (source/'fixture.dng').write_bytes(qa.synthetic_dng(514,386,1))
 else:
  for n in ('nikon_d40.nef','canon_350d.cr2'): shutil.copyfile(a.fixture_dir/n,source/n)
 manifest=d/'manifest.json';manifest.write_text(json.dumps({f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(source.iterdir())}))
 co=Node(d/'c',cli); workers=[Node(d/('w'+str(i)),cli) for i in range(3)]; first=workers[0]
 first.command('plugins','install','image-dehaze','--catalog',root/'plugins','--wasm',a.wasm,'--no-load')
 package=first.home/'.entangle/plugins/image-dehaze';plugin=tomllib.loads((package/'entangle.toml').read_text())['plugin']['id']
 addrs=[]
 for w in workers:
  co.trust(w);w.trust(co)
  if w!=first:w.command('keyring','add',first.key,'--name','benchmark publisher')
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  w.start(stack,daemon,port,[]);w.command('plugins','load',package);addrs.append(f'{w.key}@127.0.0.1:{port}')
 co.start(stack,daemon,0,addrs)
 payload=d/'ready.png';payload.write_bytes(qa.warmup_png())
 for w in workers:
  ready=[str(cli),'compute','dispatch',plugin,'--integrity','trusted-executor','--allow',w.peer,'--cpu-cores','.01','--input-file',str(payload),'--raw']
  end=time.monotonic()+45
  while True:
   r=subprocess.run(ready,env=co.env,capture_output=True,timeout=45)
   if r.returncode==0:break
   if not (b'no live workers' in r.stderr or b'no worker satisfies' in r.stderr) or time.monotonic()>end:raise RuntimeError(r.stderr)
   time.sleep(.15)
 sys.argv=['benchmark_raw_batch','--input-dir',str(source),'--cli',str(cli),'--manifest',str(manifest),'--single-home',str(first.home),'--mesh-home',str(co.home),'--scratch',str(d),'--report',str(a.report),'--plugin',plugin,'--tile-edge',str(a.edge)]
 for w in workers:sys.argv+=['--worker',w.peer]
 bench()
