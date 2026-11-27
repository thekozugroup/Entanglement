"""Probe one unchanged published upstream Rust test through the normal signed runner."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,tempfile,time
from contextlib import ExitStack
from pathlib import Path
p=argparse.ArgumentParser()
for arg in ("root","bin-dir","wasm-artifacts","upstream","out"):
    p.add_argument("--"+arg,type=Path,required=True)
a=p.parse_args()
src_cmd=[sys.executable,str(a.root/"scripts/production_score.py"),"--source-id"]
source_before=subprocess.check_output(src_cmd,cwd=a.root,text=True).strip()
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fx=module("fx",a.root/"scripts/tests/distributed-rust-tests.py")
rr=module("rr",a.root/"scripts/run-rust-tests.py")
jobs=[json.loads(x) for x in a.wasm_artifacts.read_text().splitlines()]
artifact=Path(next(j["executable"]for j in jobs if j["reason"]=="compiler-artifact" and j["target"]["name"]=="async_await_macros" and j["profile"]["test"] and j["executable"]))
r={"candidate_source_before":source_before,"candidate_binary_hashes":{s:digest(a.bin_dir/s)for s in ["entangle","entangled"]},
   "upstream_revision":subprocess.check_output(["git","rev-parse","HEAD"],cwd=a.upstream,text=True).strip(),
   "upstream_target_source_sha256":digest(a.upstream/"futures/tests/async_await_macros.rs"),"wasm_sha256":digest(artifact),
   "published_crate":"futures 0.3.32","test":"stream_select","bound":"Three runs; futures-util initializes a thread-local deterministic PRNG with a counter starting at zero in each fresh single-threaded store.",
   "build_note":"The original published target file was compiled byte-for-byte with its public default futures dependency in an external manifest. The full published package and full upstream workspace are reported separately, including target and dependency errors.",
   "started_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"trials":[]}
with tempfile.TemporaryDirectory(prefix="ent-e2e-futures-")as tmp,ExitStack()as stack:
    d=Path(tmp);coord=fx.Node(d/"coordinator",a.bin_dir);workers=[fx.Node(d/("worker"+str(i)),a.bin_dir)for i in range(2)]
    plugin,package=fx.signed_suite(coord,d,"futures-async-await-macros",artifact);routes=[]
    for w in workers:
        coord.trust(w);w.trust(coord);w.cli('keyring','add',coord.key,'--name','published futures test target')
        port=fx.free_port();w.start(stack,port,[]);w.cli("plugins","load",package);routes.append(f"{w.key}@127.0.0.1:{port}")
    coord.start(stack,0,routes);peers=[x.peer for x in workers];r["peers"]=peers
    for peer in peers:
        stop=time.monotonic()+45
        while True:
            try:rr.dispatcher(coord.socket,plugin,30000)(peer,{"operation":"list"});break
            except rr.DispatchError as err:
                if "no live worker" not in str(err) or time.monotonic()>stop:raise
                time.sleep(.2)
    for i in range(3):
        order=peers if i%2==0 else peers[::-1]
        cmd=[sys.executable,str(a.root/"scripts/run-rust-tests.py"),plugin,"--socket",str(coord.socket),"--peer",order[0],"--peer",order[1],"--filter","stream_select","--exact","--retries","1"]
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=90);report=json.loads(proc.stdout);case,=report['suites'][0]['results']
        assert case['name']=="stream_select" and case['attempts'][0]['peer']==order[0]
        r['trials'].append(dict(index=i+1,exit=proc.returncode,stderr=proc.stderr,report=report))
r["candidate_source_after"]=subprocess.check_output(src_cmd,cwd=a.root,text=True).strip();assert source_before==r["candidate_source_after"]
r["finished_utc"]=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
a.out.write_text(json.dumps(r,indent=2)+"\n")
print([(j["exit"],j["report"]["counts"])for j in r["trials"]])
