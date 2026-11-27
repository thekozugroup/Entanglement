"""Two diagnostic CLI executions using the frozen product and corrected coverage observer."""
import datetime
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

here=Path(__file__).resolve().parent
root=here.parents[5]
candidate=here.parent
toolroot=Path("/tmp/entangle-f499-raw-coverage-fix")
sys.path.insert(0,str(root/"scripts"))
from benchmark_image_batch import Node
def imported(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def save(p,data):p.write_text(json.dumps(data,indent=2)+"\n")
def source():return subprocess.check_output(["python3","scripts/production_score.py","--source-id"],cwd=root,text=True).strip()

frozen="sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
toolpath=toolroot/"scripts/benchmark_raw_batch.py"
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=toolroot,text=True).strip()=="b90aac1bf936c71f1ee4cf12893312f530a92b53"
assert sha(toolpath)=="8799aa5f8679e54331405fb643e18a0698276052ada641d97f98bb739b8d0012"
tool=imported("corrected_raw_observer",toolpath)
qa=imported("image_fixture",root/"scripts/tests/image-dehaze-batch.py")
assert sha(here/"plan.md")=="81cbff759d923b61d6273954df38592c9de94ff32ceda166f35d3956e742faf2"
assert source()==frozen
ref=json.loads((candidate/"raw-batch/real-photo-wall-times.json").read_text())["verified_output_sha256"]
assert ref=={"canon_350d.cr2":"2271485f205f0c831ff9b4048b5ca4ea465944a3fb9e4e88e0a2ecbb7ad83849",
             "nikon_d40.nef":"133fde6d0931c43e8155a5b1970ef7d7bd57b3dfea5f7007265ff1289e12a57a"}
input_root=Path("/tmp/entangle-raw-cc0")
manifest={"canon_350d.cr2":"8cbb84e04d93b005fe082da9c954122a612b5281af00aa088d767850f343fd38",
          "nikon_d40.nef":"44e88bc77b7a531b22647bcd07b9393c4568062e8f0906d3bbdecb42fbe29e03"}
release=json.loads((candidate/"linux-archive.json").read_text()); assert release["source_id"]==frozen
cli=root/"target/release/entangle";daemon=root/"target/release/entangled"
assert sha(cli)==release["files_sha256"]["entangle"] and sha(daemon)==release["files_sha256"]["entangled"]
wasm=root/"target/catalog-smoke/wasm32-wasip2/release/entangle_image_dehaze.wasm"
assert sha(wasm)=="eb0e482edfa642479d5b16caccf39b8e4dac4c4d290699fe6d97ee5d9103b973"
os.environ["PATH"]="/workspace/.entanglement-dev/libraw/usr/bin:/workspace/.entanglement-dev/cargo/bin:"+os.environ["PATH"]
out=here/"observations.json";assert not out.exists()
records={"source_before":frozen,"started_utc":now(),"product_commit":release["source_commit"],"archive_sha256":release["sha256"],
         "cli_sha256":sha(cli),"daemon_sha256":sha(daemon),"wasm_sha256":sha(wasm),"input_sha256":manifest,
         "tool_commit":"b90aac1bf936c71f1ee4cf12893312f530a92b53","tool_sha256":sha(toolpath),"plan_sha256":sha(here/"plan.md"),
         "driver_sha256":sha(Path(__file__)),"expected_output_sha256":ref,"arms":[]}
error=None
try:
    with tempfile.TemporaryDirectory(prefix="raw-coverage-diagnostics-",dir="/tmp") as tmp, ExitStack() as stack:
        d=Path(tmp);sources=d/"source";sources.mkdir()
        for name,hashval in manifest.items():
            assert sha(input_root/name)==hashval
            shutil.copyfile(input_root/name,sources/name)
        tool.validate_inputs(sources,manifest)
        coordinator=Node(d/"coordinator",cli)
        workers=[Node(d/f"worker-{i}",cli) for i in range(3)]
        first=workers[0]
        first.command("plugins","install","image-dehaze","--catalog",root/"plugins","--wasm",wasm,"--no-load")
        package=first.home/".entangle/plugins/image-dehaze"
        plugin=tomllib.loads((package/"entangle.toml").read_text())["plugin"]["id"]
        addresses=[]
        for w in workers:
            coordinator.trust(w);w.trust(coordinator)
            if w!=first:w.command("keyring","add",first.key,"--name","benchmark publisher")
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as port_socket:
                port_socket.bind(("127.0.0.1",0));port=port_socket.getsockname()[1]
            w.start(stack,daemon,port,[]);w.command("plugins","load",package);addresses.append(f"{w.key}@127.0.0.1:{port}")
        coordinator.start(stack,daemon,0,addresses)
        assert not tool.cli_json(cli,coordinator.env,"plugins","list")["plugins"]
        assert plugin in tool.cli_json(cli,first.env,"plugins","list")["plugins"]
        payload=d/"warmup.png";payload.write_bytes(qa.warmup_png())
        for w in workers:
            ready=[cli,"compute","dispatch",plugin,"--integrity","trusted-executor","--allow",w.peer,
                   "--cpu-cores",".01","--input-file",str(payload),"--raw"]
            deadline=time.monotonic()+45
            while True:
                p=subprocess.run(ready,env=coordinator.env,capture_output=True,timeout=45)
                if p.returncode==0:break
                if time.monotonic()>=deadline or not any(x in p.stderr for x in (b"no live workers",b"no worker satisfies")):
                    raise RuntimeError(p.stderr[-1000:])
                time.sleep(.15)
        records.update(coordinator=coordinator.peer,mesh_workers=[w.peer for w in workers],single_worker=first.peer,plugin=plugin)
        for name,node,allowed in (("single",first,{first.peer}),("mesh",coordinator,{w.peer for w in workers})):
            path=d/name
            cmd=[str(cli),"image","dehaze","--recursive",str(sources),"--output-dir",str(path),
                 "--plugin",plugin,"--jobs","3","--tile-edge","1024","--json"]
            for peer in sorted(allowed):cmd.extend(("--allow",peer))
            record={"route":name,"command":cmd,"specified_workers":sorted(allowed),"started_utc":now()}
            records["arms"].append(record)
            t=time.monotonic();proc=subprocess.run(cmd,env=tool.profile_env(node.home),capture_output=True,timeout=180)
            record.update(wall_s=time.monotonic()-t,cli_exit_code=proc.returncode,finished_utc=now())
            for suffix,content in (("stdout.jsonl",proc.stdout),("stderr",proc.stderr)):
                log=here/f"{name}.{suffix}";log.write_bytes(content);record[suffix+"_sha256"]=sha(log)
            if proc.returncode:raise RuntimeError(f"{name} CLI failed")
            try:
                hashes,counts,photos=tool.verify_run(proc.stdout,path,manifest,allowed,1024,ref)
            except tool.BatchVerificationError as exc:
                record.update(verified=False,failed_verification=exc.observations);raise
            record.update(verified=True,output_sha256=hashes,worker_tiles={k:counts.get(k,0) for k in sorted(allowed)},photos=photos)
        tool.validate_inputs(sources,manifest)
except BaseException as exc:
    error=repr(exc)
    raise
finally:
    records.update(finished_utc=now(),source_after=source(),error=error,exit_code=0 if error is None else 1)
    save(out,records);assert records["source_after"]==frozen
