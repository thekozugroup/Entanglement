"""Execute the preregistered real photos once and retain source, archive and observable inputs."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

here=Path(__file__).resolve().parent
root=here.parents[5]
candidate=here.parent
source_id="sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
head="f499e3edf84e20f550312d05df51b9ea4e7cc699"
bin_dir=root/"target/release"
wasm=root/"target/catalog-smoke/wasm32-wasip2/release/entangle_image_dehaze.wasm"
decoder=Path("/workspace/.entanglement-dev/libraw/usr/bin")
fixture=Path("/tmp/entangle-raw-cc0")
photos={"canon_350d.cr2":"8cbb84e04d93b005fe082da9c954122a612b5281af00aa088d767850f343fd38",
        "nikon_d40.nef":"44e88bc77b7a531b22647bcd07b9393c4568062e8f0906d3bbdecb42fbe29e03"}
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def source():return subprocess.check_output(["python3","scripts/production_score.py","--source-id"],cwd=root,text=True).strip()
def save(p,d):p.write_text(json.dumps(d,indent=2)+"\n")
archive=json.loads((candidate/"linux-archive.json").read_text())
assert archive["source_commit"]==head and archive["source_id"]==source_id==source()
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()==head
assert all(sha(bin_dir/k)==archive["files_sha256"][k] for k in ("entangle","entangled"))
assert all(sha(fixture/f)==digest for f,digest in photos.items())
assert sha(wasm)=="eb0e482edfa642479d5b16caccf39b8e4dac4c4d290699fe6d97ee5d9103b973"
report=here/"real-photo-wall-times.json";monitor=here/"resource-samples.json"
assert not report.exists() and not monitor.exists()
command=["python3",str((here/"monitor.py").relative_to(root)),str(monitor.relative_to(root)),"--",
         str(root/"target/catalog-smoke-python/bin/python"),str((here/"loopback-harness.py").relative_to(root)),
         "--bin-dir",str(bin_dir),"--wasm",str(wasm),"--report",str(report)]
env={**os.environ,"PATH":str(decoder)+":/workspace/.entanglement-dev/cargo/bin:"+os.environ["PATH"]}
log=candidate/"raw-clock.log";start=now()
with log.open("x") as fp:
    proc=subprocess.run(command,cwd=root,env=env,stdout=fp,stderr=subprocess.STDOUT)
end=now();after=source()
claimed={"command":command,"source_before":source_id,"source_after":after,"started_utc":start,"finished_utc":end,
         "exit_code":proc.returncode,"log":str(log.relative_to(root)),"sha256":sha(log)}
save(candidate/"raw-clock.json",claimed)
assert after==source_id and proc.returncode==0
actual=json.loads(report.read_text())
prior=json.loads((candidate.parent/"candidate-a5728c23/raw-batch/real-photo-wall-times.json").read_text())
assert len(actual["trials"])==8
assert actual["verified_output_sha256"]==prior["verified_output_sha256"]
assert actual["cli_sha256"]==archive["files_sha256"]["entangle"]
for t in actual["trials"]:
    assert t["exit_code"]==0 and sum(t["worker_tiles"].values())==18
    assert set(t["worker_tiles"])==(set(actual["mesh_workers"]) if t["route"]=="mesh" else {actual["single_peer"]})
receipt={**claimed,"log":str(report.relative_to(root)),"sha256":sha(report),"archive_sha256":archive["sha256"],
         "archive_signing_status":archive["signing_status"],"cli_sha256":sha(bin_dir/"entangle"),
         "daemon_sha256_checked_at_normalization":sha(bin_dir/"entangled"),"wasm_sha256":sha(wasm),
         "input_sha256":photos,"decoder_sha256":{n:sha(decoder/n) for n in ("raw-identify","dcraw_emu")},
         "original_receipt_sha256":sha(candidate/"raw-clock.json"),"monitor_sha256":sha(monitor),
         "normalized_utc":now()}
save(here/"wall-times-receipt.json",receipt)
print(json.dumps({k:actual[k] for k in ("median_wall_s","median_wall_speedup","verified_output_sha256")},indent=2))
