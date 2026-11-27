#!/usr/bin/env python3
"""Verify ordinary CLI worker timeout and no publication before a successful rerun."""
import argparse
from contextlib import ExitStack
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, default=Path.cwd())
parser.add_argument("--binaries", type=Path, required=True)
parser.add_argument("--wasm", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--revision")
parser.add_argument("--source")
args = parser.parse_args()
repo, binaries, wasm = args.repo.resolve(), args.binaries.resolve(), args.wasm.resolve()
spec = importlib.util.spec_from_file_location("image_batch", repo / "scripts/tests/image-dehaze-batch.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
def file_sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()
def identity():
    return [subprocess.check_output(cmd,cwd=repo,text=True).strip() for cmd in (
        ["git","rev-parse","HEAD"], ["python3","scripts/production_score.py","--source-id"])]
before = identity()
if args.revision or args.source:
    assert before == [args.revision,args.source], before
start_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
with tempfile.TemporaryDirectory(prefix="ent-image-timeout-") as tmp, ExitStack() as stack:
    root = Path(tmp)
    coordinator, workers, plugin = fixture.start_cluster(binaries, wasm, root, stack)
    photos, output = root/"input", root/"output"
    photos.mkdir()
    photo = photos/"scene.dng"
    photo.write_bytes(fixture.synthetic_dng(896,768,17))
    common = ["image","dehaze","--recursive",photos,"--output-dir",output,"--plugin",plugin,"--tile-edge","1024","--jobs","1","--json","--allow",workers[0].peer]
    start = time.monotonic()
    failed = fixture.run_cli(coordinator,[*common,"--timeout-ms","1"],success=False,timeout=40)
    elapsed = time.monotonic() - start
    rows, summary = fixture.parsed_rows(failed.stdout)
    assert len(rows)==1 and rows[0]["status"]=="failed" and rows[0]["input"]==photo.name and summary["failed"]==1, (rows,summary)
    message = rows[0]["error"]
    assert any(word in message.lower() for word in ["deadline","timeout","timed out"]),message
    assert not list(output.rglob("*.png")) and not list(output.rglob("*.json")), "published output or receipt after timeout"
    recovered = fixture.run_cli(coordinator,[*common,"--timeout-ms","30000","--resume"],timeout=75)
    ok, final = fixture.parsed_rows(recovered.stdout)
    assert final["failed"]==0 and len(ok)==1 and ok[0]["status"]=="processed" and ok[0]["tile_workers"]==[workers[0].peer],(ok,final)
    completed = output/ok[0]["output"]
    width,height,pixels = fixture.decode_linear_png(completed.read_bytes())
    assert width*height > 500000 and len(pixels)==6*width*height,(width,height)
    names, names_output = root/"named-photos", root/"named-outputs"
    names.mkdir()
    valid_name, invalid_name = "camera\nscene.dng", "invalid\tphoto.dng"
    (names/valid_name).write_bytes(fixture.synthetic_dng(128,128,23))
    (names/invalid_name).write_bytes(b"ordinary non-RAW file")
    plain = fixture.run_cli(coordinator, ["image","dehaze","--recursive",names,
                "--output-dir",names_output,"--plugin",plugin,"--tile-edge","1024","--jobs","1",
                "--allow",workers[0].peer],success=False,timeout=45)
    assert valid_name not in plain.stdout and invalid_name not in plain.stderr,(plain.stdout,plain.stderr)
    assert r"camera\nscene.dng" in plain.stdout and r"invalid\tphoto.dng" in plain.stderr,(plain.stdout,plain.stderr)
    assert (names_output/(valid_name+".dehazed.png")).is_file()
    assert not (names_output/(invalid_name+".dehazed.png")).exists()
    after = identity()
    if args.revision or args.source:
        assert before == after, (before,after)
    record = dict(revision=before[0],source_before=before[1],revision_after=after[0],source_after=after[1],
        started_utc=start_utc,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        cli_sha256=file_sha(binaries/"entangle"),daemon_sha256=file_sha(binaries/"entangled"),wasm_sha256=file_sha(wasm),
        host="Linux x86_64 with isolated loopback QUIC workers",worker_deadline_ms=1,
        failed_exit=failed.returncode,failed_seconds=round(elapsed,3),error=message,
        published_outputs_after_timeout=0,published_receipts_after_timeout=0,
        rerun_worker_deadline_ms=30000,recovered_exit=recovered.returncode,recovered_tile_count=1,
        human_mode_valid_newline_name_is_one_line=True,human_mode_invalid_tab_name_escaped=True,
        rerun_used_assigned_worker=True,dimensions=[width,height],
        input_sha256=file_sha(photo),output_sha256=file_sha(completed))
with args.out.open("x") as out:
    json.dump(record,out,indent=2);print(file=out)
print(json.dumps(record,indent=2))
