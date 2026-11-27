#!/usr/bin/env python3
"""Run a Cargo workspace's WASI libtest and merged rustdoc harnesses on paired daemons."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import uuid
import rustdoc_178_observer as observer
from types import SimpleNamespace

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def package(ctx, artifact, directory):
    fixture = load("fixture", Path(ctx["root"]) / "scripts/tests/distributed-rust-tests.py")
    binary_dir = Path(ctx["binaries"])
    class Installed:
        def __init__(self, home):
            self.home = home
        def cli(self, *args):
            return subprocess.check_output([binary_dir / "entangle", *args],
                env={**os.environ, "HOME": self.home}, timeout=60)
    key = digest(artifact)
    pub = Installed(ctx["coordinator_home"])
    component=directory/"command.component.wasm"
    subprocess.run([os.environ["JAQ_COMPONENT_ENCODER"],artifact,os.environ["JAQ_WASI_ADAPTER"],component],check=True)
    plugin, destination = fixture.signed_suite(pub, directory, "test-" + key[:24], component)
    (Path(ctx["artifact_evidence"])/(key+".json")).write_text(json.dumps({"core_sha256":key,"signed_component_sha256":digest(component),"signed_manifest_sha256":digest(destination/"entangle.toml"),"plugin":plugin}))
    for home in ctx["worker_homes"]:
        Installed(home).cli("plugins", "load", destination)
    return plugin

def cargo_call(artifact, arguments):
    context = Path(os.environ["ENTANGLE_CARGO_REVIEW"])
    ctx = json.loads(context.read_text())
    if arguments:
        raise ValueError(f"unsupported harness arguments {arguments!r}")
    runner = load("runner", Path(ctx["sharder"]))
    if digest(Path(ctx["sharder"])) != ctx["sharder_sha256"]:
        raise RuntimeError("sharder changed after qualification started")
    started = time.monotonic()
    key = digest(artifact)
    with tempfile.TemporaryDirectory(dir=context.parent) as directory:
        plugin = ctx["preloaded"].get(key) or package(ctx, artifact, Path(directory))
        socket = Path(ctx["socket"])
        descriptor = ctx["paths"].get(str(artifact.resolve()))
        if "ENTANGLE_RUSTDOC_INVOCATION" in os.environ:
            doc_dir, meta = observer.invocation()
            if descriptor is not None or artifact.name != "rust_out.wasm":
                raise RuntimeError(f"unknown Cargo harness {artifact}")
            package_name = meta["package"]
            if str(Path.cwd().resolve()) != meta["manifest_dir"]:
                raise RuntimeError("rustdoc child was invoked outside its Cargo package directory")
            descriptor = {"kind": "rustdoc", "package": package_name, "target": "doctest"}
            generated = observer.merged_sources(artifact)
            if not generated:
                return observer.standalone(ctx, artifact, descriptor, plugin, socket, runner)
            # Rustdoc's 2024 merged program ignores libtest selectors and runs
            # its entire documented crate as one WASI command. Its own output
            # contains the real individual test names, ignores and outcomes.
            peers = ctx["peers"]
            index = ctx["package_names"].index(package_name) % len(peers)
            attempts = []
            rows = {}
            for attempt in range(1, 3):
                peer = peers[(index + attempt - 1) % len(peers)]
                until = time.monotonic() + 75
                while True:
                    try:
                        raw = runner.dispatcher(socket, plugin, 60_000)(
                            peer, {"operation": "test", "name": "rustdoc", "attempt": attempt})
                        break
                    except runner.DispatchError as err:
                        if "no live worker" not in str(err) or time.monotonic() >= until:
                            raise
                        time.sleep(.2)
                matches = re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?:, .*?)?$",raw["stdout"],re.MULTILINE)
                summary = runner.RESULT.findall(raw["stdout"])
                counts = {k: sum(status == k for _,status in matches) for k in ("ok","FAILED","ignored")}
                if not matches or len(summary) != 1 or len(dict(matches)) != len(matches):
                    raise RuntimeError(f"unrecognised merged rustdoc output {raw!r}")
                phase, passed, failed, ignored, measured, filtered = summary[0]
                if (int(passed),int(failed),int(ignored),int(measured),int(filtered)) != (counts["ok"],counts["FAILED"],counts["ignored"],0,0):
                    raise RuntimeError(f"rustdoc summary disagrees with individual results {raw!r}")
                if phase != ("FAILED" if counts["FAILED"] else "ok") or raw["exit_code"] is None or bool(raw["exit_code"]) != bool(counts["FAILED"]):
                    raise RuntimeError(f"rustdoc exit disagrees with individual results {raw!r}")
                if rows and set(rows) != set(dict(matches)):
                    raise RuntimeError("merged rustdoc inventory changed between attempts")
                attempts.append({"attempt":attempt,**raw})
                for name, status in matches:
                    row=rows.setdefault(name,{"name":name,"status":None,"attempts":[]})
                    new_status={"ok":"passed","FAILED":"failed","ignored":"ignored"}[status]
                    if new_status != "ignored":
                        row["attempts"].append({"attempt":attempt,"peer":peer,"status":new_status})
                    row["status"] = "flaky" if new_status=="passed" and any(i["status"]=="failed" for i in row["attempts"]) else new_status
                if failed=="0":
                    break
            report={"suite":plugin,"mode":"complete merged rustdoc command","raw_attempts":attempts,
                    "results":list(rows.values()),"counts":{k:sum(r["status"]==k for r in rows.values()) for k in runner.STATUSES}}
            observer.write_json(doc_dir / ("merged-" + key + ".json"), sorted(rows))
            report["generated_sources"] = generated
            report["rustdoc_invocation"] = meta["id"]
        else:
            if descriptor is None or descriptor["wasm_hash"] != key:
                raise RuntimeError("ordinary executable absent from Cargo compiler metadata")
            for peer in ctx["peers"]:
                until = time.monotonic() + 75
                while True:
                    try:
                        runner.dispatcher(socket, plugin, 30_000)(peer, {"operation": "list"})
                        break
                    except runner.DispatchError as err:
                        if "no live worker" not in str(err) or time.monotonic() >= until:
                            raise
                        time.sleep(.2)
            opts = SimpleNamespace(peer=ctx["peers"], socket=socket, timeout_ms=60_000,
                plugins=[plugin], retries=1, filter=[], skip=[], ignored=False, include_ignored=False, exact=False)
            report = runner.run_suites(opts)['suites'][0]
    entry = dict(**descriptor, wasm_sha256=key, wasi_bytes=artifact.stat().st_size, report=report, elapsed_s=time.monotonic()-started)
    (context.parent / "reports" / (uuid.uuid4().hex + ".json")).write_text(json.dumps(entry,indent=2))
    if "raw_attempts" in report:
        # Rustdoc receives the real output of its generated merged executable.
        sys.stdout.write(report["raw_attempts"][-1]["stdout"])
        sys.stderr.write(report["raw_attempts"][-1]["stderr"])
        return report["raw_attempts"][-1]["exit_code"]
    else:
        for row in report["results"]:
            print(f"test {row['name']} ... {row['status']}", flush=True)
        print(report["counts"], flush=True)
    return int(bool(report["counts"]["failed"] or report["counts"]["error"]))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root","workspace","binaries","metadata","wasm-artifacts","out","cargo-log"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--sharder", type=Path, required=True)
    parser.add_argument("--binary-manifest", type=Path, required=True)
    args=parser.parse_args()
    before_cluster = time.monotonic()
    manifest = json.loads(args.binary_manifest.read_text())
    for name in ["entangle", "entangled"]:
        if digest(args.binaries / name) != manifest["files_sha256"][name]:
            raise RuntimeError("binary differs from verified archive manifest: " + name)
    sharder_sha = digest(args.sharder)
    before_load = Path("/proc/loadavg").read_text().strip()
    before_cpu = Path("/sys/fs/cgroup/cpu.stat").read_text()
    root=args.root.resolve()
    source_command=[sys.executable,str(root/"scripts/production_score.py"),"--source-id"]
    source_before=subprocess.check_output(source_command,cwd=root,text=True).strip()
    fixture=load("fixture",root/"scripts/tests/distributed-rust-tests.py")
    m=json.loads(args.metadata.read_text())
    packages={p["id"]:p["name"]for p in m["packages"]}
    artifacts={}
    for line in args.wasm_artifacts.read_text().splitlines():
        a=json.loads(line)
        if a["reason"]=="compiler-artifact" and a["package_id"]in packages and a["profile"]["test"] and a["executable"]:
            artifact=Path(a["executable"]);artifacts[artifact]=dict(kind="+".join(a["target"]["kind"]),
                package=packages[a["package_id"]],target=a["target"]["name"])
    assert artifacts
    manifest_dirs = {str(Path(p["manifest_path"]).resolve().parent): p["name"] for p in m["packages"]}
    real_rustdoc = subprocess.check_output(["rustup", "which", "--toolchain", "1.78.0", "rustdoc"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="ent-cargo-wasi-") as temp, ExitStack() as stack:
        d=Path(temp);(d/"reports").mkdir()
        coord=fixture.Node(d/"coordinator",args.binaries);workers=[fixture.Node(d/("worker-"+str(i)),args.binaries) for i in range(2)]
        routes=[]
        for w in workers:
            port=fixture.free_port();coord.trust(w);w.trust(coord)
            w.cli("keyring","add",coord.key,"--name","external workspace publisher")
            w.start(stack,port,[]);routes.append(f"{w.key}@127.0.0.1:{port}")
        ctx={"sharder":str(args.sharder.resolve()),"sharder_sha256":sharder_sha,"root":str(root),"binaries":str(args.binaries),"coordinator_home":str(coord.directory),
            "worker_homes":[str(w.directory)for w in workers],"socket":str(coord.socket),
            "peers":[w.peer for w in workers],"manifest_dirs": manifest_dirs,
            "paths":{str(k.resolve()):{**v,"wasm_hash":digest(k)} for k,v in artifacts.items()},"package_names":sorted(packages.values()),"artifacts":{digest(k):v for k,v in artifacts.items()},"preloaded":{},"artifact_evidence":os.environ["JAQ_ARTIFACT_EVIDENCE"]}
        for i,artifact in enumerate(artifacts):
            where=d/("suite"+str(i));where.mkdir()
            try:
                ctx["preloaded"][digest(artifact)]=package(ctx,artifact,where)
            except subprocess.CalledProcessError as exc:
                (Path(ctx["artifact_evidence"])/(digest(artifact)+"-unsupported.json")).write_text(json.dumps({"artifact":str(artifact),"core_sha256":digest(artifact),"error":str(exc),"status":"preload failed; real Cargo runner will receive the same artifact"}))
        coord.start(stack,0,routes)
        cpath=d/"context.json";cpath.write_text(json.dumps(ctx))
        env={**os.environ,"RUSTC_BOOTSTRAP":"1","RUSTDOC":str(Path(observer.__file__).resolve()),"ENTANGLE_REAL_RUSTDOC":real_rustdoc,"ENTANGLE_CARGO_REVIEW":str(cpath),"CARGO_TARGET_WASM32_WASIP1_RUNNER":shlex.join([sys.executable,str(Path(__file__).resolve()),"--cargo-runner"])}
        cmd=["cargo","+1.78.0","-Zdoctest-xcompile","test","--offline","--locked","--workspace","--target","wasm32-wasip1","--no-fail-fast"]
        setup_s=time.monotonic()-before_cluster
        start=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        t=time.monotonic()
        with args.cargo_log.open("wb") as log:
            proc=subprocess.run(cmd,cwd=args.workspace,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
        entries=[json.loads(p.read_text())for p in sorted((d/"reports").glob("*.json"))]
        source_after=subprocess.check_output(source_command,cwd=root,text=True).strip()
        result=dict(command=cmd,source_before=source_before,source_after=source_after,driver_sha256=digest(Path(__file__)),started_utc=start,finished_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            rustdoc_observer_sha256=digest(Path(observer.__file__)),sharder_sha256=sharder_sha, archive_manifest_sha256=digest(args.binary_manifest),
            daemon_source_ref=manifest["source_commit"],daemon_source_id=manifest["source_id"],cluster_setup_s=setup_s,
            loadavg_before=before_load,loadavg_after=Path("/proc/loadavg").read_text().strip(),
            cgroup_cpu_before=before_cpu,cgroup_cpu_after=Path("/sys/fs/cgroup/cpu.stat").read_text(),
            elapsed_s=time.monotonic()-t,exit_code=proc.returncode,peers=ctx["peers"],coordinator=coord.peer,
            daemon_sha256=digest(args.binaries/"entangled"),cli_sha256=digest(args.binaries/"entangle"),
            upstream_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=args.workspace,text=True).strip(),
            upstream_diff=subprocess.check_output(["git","diff","HEAD","--stat"],cwd=args.workspace,text=True),
            dependency_lock_sha256=digest(args.workspace/"Cargo.lock"),
            known_test_artifacts=len(artifacts),targets=entries)
        args.out.write_text(json.dumps(result,indent=2)+"\n")
        print(f"{len(entries)} harnesses, Cargo exit {proc.returncode}",flush=True)
        if source_before != source_after:
            raise RuntimeError("source changed while the workspace ran")
        return proc.returncode

if __name__=="__main__":
    if sys.argv[1:2]==["--cargo-runner"]:
        try:
            result = cargo_call(Path(sys.argv[2]), sys.argv[3:])
        except Exception as exc:
            if "ENTANGLE_RUSTDOC_INVOCATION" in os.environ:
                doc_dir, _ = observer.invocation()
                (doc_dir / ("fatal-" + uuid.uuid4().hex + ".txt")).write_text(str(exc))
            raise
        sys.exit(result)
    sys.exit(main())
