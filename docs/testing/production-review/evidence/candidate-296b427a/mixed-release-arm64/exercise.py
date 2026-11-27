#!/usr/bin/env python3
"""Dispatch one signed JSON Pointer job across frozen native x86 and prior emulated ARM."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import time


CURRENT = "296b427a3bb2d60615ea3c56b9779f97039c6e24"
SOURCE = "sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b"
OLDER = "c19ef7587a2215ef9434b642413bebd0473caf20"
OLDER_SOURCE = "sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644"
FIXTURE = "ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb"
BINS = ("entangle", "entangled")
ROLES = ("x86", "arm")


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    with path.open("rb") as incoming:
        return hashlib.file_digest(incoming, "sha256").hexdigest()


def public_file(path):
    path.chmod(0o644)


def public_dir(path):
    path.mkdir()
    path.chmod(0o755)


def main(args):
    repo = args.repo.resolve(strict=True)
    out = args.out.resolve(strict=True)
    work = args.work.resolve(strict=True)
    summary = {"started_at_utc": utc(), "commit": CURRENT, "source_before": SOURCE,
               "scope": "Current 296b427a x86_64 GNU/Linux CLI/daemon and prior c19ef758 AArch64 GNU/Linux CLI/daemon under explicit QEMU user mode. One x86_64 physical host, one network-disconnected container, and distinct loopback Iroh QUIC identities. Both binaries report v0.1.0."}
    log = out/"commands.jsonl"
    with ExitStack() as resources:
        stream = resources.enter_context(log.open("x"))

        def invoke(command, *, expected=0, stdin=None, label=None):
            argv = list(map(str,command))
            start = utc()
            proc = subprocess.run(argv, cwd=repo, input=stdin, capture_output=True, text=True, timeout=60)
            row = {"label":label,"argv":argv,"started_at_utc":start,"finished_at_utc":utc(),
                   "exit_code":proc.returncode,"stdout":proc.stdout,"stderr":proc.stderr}
            if stdin is not None:
                row["input_sha256"] = hashlib.sha256(stdin.encode()).hexdigest()
            print(json.dumps(row),file=stream,flush=True)
            assert expected is None or proc.returncode==expected,row
            return proc

        def stamp():
            assert invoke(["git","rev-parse","HEAD"]).stdout.strip() == CURRENT
            actual = invoke(["python3","scripts/production_score.py","--source-id"]).stdout.strip()
            assert actual==SOURCE
            return actual

        assert stamp()==SOURCE
        summary["inputs"] = {}
        stage = work/"fixtures"
        public_dir(stage)
        for role,commit,source,archive,receipt in (
            ("x86",CURRENT,SOURCE,args.x86,args.x86_receipt),
            ("arm",OLDER,OLDER_SOURCE,args.arm,args.arm_receipt),
        ):
            expected = json.loads(receipt.read_text())
            archive_sha = expected.get("archive_sha256",expected.get("sha256"))
            elfs = expected.get("elfs_sha256",expected.get("files_sha256"))
            assert expected["source_commit"]==commit and expected["source_after"]==source
            assert expected.get("source_before",expected.get("source_id"))==source
            assert sha(archive)==archive_sha
            sidecars = {}
            for suffix,digest in (("sha256",archive_sha),("b3",expected["blake3"])):
                sidecar=archive.with_name(archive.name+"."+suffix)
                assert sidecar.read_text().split()==[digest,archive.name]
                sidecars[suffix]=sha(sidecar)
            b3=invoke([args.b3sum,"--no-names",archive],label=f"{role}:archive-blake3").stdout.strip()
            assert b3==expected["blake3"]
            dest=stage/role
            public_dir(dest)
            with tarfile.open(archive) as tf:
                stem = archive.name.removesuffix(".tar.gz")
                for n in BINS:
                    member=tf.getmember(f"{stem}/{n}")
                    assert member.isfile()
                    binary=dest/n
                    with tf.extractfile(member) as original,binary.open("xb") as new:
                        shutil.copyfileobj(original,new,1024*1024)
                    binary.chmod(0o755)
                    assert sha(binary)==elfs[n]
                    readelf=invoke(["readelf","-h",binary],label=f"{role}:{n}:ELF").stdout
                    machine=re.search(r"^\s*Machine:\s*(.+)$",readelf,re.M)[1].strip()
                    assert machine==("AArch64" if role=="arm" else "Advanced Micro Devices X86-64"),machine
            summary["inputs"][role] = {"source_commit":commit,"source_id":source,
                "archive":str(archive),"archive_size":archive.stat().st_size,"archive_sha256":archive_sha,
                "archive_blake3":b3,"sidecar_sha256":sidecars,"archive_receipt_sha256":sha(receipt),
                "elf_sha256":{n:elfs[n] for n in BINS},"machine":machine}

        public_dir(stage/"source")
        manifest=repo/"plugins/json-pointer/entangle.toml"
        shutil.copyfile(manifest,stage/"source/entangle.toml")
        public_file(stage/"source/entangle.toml")
        trees={rev:invoke(["git","rev-parse",rev+":plugins/json-pointer"]).stdout.strip() for rev in (CURRENT,OLDER)}
        assert len(set(trees.values()))==1
        assert sha(args.wasm)==FIXTURE
        shutil.copyfile(args.wasm,stage/"json-pointer.wasm")
        public_file(stage/"json-pointer.wasm")
        assert sha(stage/"json-pointer.wasm")==FIXTURE
        summary["fixture"]={"plugin":"json-pointer@0.1.0","component_sha256":FIXTURE,
            "manifest_sha256":sha(manifest),"matching_source_git_trees":trees,"wasm_path":str(args.wasm)}
        emu=work/"emulator"
        arm_loader=emu/"fs/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1"
        assert arm_loader.is_file()
        summary["emulation"]={"emulator_sha256":sha(emu/"qemu-aarch64"),"arm_loader_sha256":sha(arm_loader),
            "runtime_packages":(emu/"packages.txt").read_text().splitlines(),
            "provision_recipe_sha256":sha(out/"provision-tools.sh"),"provision_log_sha256":sha(out/"provision.log")}
        image,image_id,_= (out/"debian-image.txt").read_text().splitlines()
        security=json.loads(invoke(["docker","info","--format","{{json .SecurityOptions}}"]).stdout)
        assert "name=rootless" in security
        assert invoke(["docker","image","inspect",image,"--format","{{.Id}}"]).stdout.strip()==image_id
        summary["container"]={"image":image,"image_id":image_id,"network_mode":"none","security":security}
        create=["docker","run","-d","--rm","--pull=never","--platform","linux/amd64","--network","none",
                "--user","65534:65534","--read-only","--cap-drop=ALL","--security-opt","no-new-privileges",
                "--tmpfs","/work:rw,nosuid,nodev,exec,mode=1777,size=192m",
                "--tmpfs","/tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m",
                "--mount",f"type=bind,src={stage},dst=/fixture,readonly",
                "--mount",f"type=bind,src={emu},dst=/emulator,readonly",image,"sleep","infinity"]
        cid=invoke(create,label="start-disconnected-container").stdout.strip()
        summary["container"]["id"]=cid

        def remove_container():
            invoke(["docker","rm","-f",cid],label="remove-disposable-container")
            absent=invoke(["docker","inspect",cid],expected=None)
            assert absent.returncode!=0

        resources.callback(remove_container)

        def raw(*cmd, expected=0, stdin=None, label=None):
            return invoke(["docker","exec","-i",cid,*cmd],expected=expected,stdin=stdin,label=label)

        qemu=["/emulator/qemu-aarch64","-L","/emulator/fs/usr/aarch64-linux-gnu"]

        def prefix(role):
            arguments=["docker","exec","-e",f"HOME=/work/{role}","-e","ENTANGLE_ALLOW_LOCAL=0",
                       "-e","TOKIO_WORKER_THREADS=2","-e","RAYON_NUM_THREADS=2",cid]
            return arguments

        def binary(role,name):
            return [*(qemu if role=="arm" else []),f"/fixture/{role}/{name}"]

        def cli(role,*arguments,expected=0,label=None):
            return invoke([*prefix(role),*binary(role,"entangle"),*arguments],
                          expected=expected,label=label or f"{role}:cli")

        assert invoke(["docker","inspect",cid,"--format","{{.HostConfig.NetworkMode}}"]).stdout.strip()=="none"
        net=raw("cat","/proc/net/route",label="only-loopback").stdout
        assert len(net.splitlines())==1
        assert raw("id","-u",label="runtime-nonroot").stdout.strip()=="65534"
        summary["emulation"]["emulator_version"]=raw("/emulator/qemu-aarch64","--version").stdout.strip()
        summary["emulation"]["arm_loader_version"]=raw(*qemu,"/emulator/fs/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1","--version").stdout.splitlines()[0]
        for role in ROLES:
            for name in BINS:
                output=invoke([*prefix(role),*binary(role,name),"--version"],label=f"{role}:{name}:version").stdout.strip()
                assert output==f"{name} 0.1.0"
                summary["inputs"][role].setdefault("versions",{})[name]=output
                exact=raw("sha256sum",f"/fixture/{role}/{name}").stdout.split()[0]
                assert exact==summary["inputs"][role]["elf_sha256"][name]

        nodes={}
        for role in ROLES:
            raw("mkdir","-m","700",f"/work/{role}")
            init=cli(role,"init","--non-interactive").stdout
            peer=re.search(r"Fingerprint:\s*([0-9a-f-]+)",init)[1].replace("-","")
            # The signing command prints the public key for the peer's disposable identity.
            signed=cli(role,"plugins","build","/fixture/source","--wasm","/fixture/json-pointer.wasm",
                       "--out",f"/work/pkg-{role}",label=f"{role}:sign-with-disposable-identity").stdout
            key=re.search(r"entangle keyring add ([0-9a-f]{64}) --name",signed)[1]
            plugin=re.search(r"entangle plugins invoke (\S+) --input",signed)[1]
            assert f"{peer}/json-pointer@0.1.0"==plugin
            nodes[role]={"peer":peer,"public_key":key,"plugin":plugin,
                         "port":18443 if role=="arm" else 28443,"home":f"/work/{role}"}
        assert nodes["x86"]["peer"]!=nodes["arm"]["peer"]
        summary["nodes"]=nodes
        with ExitStack() as running:
            for role,other in (("arm","x86"),("x86","arm")):
                node,peer=nodes[role],nodes[other]
                cli(role,"mesh","trust",peer["peer"],"--public-key-hex",peer["public_key"],"--display-name",other)
                config=('[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nrelay=false\n'
                        f'bind="127.0.0.1:{node["port"]}"\n'
                        f'peers=["{peer["public_key"]}@127.0.0.1:{peer["port"]}"]\n')
                raw("/bin/sh","-ec",'cat > "$1"',"configure",node["home"]+"/.entangle/config.toml",stdin=config)
                started=[*prefix(role),"/bin/sh","-ec",'printf "%s\\n" "$$" > "$HOME/daemon.pid"; exec "$@"',
                         "start",*binary(role,"entangled"),"run"]
                path=out/f"{role}-daemon.log"
                output=running.enter_context(path.open("x"))
                print(shlex.join(started),file=output,flush=True)
                proc=subprocess.Popen(started,cwd=repo,stdout=output,stderr=subprocess.STDOUT)

                def stop(role=role,node=node,proc=proc):
                    if proc.poll() is None:
                        raw("/bin/sh","-ec",'kill -TERM "$(cat "$1")"',"stop",node["home"]+"/daemon.pid",expected=None)
                    node["daemon_exit_code"]=proc.wait(timeout=45)
                    assert node["daemon_exit_code"]==0

                running.callback(stop)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    assert proc.poll() is None,path.read_text()
                    if raw("test","-S",node["home"]+"/.entangle/sock",expected=None).returncode==0:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError(f"{role} daemon did not create its Unix socket")
                status=json.loads(cli(role,"mesh","status","--json").stdout)
                assert status["local_peer_id"]==node["peer"] and status["trusted_peer_count"]==1
                assert "iroh" in status["transports_active"]
                node["mesh_status"]=status
                pid=raw("cat",node["home"]+"/daemon.pid").stdout.strip()
                process_executable=raw("readlink",f"/proc/{pid}/exe").stdout.strip()
                assert process_executable==("/emulator/qemu-aarch64" if role=="arm" else "/fixture/x86/entangled")
                node["process_executable"]=process_executable

            package="/work/pkg-x86"
            plugin=nodes["x86"]["plugin"]
            assert json.loads(cli("x86","plugins","list","--json").stdout)=={"plugins":[]}
            assert json.loads(cli("arm","plugins","list","--json").stdout)=={"plugins":[]}
            denied=cli("arm","plugins","load",package,expected=None,label="arm:publisher-untrusted")
            assert denied.returncode!=0 and re.search(r"trust|publisher|keyring|verification key",denied.stderr,re.I)
            cli("arm","keyring","add",nodes["x86"]["public_key"],"--name","disposable x86 publisher")
            cli("arm","plugins","load",package)
            assert json.loads(cli("arm","plugins","list","--json").stdout)=={"plugins":[plugin]}
            summary["signing"]={"package_owner":"296b x86 coordinator",
                "worker_rejected_before_publisher_trust":denied.returncode,
                "worker_rejection":denied.stderr,
                "package_file_sha256":{name:raw("sha256sum",f"{package}/{name}").stdout.split()[0]
                    for name in ("entangle.toml","plugin.wasm","plugin.wasm.sig")}}
            assert summary["signing"]["package_file_sha256"]["plugin.wasm"]==FIXTURE

            def wasm_counts(role):
                metrics=cli(role,"metrics").stdout
                observed=re.findall(r'^entangle_wasm_invocation_seconds_count\{result="(ok|error)"\} ([0-9]+)$',metrics,re.M)
                return {"ok":0,"error":0,**{name:int(count) for name,count in observed}}

            counts_before={role:wasm_counts(role) for role in ROLES}
            assert counts_before=={"x86":{"ok":0,"error":0},"arm":{"ok":0,"error":0}}
            nonce=secrets.token_hex(16)
            leaf=f"Ready from release fixture {nonce}"
            pointer="#/paths/~1health/get/responses/200/description"
            payload=json.dumps({"pointer":pointer,"data":{"paths":{"/health":{"get":{"responses":{
                "200":{"description":leaf}}}}}}},separators=(",",":"))
            answer=cli("x86","compute","dispatch",plugin,"--input",payload,"--raw","--timeout-ms","30000",
                       "--cpu-cores","0.01","--integrity","trusted-executor","--allow",nodes["arm"]["peer"],
                       label="new-x86:dispatch-signed-one-shot-to-old-arm")
            executor=re.search(r"^Chosen: ([a-f0-9]{32}) ",answer.stderr,re.M)[1]
            assert executor==nodes["arm"]["peer"] and answer.stdout==json.dumps(leaf)
            counts_after={role:wasm_counts(role) for role in ROLES}
            assert counts_after=={"x86":{"ok":0,"error":0},"arm":{"ok":1,"error":0}}
            assert json.loads(cli("x86","plugins","list","--json").stdout)=={"plugins":[]}
            assert json.loads(cli("arm","plugins","list","--json").stdout)=={"plugins":[plugin]}
            raw("test","!","-e","/work/x86/.entangle/plugins")
            summary["dispatch"]={"exit_code":answer.returncode,"pointer":pointer,"input":payload,
                "chosen_peer":executor,"output":answer.stdout,"expected":json.dumps(leaf),
                "output_sha256":hashlib.sha256(answer.stdout.encode()).hexdigest(),"placement":answer.stderr,
                "coordinator_loaded_plugins":[],"worker_loaded_plugins":[plugin],"before":counts_before,"after":counts_after}

        summary["daemon_log_sha256"]={role:sha(out/f"{role}-daemon.log") for role in ROLES}
        for role,archive in (("x86",args.x86),("arm",args.arm)):
            assert sha(archive)==summary["inputs"][role]["archive_sha256"]
        assert sha(args.wasm)==FIXTURE
        summary["source_after"]=stamp()

    summary.update(exit_code=0,finished_at_utc=utc(),command_log_sha256=sha(log),runner_sha256=sha(Path(__file__)))
    (out/"mixed-release-arm64.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps({"source":summary["source_after"],"selected_arm_worker":summary["dispatch"]["chosen_peer"],"exit_code":0}))


if __name__ == "__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ("repo","out","work","x86","x86-receipt","arm","arm-receipt","wasm","b3sum"):
        ap.add_argument("--"+name,required=True,type=Path)
    main(ap.parse_args())
