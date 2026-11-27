#!/usr/bin/env python3
"""Observe native archive installation, normal interactive shell startup and real doctor outcomes."""
import argparse
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent
SOURCE = "sha256:c276c15010e510172c5fbf07e6d3dc3c979f8270e0eb0b200026e7b6c5f6770e"
WARN = "claude-code launched outside Entanglement session"


def require(ok, text):
    if not ok:
        raise RuntimeError(text)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def run(cmd, env, timeout=12, check=True):
    p = subprocess.run(list(map(str,cmd)), env=env, capture_output=True, timeout=timeout, text=True)
    if check:
        require(p.returncode == 0, f"{cmd}: {p.stdout} {p.stderr}")
    return dict(exit=p.returncode,stdout=p.stdout,stderr=p.stderr)


def stamp(cli):
    source=subprocess.check_output(["python3","scripts/production_score.py","--source-id"], cwd=ROOT,text=True).strip()
    require(source == SOURCE, "wrong candidate")
    return dict(source_id=source,commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
                utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), cli_sha256=digest(cli),
                driver_sha256=digest(Path(__file__)))


def install_interactively(cli, archive, env):
    pid,master=pty.fork()
    if pid==0:
        os.execve(str(cli),[str(cli),"install",str(archive)],env)
    output=b""
    answered=False
    deadline=time.monotonic()+30
    exited=False
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],.2)[0]:
                try:
                    next_output=os.read(master,16384)
                except OSError as err:
                    if err.errno == errno.EIO:
                        break
                    raise
                if not next_output:
                    break
                output+=next_output
            if not answered and b"Install shell warnings" in output:
                os.write(master,b"y\n")
                answered=True
        else:
            raise TimeoutError("interactive installer timed out")
        _,status=os.waitpid(pid,0)
        exited=True
        require(os.waitstatus_to_exitcode(status)==0 and answered and b"Wrapper enabled" in output,
                "missing affirmative install prompt/activation: "+output.decode(errors="replace"))
        return dict(command=["entangle","install",archive.name],answered="y",exit=0,
                    transcript=output.decode(errors="replace").replace("\r",""))
    finally:
        os.close(master)
        if not exited:
            try:
                os.kill(pid,9)
            except ProcessLookupError:
                pass
            os.waitpid(pid,0)


def shell_run(shell, home, env, source, fish):
    if shell != "fish":
        return run([f"/usr/bin/{shell}","-ic",source],env,check=False)
    # This verified Debian Fish build resolves its vendor assets at /usr/share/fish.
    # Mount the full matching fish-common tree at its normal location, so Fish
    # itself reads the user's conf.d at startup. No manually sourced fish script.
    mounts = [(fish/"usr/bin/fish","/usr/bin/fish"),
              (fish/"usr/share/fish","/usr/share/fish"),
              (Path("/lib/x86_64-linux-gnu/libpcre2-32.so.0"),"/lib/x86_64-linux-gnu/libpcre2-32.so.0")]
    argv = ["docker","run","--rm","--pull=never","--network=none","--read-only","--cap-drop=ALL",
            "--user",f"{os.getuid()}:{os.getgid()}","--tmpfs","/tmp:rw,mode=1777",
            "-v",f"{home}:{home}:rw"]
    for src,dst in mounts:
        argv.extend(["-v",f"{src}:{dst}:ro"])
    for key in ["HOME","XDG_CONFIG_HOME","SHELL","PATH","TERM","ENTANGLE_SESSION_ID"]:
        if key in env:
            argv.extend(["-e",f"{key}={env[key]}"])
    argv.extend(["debian:trixie-slim","fish","-ic",source])
    return run(argv,os.environ,check=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli",type=Path,required=True)
    parser.add_argument("--fixture",type=Path,required=True)
    parser.add_argument("--fish-tree",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    cli=args.cli.resolve()
    fixture=args.fixture.resolve()
    archive=fixture/"hello-world-0.1.0.tar.zst"
    public=fixture/"test-publisher.pub.pem"
    key_der=subprocess.check_output(["openssl","pkey","-pubin","-in",public,"-outform","DER"])
    require(len(key_der)==44 and key_der[:12].hex()=="302a300506032b6570032100","not Ed25519")
    before=stamp(cli)
    reports={}
    with tempfile.TemporaryDirectory(prefix="ent-wrapper-",dir="/tmp") as root:
        for sh in ["bash","zsh","fish"]:
            home=Path(root)/sh
            home.mkdir(mode=0o700)
            bindir=home/"bin"
            bindir.mkdir()
            # Transparent argument/exit fixture substitutes for the third-party executable.
            agent=bindir/"claude-code"
            agent.write_text('#!/bin/sh\nprintf "underlying[%s]\\n" "$@"\nexit 23\n')
            agent.chmod(0o755)
            shell=f"/usr/bin/{sh}"
            env={k:v for k,v in os.environ.items() if not k.startswith(("ENTANGLE_", "BASH_FUNC_")) and k not in ("BASH_ENV","ENV","ZDOTDIR","XDG_CONFIG_HOME","XDG_DATA_HOME")}
            env.update(HOME=str(home), SHELL=shell, XDG_CONFIG_HOME=str(home/".config"), PATH=f"{bindir}:/usr/bin:/bin",
                       TERM="xterm", RUST_LOG="error", TOKIO_WORKER_THREADS="2", RAYON_NUM_THREADS="2")
            run([cli,"init","--non-interactive"],env)
            run([cli,"keyring","add",key_der[-32:].hex(),"--name","wrapper acceptance publisher"],env)
            install=install_interactively(cli,archive,env)
            require(tomllib.loads((home/".entangle/config.toml").read_text())["wrappers"]["install"] is True,sh)
            resolution="type -t claude-code" if sh=="bash" else ("whence -w claude-code" if sh=="zsh" else "type -t claude-code")
            resolved=shell_run(sh,home,env,resolution,args.fish_tree)
            require(resolved["exit"]==0 and "function" in resolved["stdout"].lower(),str(resolved))
            outside=shell_run(sh,home,env,'claude-code --version',args.fish_tree)
            direct=shell_run(sh,home,env,'command claude-code --version',args.fish_tree)
            inside=shell_run(sh,home,{**env,"ENTANGLE_SESSION_ID":"dummy-acceptance-session"},'claude-code --version',args.fish_tree)
            require(outside["exit"]==direct["exit"]==inside["exit"]==23
                    and outside["stdout"]==direct["stdout"]==inside["stdout"]=="underlying[--version]\n"
                    and WARN in outside["stderr"] and WARN not in inside["stderr"]+direct["stderr"],str([outside,direct,inside]))
            reports[sh]=dict(install=install,resolution=resolved,outside=outside,direct=direct,inside=inside)
            if sh != "bash":
                continue
            # The stdout from doctor, its status, and the independently established
            # parent-shell resolution are kept separate. Other checks may warn.
            os.symlink(cli,bindir/"entangle")
            template='''printf 'marker=%s\\n' "${ENTANGLE_WRAPPER_ACTIVE-unset}"
type -t claude-code
claude-code --version
printf 'dispatch-exit=%s\\n' "$?"
entangle doctor'''
            cases={}
            for case,prep in [
                ("working",""),
                ("unloaded-marker-cleared","unset -f claude-code\nunset ENTANGLE_WRAPPER_ACTIVE\n"),
                ("marker-inherited-command-only","unset -f claude-code\n"),
                ("later-function","claude-code() { printf 'independent function\\n'; return 47; }\n"),
                ("later-alias","alias claude-code='printf \"independent alias\\\\n\"'\n"),
            ]:
                obs=shell_run("bash",home,env,prep+template,args.fish_tree)
                cases[case]={**obs,"doctor_reported_shadow": "shadowed" in obs["stdout"]}
            require(cases["working"]["exit"]==0 and not cases["working"]["doctor_reported_shadow"],str(cases["working"]))
            require(cases["unloaded-marker-cleared"]["exit"]==1 and cases["unloaded-marker-cleared"]["doctor_reported_shadow"],str(cases["unloaded-marker-cleared"]))
            require("independent function" in cases["later-function"]["stdout"] and "dispatch-exit=47" in cases["later-function"]["stdout"],"function fixture did not replace wrapper")
            require("independent alias" in cases["later-alias"]["stdout"] and "\nalias\n" in cases["later-alias"]["stdout"],"alias fixture did not replace wrapper")
            require("marker=1\nfile\n" in cases["marker-inherited-command-only"]["stdout"],"stale marker/control fixture")
            reports[sh]["doctor"]=cases
    after=stamp(cli)
    require(all(before[k]==after[k] for k in ("source_id","commit","cli_sha256","driver_sha256")),"candidate changed")
    args.out.write_text(json.dumps(dict(before=before,after=after,archive_sha256=digest(archive),signature_sha256=digest(Path(str(archive)+".sig")),
        trusted_publisher_public_key_hex=key_der[-32:].hex(),fixture_scope="signed public test package, disposable HOME, controlled claude-code binary exits 23",
        fish_image=subprocess.check_output(["docker","image","inspect","debian:trixie-slim","--format","{{index .RepoDigests 0}}"],text=True).strip(),
        fish_binary_sha256=digest(args.fish_tree/"usr/bin/fish"),reports=reports),indent=2)+"\n")
    print("WRP-1 interactive authenticated installer and ordinary shell startup passed for Bash, Zsh and Fish.")
    print("WRP-3 doctor statuses", {k:(v["exit"],v["doctor_reported_shadow"]) for k,v in reports["bash"]["doctor"].items()})
    print("Receipt SHA-256",digest(args.out))


if __name__=="__main__":
    main()
