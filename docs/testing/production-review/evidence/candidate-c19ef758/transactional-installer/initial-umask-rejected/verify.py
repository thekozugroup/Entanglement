#!/usr/bin/env python3
"""Test the frozen POSIX installer against genuine Linux archives and signed work."""

import argparse
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
import tempfile
import time

BINS = ("entangle", "entangled")
ASSET = "entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
URL = "https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/" + ASSET
OUT = Path(__file__).resolve().parent


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def capture(*cmd, cwd=None):
    return subprocess.check_output(cmd, text=True, cwd=cwd).strip()


def copy(src, dst, mode=0o644):
    shutil.copyfile(src, dst)
    dst.chmod(mode)
    assert sha(src) == sha(dst)


def run(args):
    repo = args.repo.resolve()
    source = lambda: capture("python3", "scripts/production_score.py", "--source-id", cwd=repo)
    before = source()
    assert before == args.source_id
    commit = capture("git", "rev-parse", "HEAD", cwd=repo)
    security = json.loads(capture("docker", "info", "--format", "{{json .SecurityOptions}}"))
    assert "name=rootless" in security
    summary = {"started_at_utc": utc(), "source_before": before, "source_commit": commit,
               "docker_security": security, "archives": {}, "distros": {},
               "case_limitation": "A pair of different verified builds reporting the same requested version is indistinguishable to the version-only no-op check. --force deliberately reinstalls the selected archive."}
    failed = False
    tracefile = OUT / "commands.jsonl"
    packager = repo / "scripts/package-native-release.py"
    summary["source_inputs_sha256"] = {name: sha(path) for name,path in {
        "qualification_plan": args.prereg, "packager": packager, "runner": Path(__file__),
        "curl-fixture": OUT / "curl-fixture.sh", "mv-fixture": OUT / "mv-fixture.sh",
    }.items()}
    with tracefile.open("x") as trace, tempfile.TemporaryDirectory(prefix="entangle-installer-c19ef-", dir="/workspace") as tmp:
        stage = Path(tmp)
        stage.chmod(0o755)

        def record(cmd, expected=None, *, name=None, stdout=None, enter=None):
            start = utc()
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            result = {"name": name, "command": list(map(str,cmd)), "started_at_utc": start, "finished_at_utc": utc(),
                      "exit_code": p.returncode, "expected_exit_code": expected, "stdout": p.stdout, "stderr": p.stderr}
            if enter:
                result.update(enter)
            print(json.dumps(result), file=trace, flush=True)
            assert expected is None or expected == p.returncode, result
            assert stdout is None or stdout == p.stdout, result
            return result

        for variant, archive, manifest in (
            ("jammy", args.portable, args.portable_receipt),
            ("canonical", args.canonical, args.canonical_receipt),
        ):
            manifest_data = json.loads(manifest.read_text())
            assert manifest_data["source_commit"] == commit
            assert manifest_data["source_id"] == manifest_data["source_after"] == before
            assert archive.name == ASSET and sha(archive) == manifest_data["sha256"]
            if "packager_sha256" in manifest_data:
                assert manifest_data["packager_sha256"] == sha(packager)
            stored = stage / variant
            stored.mkdir(mode=0o755)
            sidecars = {}
            digest = {"sha256": sha(archive), "b3": capture(str(args.b3sum), str(archive)).split()[0]}
            assert digest["b3"] == manifest_data["blake3"]
            copy(archive, stored / ASSET)
            for suffix, value in digest.items():
                sidecar = archive.with_name(f"{ASSET}.{suffix}")
                assert sidecar.read_text().split() == [value, ASSET]
                copy(sidecar, stored / sidecar.name)
                sidecars[sidecar.name] = sha(sidecar)
            files = manifest_data["files_sha256"]
            local = stage / (variant + "-bins")
            local.mkdir(mode=0o755)
            versions = {}
            with tarfile.open(stored / ASSET) as package:
                assert {member.name for member in package.getmembers() if member.isfile()} == {
                    f"{ASSET.removesuffix('.tar.gz')}/{name}" for name in files
                }
                for member in package.getmembers():
                    if member.isdir():
                        continue
                    assert member.isfile()
                    name = member.name.split("/")[1]
                    payload = package.extractfile(member).read()
                    assert hashlib.sha256(payload).hexdigest() == files[name]
                    if name in BINS:
                        binary = local / name
                        binary.write_bytes(payload)
                        binary.chmod(0o755)
                        table = record(["readelf", "--version-info", binary], 0, name=f"readelf:{variant}:{name}")["stdout"]
                        requirements = re.findall(r"Name: GLIBC_([\d.]+)", table.split("Version needs section",1)[1])
                        versions[name] = max(requirements, key=lambda v: tuple(map(int,v.split("."))))
            assert set(versions.values()) == ({"2.34"} if variant == "jammy" else {"2.39"})
            summary["archives"][variant] = {"path": str(archive), "manifest_sha256": sha(manifest),
                "sha256": digest["sha256"], "blake3": digest["b3"], "sidecar_sha256": sidecars,
                "ELF_sha256": {name:files[name] for name in BINS}, "GLIBC_requirements": versions}

        source_files = {
            "install-new.sh": "scripts/install.sh",
            "sample/entangle.toml": "examples/hello-world/entangle.toml",
            "sample/hello.wasm": "crates/entangle-host/tests/fixtures/hello-pong.wasm",
        }
        (stage / "sample").mkdir(mode=0o755)
        for destination, sourcefile in source_files.items():
            data = (repo / sourcefile).read_bytes()
            assert data == subprocess.check_output(["git", "show", f"{commit}:{sourcefile}"], cwd=repo)
            (stage / destination).write_bytes(data)
            (stage / destination).chmod(0o644)
            summary["source_inputs_sha256"][destination] = sha(stage / destination)
        (stage / "install-old.sh").write_bytes(subprocess.check_output(
            ["git", "show", "a0926c6ef3471aad01cedd256028437b249ef747:scripts/install.sh"], cwd=repo))
        (stage / "install-old.sh").chmod(0o644)
        summary["source_inputs_sha256"]["install-old.sh"] = sha(stage / "install-old.sh")
        copy(OUT / "curl-fixture.sh", stage / "curl", 0o755)
        copy(OUT / "mv-fixture.sh", stage / "mv", 0o755)

        for variant in ("missing-checksum", "malformed-checksum", "bad-checksum", "missing-daemon"):
            folder = stage / variant
            folder.mkdir(mode=0o755)
            if variant == "missing-daemon":
                with tarfile.open(stage / "jammy" / ASSET) as original, tarfile.open(folder / ASSET, "w:gz") as altered:
                    for member in original.getmembers():
                        if not member.name.endswith("/entangled"):
                            altered.addfile(member, original.extractfile(member) if member.isfile() else None)
                data = sha(folder / ASSET)
            else:
                (folder / ASSET).hardlink_to(stage / "jammy" / ASSET)
                data = "not-a-digest" if variant == "malformed-checksum" else "0" * 64
            sidecar = folder / (ASSET + ".sha256")
            if variant != "missing-checksum":
                sidecar.write_text(f"{data}  {ASSET}\n")
                sidecar.chmod(0o644)
            (folder / ASSET).chmod(0o644)
            summary.setdefault("negative_fixture_digests", {})[variant] = {
                "archive_sha256": sha(folder / ASSET), "sidecar_sha256": sha(sidecar) if sidecar.exists() else None,
            }

        for distro, libc in (("22.04","2.35"), ("24.04","2.39")):
            res = summary["distros"][distro] = {"cases": {}, "installed_workloads": {}}
            image = capture("docker", "image", "inspect", "ubuntu:"+distro,"--format","{{index .RepoDigests 0}}")
            res["image"] = image
            res["image_id"] = capture("docker", "image", "inspect", image, "--format", "{{.Id}}")
            docker = ["docker","run","-d","--pull=never","--network","none","--read-only","--cap-drop=ALL",
                      "--security-opt","no-new-privileges","--user","65534:65534","--platform","linux/amd64",
                      "--tmpfs","/tmp:rw,nosuid,nodev,noexec,mode=1777","--tmpfs","/work:rw,nosuid,nodev,exec,mode=1777",
                      "--mount",f"type=bind,src={stage},dst=/fixture,readonly",image,"sleep","infinity"]
            c = record(docker,0,name=f"{distro}:container-start")["stdout"].strip()
            serial = 0

            def ex(*cmd, name=None, expected=0, stdout=None, env=None):
                request = ["docker","exec"]
                for key,value in (env or {}).items():
                    request.extend(["-e",f"{key}={value}"])
                return record([*request,c,*cmd], expected, stdout=stdout, name=f"{distro}:{name}" if name else distro)

            def install(variant, *, case, generation="new", expected=0, force=False, failure=False, prefix=None, dry=False, requests=2):
                nonlocal serial
                serial += 1
                urls = f"{home}/urls-{serial}"
                cmd = ["/bin/sh",f"/fixture/install-{generation}.sh","--version","v0.1.0","--prefix",prefix or install_prefix]
                if force:
                    cmd.append("--force")
                if dry:
                    cmd.append("--dry-run")
                result = ex(*cmd,name=case,expected=expected,env={**shell_env,
                    "FIXTURE_ARCHIVE":ASSET, "FIXTURE_VARIANT":variant, "FIXTURE_REQUESTS":urls,
                    "FIXTURE_RENAME_FAILURE":str(int(failure))})
                recorded = ex("cat",urls,name=f"{case}:requests",expected=0 if requests else 1)
                expect = [URL,URL+".sha256"] if requests == 2 else []
                if not requests:
                    assert "No such file" in recorded["stderr"]
                assert recorded["stdout"].splitlines() == expect
                res["cases"][case] = {"exit_code":result["exit_code"], "requests":expect}
                return result["stderr"]

            def snapshot(prefix=None):
                directory = (prefix or install_prefix)+"/bin"
                result = {}
                for name in BINS:
                    path = directory+"/"+name
                    result[name] = {"sha256":ex("sha256sum",path)["stdout"].split()[0],
                                    "stat":ex("stat","-c","%a:%i",path)["stdout"].strip()}
                return result

            def pair(variant):
                data = snapshot()
                assert {name:value["sha256"] for name,value in data.items()} == summary["archives"][variant]["ELF_sha256"]
                for name in BINS:
                    ex(install_prefix+"/bin/"+name,"--version",stdout=f"{name} 0.1.0\n")
                return data

            def clean():
                ex("test","!","-e",install_prefix+"/bin/.entangle-install.lock")
                ex("test","!","-e",install_prefix+"/bin/.entangle-install.lock/new/entangle")
                ex("stat","-c","%a",sentinel,stdout="640\n")
                ex("cat",sentinel,stdout="unrelated user data\n")
                ex("find","/tmp","-mindepth","1","-maxdepth","1",stdout="")

            def installed_work(phase, variant):
                data = pair(variant)
                cli,daemon = (install_prefix+"/bin/"+name for name in BINS)
                if not prepared:
                    ex(cli,"init","--non-interactive",name=phase+":init",env=shell_env)
                    ex("/bin/sh","-ec",'printf "[mesh]\\ntransports=[]\\n" > "$HOME/.entangle/config.toml"',env=shell_env)
                    build = ex(cli,"plugins","build","/fixture/sample","--wasm","/fixture/sample/hello.wasm",
                               "--out",home+"/signed",name=phase+":sign",env=shell_env)["stdout"]
                    prepared["publisher"] = re.search(r"entangle keyring add ([a-f0-9]{64}) --name",build)[1]
                    prepared["plugin"] = re.search(r"entangle plugins invoke ([^ ]+) --input",build)[1]
                    prepared["signed_wasm_sha256"] = ex("sha256sum",home+"/signed/plugin.wasm")["stdout"].split()[0]
                    prepared["signature_sha256"] = ex("sha256sum",home+"/signed/plugin.wasm.sig")["stdout"].split()[0]
                cmd = ["docker","exec"]
                for key,value in shell_env.items():
                    cmd.extend(["-e",f"{key}={value}"])
                cmd += [c,"/bin/sh","-ec",'printf "%s\\n" "$$" > "$HOME/daemon.pid"; exec "$1" run',"sh",daemon]
                log = OUT / f"{distro}-{phase}-daemon.log"
                with log.open("x") as logs:
                    print(shlex.join(cmd),file=logs,flush=True)
                    start = utc()
                    proc = subprocess.Popen(cmd,stdout=logs,stderr=subprocess.STDOUT)
                    try:
                        for _ in range(80):
                            assert proc.poll() is None, log.read_text()
                            if ex("test","-S",home+"/.entangle/sock",expected=None)["exit_code"]==0:
                                break
                            time.sleep(.08)
                        else:
                            raise RuntimeError("installed daemon never bound its Unix socket")
                        mesh = json.loads(ex(cli,"mesh","status","--json",name=phase+":installed-uds",env=shell_env)["stdout"])
                        assert re.fullmatch(r"[a-f0-9]{32}",mesh["local_peer_id"])
                        if "trusted" not in prepared:
                            denied = ex(cli,"plugins","load",home+"/signed",name=phase+":untrusted",expected=None,env=shell_env)
                            assert denied["exit_code"] != 0 and re.search(r"trust|publisher|keyring|verification key",denied["stderr"],re.I)
                            ex(cli,"keyring","add",prepared["publisher"],"--name","isolated qualification publisher",
                               name=phase+":trust",env=shell_env)
                            prepared["trusted"] = True
                        ex(cli,"plugins","load",home+"/signed",name=phase+":load",env=shell_env)
                        nonce = secrets.token_hex(16)
                        expected_work = "Hello, "+nonce+"!"
                        actual = ex(cli,"plugins","invoke",prepared["plugin"],"--input",nonce,"--raw",
                                    name=phase+":signed-nonce",stdout=expected_work,env=shell_env)["stdout"]
                    finally:
                        ex("/bin/sh","-ec",'kill -TERM "$(cat "$HOME/daemon.pid")"',env=shell_env,expected=None)
                        exit_code = proc.wait(timeout=15)
                assert exit_code == 0, log.read_text()
                res["installed_workloads"][phase] = {"installed":data,"mesh_status":mesh,
                     "nonce":nonce,"expected":expected_work,"actual":actual,"daemon_exit_code":exit_code,
                     "started_at_utc":start,"finished_at_utc":utc(),"daemon_log":log.name,
                     "daemon_log_sha256":sha(log),"fixture":dict(prepared)}
                clean()

            try:
                actual_libc = ex("/bin/sh","-ec",'. /etc/os-release && echo "$VERSION_ID"; getconf GNU_LIBC_VERSION',
                                name="userspace",stdout=f"{distro}\nglibc {libc}\n")["stdout"]
                ex("id","-u",name="nonroot",stdout="65534\n")
                ex("readlink","/bin/sh",name="posix-shell",stdout="dash\n")
                ex("grep","-E"," /tmp .*noexec","/proc/mounts",name="noexec-download-filesystem")
                network = record(["docker","inspect",c,"--format","{{.HostConfig.NetworkMode}}"],0,name=f"{distro}:network")
                assert network["stdout"] == "none\n"
                res.update(libc=actual_libc,network="none",uid=65534)
                work = ex("mktemp","-d","/work/qual.XXXXXX")["stdout"].strip()
                home = work+"/home"
                install_prefix = work+"/installation prefix"
                sentinel = work+"/unrelated"
                ex("mkdir","-m","700",home)
                ex("/bin/sh","-ec",'umask 027; printf "unrelated user data\\n" > "$1"',"sh",sentinel)
                shell_env = {"HOME":home,"TMPDIR":"/tmp","PATH":"/fixture:/usr/bin:/bin",
                    "ENTANGLE_ALLOW_LOCAL":"0","TOKIO_WORKER_THREADS":"2"}
                prepared = {}

                dry = work+"/dry run"
                assert "Dry run" in install("jammy",case="dry-run",prefix=dry,dry=True,requests=0)
                ex("test","!","-e",dry)
                install("jammy",case="fresh-portable-install")
                portable_before = installed_work("portable-before","jammy")
                pristine = pair("jammy")
                assert "already installed" in install("jammy",case="complete-same-version-no-op",requests=0)
                assert snapshot() == pristine
                if distro == "22.04":
                    for name in BINS:
                        bad = ex(f"/fixture/canonical-bins/{name}","--version",name=f"direct-incompatibility:{name}",expected=1)
                        assert "GLIBC_2.39" in bad["stderr"]
                    error = install("canonical",case="force-incompatible-canonical",force=True,expected=1)
                    assert "Verifying SHA-256" in error and "ok: "+summary["archives"]["canonical"]["sha256"] in error
                    assert "staged entangle" in error and "GLIBC_2.39" in error and "Installing into" not in error
                    assert pair("jammy") == pristine
                    installed_work("portable-after-rejection","jammy")
                    res["cases"]["force-incompatible-canonical"].update(installed_before=pristine,installed_after=snapshot())

                    ex("rm",install_prefix+"/bin/entangled")
                    install("jammy",case="repair-missing-daemon")
                    pair("jammy")
                    ex("cp","/fixture/canonical-bins/entangled",install_prefix+"/bin/entangled")
                    broken = ex(install_prefix+"/bin/entangled","--version",name="precondition-broken-daemon",expected=1)
                    assert "GLIBC_2.39" in broken["stderr"]
                    install("jammy",case="repair-incompatible-daemon")
                    pair("jammy")
                    ex("rm",install_prefix+"/bin/entangle")
                    install("jammy",case="repair-missing-cli")
                    pair("jammy")

                    previous_prefix = work+"/baseline"
                    install("jammy",case="old-prepare",generation="old",prefix=previous_prefix)
                    before_old = snapshot(previous_prefix)
                    assert {name:value["sha256"] for name,value in before_old.items()} == summary["archives"]["jammy"]["ELF_sha256"]
                    ex("rm",previous_prefix+"/bin/entangled")
                    assert "already installed" in install("jammy",case="old-skip-missing-daemon",generation="old",prefix=previous_prefix,requests=0)
                    ex("test","!","-e",previous_prefix+"/bin/entangled")
                    ex("cp","/fixture/jammy-bins/entangled",previous_prefix+"/bin/entangled")
                    baseline = install("canonical",case="old-failed-upgrade-clobbers",generation="old",prefix=previous_prefix,force=True,expected=1)
                    assert "GLIBC_2.39" in baseline and "Installing into" in baseline
                    old_post = snapshot(previous_prefix)
                    assert {name:value["sha256"] for name,value in old_post.items()} == summary["archives"]["canonical"]["ELF_sha256"]
                    res["cases"]["old-failed-upgrade-clobbers"].update(installed_before=before_old,installed_after=old_post)

                    for variant, reason in (
                        ("missing-checksum","checksum file missing"),
                        ("malformed-checksum","malformed checksum file"),
                        ("bad-checksum","SHA-256 MISMATCH"),
                        ("missing-daemon","not found inside"),
                    ):
                        initial = snapshot()
                        text = install(variant,case=f"negative-{variant}",force=True,expected=1)
                        assert reason in text and "Verifying staged executables" not in text
                        assert pair("jammy") == initial
                        res["cases"][f"negative-{variant}"].update(installed_before=initial,installed_after=snapshot())
                        clean()

                    initial = snapshot()
                    ex("chmod","0555",install_prefix+"/bin")
                    assert "already installed" in install("jammy",case="complete-read-only-no-op",requests=0)
                    assert "not writable" in install("jammy",case="force-read-only-rejected",force=True,expected=1,requests=0)
                    ex("chmod","0755",install_prefix+"/bin")
                    assert pair("jammy") == initial
                    clean()
                else:
                    before_rename = snapshot()
                    rollback = install("canonical",case="failed-second-rename",expected=1,failure=True,force=True)
                    assert "fixture: controlled second publication failure" in rollback and "could not install" in rollback
                    assert pair("jammy") == before_rename
                    res["cases"]["failed-second-rename"].update(installed_before=before_rename,installed_after=snapshot())
                    clean()
                    install("canonical",case="force-compatible-canonical",force=True)
                    installed_work("canonical-after-upgrade","canonical")
                    ex("cp","/fixture/jammy-bins/entangle",install_prefix+"/bin/entangle")
                    mixed = snapshot()
                    assert mixed["entangle"]["sha256"] == summary["archives"]["jammy"]["ELF_sha256"]["entangle"]
                    assert mixed["entangled"]["sha256"] == summary["archives"]["canonical"]["ELF_sha256"]["entangled"]
                    for name in BINS:
                        ex(install_prefix+"/bin/"+name,"--version",stdout=f"{name} 0.1.0\n")
                    assert "already installed" in install("canonical",case="same-version-different-builds-limitation",requests=0)
                    assert snapshot() == mixed
                    res["cases"]["same-version-different-builds-limitation"].update(installed_before=mixed,installed_after=snapshot())
                    install("canonical",case="force-repair-same-version-different-builds",force=True)
                    pair("canonical")
                    clean()
            except BaseException as trouble:
                failed = True
                res["failure"] = repr(trouble)
                print(repr(trouble),flush=True)
            finally:
                record(["docker","rm","-f",c],0,name=f"{distro}:container-stop")

        res = record(["/bin/sh","-n",str(repo/"scripts/install.sh")],0,name="frozen-posix-syntax")
        record(["python3","-B",str(repo/"scripts/tests/test_install_transaction.py"),"-v"],0,name="frozen-installer-regression")
        assert sha(args.portable) == summary["archives"]["jammy"]["sha256"]
        assert sha(args.canonical) == summary["archives"]["canonical"]["sha256"]

    after = source()
    summary.update(source_after=after,commands_log=tracefile.name,commands_sha256=sha(tracefile),
                   finished_at_utc=utc(),exit_code=int(failed or before != after))
    (OUT / "installer-qualification.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps({"commit":commit,"source":after,"distros":{name:list(data["installed_workloads"]) for name,data in summary["distros"].items()},"exit_code":summary["exit_code"]}))
    return summary["exit_code"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("repo","portable","portable-receipt","canonical","canonical-receipt","b3sum","prereg"):
        parser.add_argument("--"+option,type=Path,required=True)
    parser.add_argument("--source-id",required=True)
    raise SystemExit(run(parser.parse_args()))
