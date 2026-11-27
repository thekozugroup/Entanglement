#!/usr/bin/env python3
"""Verify an unsigned release archive and run signed JSON Pointer in pinned Linux userspaces."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time

IMAGES = (
    ("ubuntu-22.04", "ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb", "22.04", "2.35"),
    ("debian-12", "debian@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e", "12", "2.36"),
    ("ubuntu-24.04", "ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b", "24.04", "2.39"),
    ("debian-13", "debian@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0", "13", "2.41"),
)
BINS = ("entangle", "entangled")
WASM_SHA256 = "ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb"


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def version(value):
    return tuple(map(int, value.split(".")))


def execute(args):
    repo = args.repo.resolve(strict=True)
    archive = args.archive.resolve(strict=True)
    archive_receipt = args.archive_receipt.resolve(strict=True)
    result = args.out.resolve(strict=True)
    started = utc()
    commands = result / "commands.jsonl"

    with commands.open("x") as log:
        def run(*argv, expect=0, label=None, timeout=30):
            argv = list(map(str, argv))
            begin = utc()
            proc = subprocess.run(argv, cwd=repo, capture_output=True, timeout=timeout)
            row = {
                "label": label,
                "argv": argv,
                "started_at_utc": begin,
                "finished_at_utc": utc(),
                "exit_code": proc.returncode,
                "stdout": proc.stdout.decode(errors="replace"),
                "stderr": proc.stderr.decode(errors="replace"),
            }
            print(json.dumps(row), file=log, flush=True)
            assert expect is None or proc.returncode == expect, row
            return proc

        def get(*argv, **kwargs):
            return run(*argv, **kwargs).stdout.decode().strip()

        def stamp():
            assert get("git", "rev-parse", "HEAD") == args.commit
            actual = get("python3", "scripts/production_score.py", "--source-id")
            assert actual == args.source_id
            return actual

        before = stamp()
        supplied = json.loads(archive_receipt.read_text())
        assert supplied["source_commit"] == args.commit
        assert supplied["source_after"] == args.source_id
        assert supplied.get("source_before", supplied.get("source_id")) == args.source_id
        archive_sha256 = sha(archive)
        archive_blake3 = get(args.b3sum, "--no-names", archive)
        assert archive_sha256 == supplied["sha256"]
        assert archive_blake3 == supplied["blake3"]
        sidecars = {}
        for suffix, digest in (("sha256", archive_sha256), ("b3", archive_blake3)):
            sidecar = archive.with_name(archive.name + "." + suffix)
            assert sidecar.read_text().split() == [digest, archive.name]
            sidecars[suffix] = sha(sidecar)
        assert sha(args.wasm) == WASM_SHA256
        security = json.loads(get("docker", "info", "--format", "{{json .SecurityOptions}}"))
        assert "name=rootless" in security
        cases = {}

        with tempfile.TemporaryDirectory(prefix="entangle-linux-userspace-", dir="/workspace") as temporary:
            files = Path(temporary)
            files.chmod(0o755)
            plugins = files / "source"
            plugins.mkdir(mode=0o755)
            plugins.chmod(0o755)
            shutil.copyfile(repo / "plugins/json-pointer/entangle.toml", plugins / "entangle.toml")
            shutil.copyfile(args.wasm, files / "json-pointer.wasm")
            for item in (plugins / "entangle.toml", files / "json-pointer.wasm"):
                item.chmod(0o644)
            guest_tree = get("git", "rev-parse", args.commit + ":plugins/json-pointer")
            expected_elf = {name: supplied["files_sha256"][name] for name in BINS}
            elf = {}
            with tarfile.open(archive) as tf:
                stem = archive.name.removesuffix(".tar.gz")
                for name in BINS:
                    member = tf.getmember(f"{stem}/{name}")
                    assert member.isfile()
                    binary = files / name
                    with tf.extractfile(member) as old, binary.open("xb") as new:
                        shutil.copyfileobj(old, new)
                    binary.chmod(0o755)
                    assert sha(binary) == expected_elf[name]
                    headers = get("readelf", "-h", binary, label=name + ":architecture")
                    assert re.search(r"Machine:\s+Advanced Micro Devices X86-64", headers)
                    imports = get("readelf", "--version-info", binary, label=name + ":glibc-imports")
                    floor = max(re.findall(r"Name: GLIBC_([\d.]+)", imports), key=version)
                    if args.max_glibc:
                        assert version(floor) <= version(args.max_glibc)
                    elf[name] = {"sha256": expected_elf[name], "required_glibc": floor}
            fixture = {
                "component_sha256": WASM_SHA256,
                "manifest_sha256": sha(plugins / "entangle.toml"),
                "guest_source_tree": guest_tree,
            }
            for os_name, image, os_version, glibc in IMAGES:
                image_id = get("docker", "image", "inspect", image, "--format", "{{.Id}}")
                create = (
                    "docker", "run", "-d", "--rm", "--pull=never", "--platform=linux/amd64",
                    "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                    "--user=65534:65534", "--env", "HOME=/work/home", "--env", "ENTANGLE_ALLOW_LOCAL=0",
                    "--env", "TOKIO_WORKER_THREADS=2", "--env", "RAYON_NUM_THREADS=2",
                    "--tmpfs", "/work:rw,nosuid,nodev,noexec,mode=1777,size=64m",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m",
                    "--mount", f"type=bind,src={files},dst=/fixture,readonly", image_id, "sleep", "infinity",
                )
                cid = get(*create, label=os_name + ":container")
                daemon = None

                def ex(*argv):
                    return ("docker", "exec", cid, *argv)

                def cap(*argv, **kwargs):
                    return run(*ex(*argv), **kwargs)

                def inside(*argv, **kwargs):
                    return get(*ex(*argv), **kwargs)

                def cli(*argv, **kwargs):
                    return cap("/fixture/entangle", *argv, **kwargs)

                cell = {"image": image, "image_id": image_id, "os_version": os_version, "glibc": glibc}
                try:
                    assert get("docker", "inspect", cid, "--format", "{{.HostConfig.NetworkMode}}") == "none"
                    assert inside("id", "-u") == "65534"
                    assert len(inside("cat", "/proc/net/route").splitlines()) == 1
                    assert inside("uname", "-m") == "x86_64"
                    assert inside("sh", "-ec", '. /etc/os-release; printf "%s\\n" "$VERSION_ID"; getconf GNU_LIBC_VERSION') == f"{os_version}\nglibc {glibc}"
                    cell["versions"] = {}
                    for name in BINS:
                        assert inside("sha256sum", "/fixture/" + name).split()[0] == expected_elf[name]
                        compatible = version(glibc) >= version(elf[name]["required_glibc"])
                        proc = cap("/fixture/" + name, "--version", expect=None, label=os_name + ":" + name)
                        if compatible:
                            assert proc.returncode == 0 and proc.stdout == f"{name} 0.1.0\n".encode()
                        else:
                            assert proc.returncode and f"GLIBC_{elf[name]['required_glibc']}".encode() in proc.stderr
                        cell["versions"][name] = {
                            "exit_code": proc.returncode, "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(),
                        }
                    if any(item["exit_code"] for item in cell["versions"].values()):
                        cell["outcome"] = "glibc_loader_refused"
                        cases[os_name] = cell
                        continue
                    inside("mkdir", "-m", "700", "/work/home")
                    cli("init", "--non-interactive")
                    inside("sh", "-ec", 'printf "%s\\n" "[mesh]" "transports=[]" > "$HOME/.entangle/config.toml"')
                    output = cli("plugins", "build", "/fixture/source", "--wasm", "/fixture/json-pointer.wasm", "--out", "/work/signed").stdout.decode()
                    public_key = re.search(r"entangle keyring add ([a-f0-9]{64}) --name", output)[1]
                    plugin = re.search(r"entangle plugins invoke (\S+) --input", output)[1]
                    daemon_log = result / f"{os_name}-daemon.log"
                    boot = ex("sh", "-ec", 'printf "%s\\n" "$$" >/work/daemon.pid; exec /fixture/entangled run')
                    with daemon_log.open("xb") as stream:
                        daemon = subprocess.Popen(boot, stdout=stream, stderr=subprocess.STDOUT)
                        deadline = time.monotonic() + 12
                        while time.monotonic() < deadline:
                            assert daemon.poll() is None
                            if cap("test", "-S", "/work/home/.entangle/sock", expect=None).returncode == 0:
                                break
                            time.sleep(0.05)
                        else:
                            raise RuntimeError(f"{os_name}: no UDS")
                        status = json.loads(cli("mesh", "status", "--json").stdout)
                        assert re.fullmatch(r"[a-f0-9]{32}", status["local_peer_id"])
                        assert plugin == status["local_peer_id"] + "/json-pointer@0.1.0"
                        assert json.loads(cli("plugins", "list", "--json").stdout) == {"plugins": []}
                        denied = cli("plugins", "load", "/work/signed", expect=None)
                        assert denied.returncode and re.search(rb"trust|publisher|keyring|verification key", denied.stderr, re.I)
                        cli("keyring", "add", public_key, "--name", "disposable fixture publisher")
                        cli("plugins", "load", "/work/signed")
                        assert json.loads(cli("plugins", "list", "--json").stdout) == {"plugins": [plugin]}
                        signed_component = inside("sha256sum", "/work/signed/plugin.wasm").split()[0]
                        assert signed_component == WASM_SHA256
                        nonce = "Café JSON Pointer " + secrets.token_hex(16)
                        literal = json.dumps({"pointer": "#/a~1b/~0", "data": {"a/b": {"~": nonce}}}, ensure_ascii=False)
                        exact = cli("plugins", "invoke", plugin, "--raw", "--input", literal).stdout
                        expect = json.dumps(nonce, ensure_ascii=False).encode()
                        assert exact == expect
                        null = '{"pointer":"/value","data":{"value":null}}'
                        assert cli("plugins", "invoke", plugin, "--raw", "--input", null).stdout == b"null"
                        missing = '{"pointer":"/missing","data":{"value":null}}'
                        refusal = cli("plugins", "invoke", plugin, "--raw", "--input", missing, expect=None)
                        assert refusal.returncode and not refusal.stdout and b'object has no member' in refusal.stderr
                        inside("sh", "-ec", 'kill -TERM "$(cat /work/daemon.pid)"')
                        assert daemon.wait(15) == 0
                    cell.update(
                        outcome="signed_guest_passed", daemon_exit_code=daemon.returncode,
                        daemon_log_sha256=sha(daemon_log), node=status["local_peer_id"], plugin=plugin,
                        publisher_public_key=public_key, untrusted_load_exit=denied.returncode,
                        signed_component_sha256=signed_component, exact_utf8_output=exact.decode(),
                        expected_output=expect.decode(), output_sha256=hashlib.sha256(exact).hexdigest(),
                        null_output="null", missing_property_exit=refusal.returncode,
                    )
                    cases[os_name] = cell
                finally:
                    cap_cleanup = run("docker", "rm", "-f", cid, expect=None)
                    assert cap_cleanup.returncode == 0 or run("docker", "inspect", cid, expect=None).returncode
                    if daemon and daemon.poll() is None:
                        daemon.wait(15)
                assert run("docker", "inspect", cid, expect=None).returncode
        assert any(case["outcome"] == "signed_guest_passed" for case in cases.values())
        assert sha(archive) == archive_sha256
        assert sha(args.wasm) == WASM_SHA256
        after = stamp()
    data = {
        "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": after,
        "started_at_utc": started, "finished_at_utc": utc(), "exit_code": 0,
        "scope": "One x86-64 Linux host and four separate rootless containers with network disabled. Candidate archives are unsigned. WASI guest signatures are verified.",
        "archive_sha256": archive_sha256, "archive_blake3": archive_blake3, "archive_path": str(archive),
        "archive_receipt_sha256": sha(archive_receipt), "sidecars_sha256": sidecars,
        "fixture": fixture, "elf": elf, "cases": cases, "runner_sha256": sha(Path(__file__)),
        "command_log_sha256": sha(commands),
    }
    (result / "userspaces.json").write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({name: case["outcome"] for name, case in cases.items()}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("repo", "out", "archive", "archive-receipt", "wasm", "b3sum"):
        parser.add_argument("--" + option, type=Path, required=True)
    for option in ("commit", "source-id"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--max-glibc")
    execute(parser.parse_args())
