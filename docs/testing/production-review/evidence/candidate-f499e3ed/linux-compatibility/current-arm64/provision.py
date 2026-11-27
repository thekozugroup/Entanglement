#!/usr/bin/env python3
"""Provision minimal Debian with authenticated cross tools and an exact tmpfs Rust sysroot."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

work = Path(__file__).resolve().parent
proof = work / "proof"
frozen = (work / "frozen").resolve(strict=True)
repo = Path("/workspace/Entanglement")
commit = "f499e3edf84e20f550312d05df51b9ea4e7cc699"
source_id = "sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa"
old = repo / "docs/testing/production-review/evidence/candidate-c19ef758/emulated-linux-arm64"
previous = repo / "docs/testing/production-review/evidence/candidate-a0926c6e/glibc-compat/build.json"
mixed = repo / "docs/testing/production-review/evidence/candidate-296b427a/mixed-release-arm64/mixed-release-arm64.json"
arm_input = json.loads((old / "inputs.json").read_bytes())
pinned_rust = json.loads(previous.read_bytes())["compiler"]
stdlib = Path(arm_input["ruststd_source"])
seed = Path("/workspace/entangle-jammy-release-mjuyx5hl/fixture")
emulator = Path("/workspace/entangle-mix-296b.3eCSwyYF/emulator")
debian_image = "debian@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0"
image_id = "sha256:cf7c9dcedc058a74762f2e1f01f6254e2376f3752452ddb347c1bb2a17618fd7"

def utc():
    return datetime.now(timezone.utc).isoformat()

def call(*command, cwd=repo):
    return subprocess.check_output(command, cwd=cwd, text=True, timeout=45).strip()

def sha(path):
    with path.open("rb") as infile:
        return hashlib.file_digest(infile, "sha256").hexdigest()

def write(filename, data):
    with (proof / filename).open("x") as output:
        json.dump(data, output, indent=2)
        output.write("\n")

def stamp(path):
    assert call("git", "rev-parse", "HEAD", cwd=path) == commit
    assert call(sys.executable, "scripts/production_score.py", "--source-id", cwd=path) == source_id
    return source_id

started = utc()
assert stamp(repo) == stamp(frozen)
assert shutil.disk_usage(work).free >= 768 * 1024**2
security = json.loads(call("docker", "info", "--format", "{{json .SecurityOptions}}"))
assert "name=rootless" in security
assert call("docker", "image", "inspect", "--format", "{{.Id}}", debian_image) == image_id
compiler_inputs = {name: sha(seed / "toolchain/bin" / name) for name in ("cargo", "rustc")}
assert compiler_inputs == pinned_rust
stdlib_hashes = {str(path.relative_to(stdlib)): sha(path) for path in stdlib.rglob("*") if path.is_file()}
assert stdlib_hashes == arm_input["ruststd_file_sha256"]
emulation = json.loads(mixed.read_bytes())["emulation"]
assert sha(emulator / "qemu-aarch64") == emulation["emulator_sha256"]
registry = next((seed / "registry/cache").iterdir())
packages = [row for row in tomllib.loads((frozen / "Cargo.lock").read_text())["package"] if "checksum" in row]
for row in packages:
    assert sha(registry / f"{row['name']}-{row['version']}.crate") == row["checksum"]
write("inputs.json", {
    "commit": commit, "source_before": source_id, "Cargo.lock": sha(frozen / "Cargo.lock"),
    "ruststd_file_sha256": stdlib_hashes, "ruststd_source": str(stdlib), "compiler_sha256": compiler_inputs,
    "registry_cache": str(registry), "registry_package_entries": len(packages),
    "registry_validation": "All registry archive SHA-256 digests matched the exact source Cargo.lock before build.",
    "image_id": image_id, "qemu_sha256": emulation["emulator_sha256"], "qemu_provenance_sha256": sha(mixed),
    "old_toolchain_inputs_sha256": sha(old / "inputs.json"),
})
create = [
    "docker", "create", "--pull=never", "--name", "entangle-arm64-f499e3ed-slim",
    "--network", "bridge", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "12g",
    "--tmpfs", "/private:rw,nosuid,nodev,exec,size=6g,mode=1777",
]
for loc, destination in ((frozen, "/src"), (seed, "/seed"), (emulator, "/emu")):
    create.extend(["--mount", f"type=bind,src={loc},dst={destination},readonly"])
create.extend([image_id, "sleep", "infinity"])
container = call(*create)
write("container.json", {"id": container, "image": image_id, "command": create})
retain = False
try:
    assert call("docker", "start", container) == container
    with (proof / "provision-tools.log").open("x") as log:
        subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-s"], input=(proof / "provision-tools.sh").read_text(),
            text=True, stdout=log, stderr=subprocess.STDOUT, timeout=540, check=True,
        )
    call("docker", "network", "disconnect", "bridge", container)
    inspected = json.loads(call("docker", "inspect", container))[0]
    networks = inspected["NetworkSettings"]["Networks"]
    assert not networks and not inspected["HostConfig"]["Privileged"]
    assert all(not item["RW"] for item in inspected["Mounts"] if item["Type"] == "bind")
    raw = ["docker", "exec", container]
    assert len(call(*raw, "/bin/cat", "/proc/net/route").splitlines()) == 1
    call(*raw, "cp", "-a", "/seed/toolchain", "/private/toolchain")
    target_dir = "/private/toolchain/lib/rustlib/aarch64-unknown-linux-gnu"
    call(*raw, "mkdir", "-p", target_dir)
    tar_command = ["tar", "-C", str(stdlib), "-cf", "-", "."]
    unpack = ["docker", "exec", "-i", container, "tar", "-xf", "-", "-C", target_dir]
    with subprocess.Popen(tar_command, stdout=subprocess.PIPE) as sender:
        try:
            subprocess.run(unpack, stdin=sender.stdout, timeout=90, check=True)
        finally:
            sender.stdout.close()
        assert sender.wait(timeout=20) == 0
    actual_stdlib = {}
    for name in stdlib_hashes:
        actual_stdlib[name] = call(*raw, "sha256sum", target_dir + "/" + name).split()[0]
    assert actual_stdlib == stdlib_hashes
    actual_compiler = {
        name: call(*raw, "sha256sum", "/private/toolchain/bin/" + name).split()[0]
        for name in ("cargo", "rustc")
    }
    assert actual_compiler == compiler_inputs
    version = call(*raw, "/private/toolchain/bin/rustc", "-Vv")
    assert "release: 1.91.1" in version
    call("docker", "cp", proof / "cross-build.sh", container + ":/tmp/cross-build.sh")
    assert call(*raw, "sha256sum", "/tmp/cross-build.sh").split()[0] == sha(proof / "cross-build.sh")
    after = stamp(frozen)
    assert stamp(repo) == after
    assert {name: sha(seed / "toolchain/bin" / name) for name in compiler_inputs} == compiler_inputs
    assert {str(path.relative_to(stdlib)): sha(path) for path in stdlib.rglob("*") if path.is_file()} == stdlib_hashes
    data = {
        "source_commit": commit, "source_before": source_id, "source_after": after,
        "started_utc": started, "finished_utc": utc(), "exit_code": 0,
        "rootless": True, "privileged": False, "networks_after_provision": networks,
        "tmpfs": inspected["HostConfig"]["Tmpfs"], "before_build_disk_available": shutil.disk_usage(work).free,
        "root_image": image_id, "image_pin": debian_image, "cargo_network": "off", "binfmt_registered": False,
        "compiler_sha256_in_tmpfs": actual_compiler, "std_lib_sha256_in_tmpfs": actual_stdlib,
        "rustc_version": version, "streamed_stdlib": [tar_command, unpack],
        "package_log_sha256": sha(proof / "provision-tools.log"),
    }
    write("provision.json", data)
    retain = True
finally:
    if not retain:
        call("docker", "rm", "-f", container)
