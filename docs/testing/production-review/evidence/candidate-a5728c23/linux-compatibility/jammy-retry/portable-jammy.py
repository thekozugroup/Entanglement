#!/usr/bin/env python3
"""Compile the frozen native CLI and daemon inside a monitored disconnected Jammy tmpfs."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

GIB = 2 ** 30
NAME = "entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
TOOLCHAIN = "/seed/toolchain"
RELEASE = "/build-target/target/x86_64-unknown-linux-gnu/release"
SOURCE = "/build-target/source"
KEY = Path("/workspace/entangle-package-seed.2uvRiy/public-repro-fixture-seed.pem")
READ_RSS = '''
total=0
for stat in /proc/[0-9]*/statm; do
    if read -r size rss rest 2>/dev/null < "$stat"; then
        total=$((total + rss))
    fi
done
printf '%s\\n' "$((total * $(getconf PAGESIZE)))"
'''

parser = argparse.ArgumentParser(description=__doc__)
for name in ("repo", "out", "b3sum"):
    parser.add_argument("--" + name, required=True, type=Path)
for name in ("commit", "source-id"):
    parser.add_argument("--" + name, required=True)
args = parser.parse_args()
out = args.out.resolve(strict=True)
repo = args.repo.resolve(strict=True)
b3sum = args.b3sum.resolve(strict=True)
provision_file = out / "jammy-provision.json"
build_script = Path(__file__).with_name("build-jammy.sh")
provision = json.loads(provision_file.read_text())
archive_tools_file = out / "jammy-archive-tools.json"
archive_tools = json.loads(archive_tools_file.read_text())
cid = provision["container"]
archive_dir = repo / "target/release-candidate" / (args.commit[:12] + "-ubuntu22")
buildlog = out / "jammy-build.log"
watchlog = out / "jammy-build-resources.jsonl"


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def get(*argv):
    return subprocess.check_output(argv, text=True, cwd=repo, timeout=20).strip()


def stamp():
    assert get("git", "rev-parse", "HEAD") == args.commit
    value = get("python3", "scripts/production_score.py", "--source-id")
    assert value == args.source_id
    return value


def kernel_file(name):
    return Path("/sys/fs/cgroup").joinpath(name).read_text()


def counters(text):
    return dict((name, int(value)) for name, value in map(str.split, text.splitlines()))


def measure():
    memavail = int(re.search(r"^MemAvailable:\s+(\d+) kB", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    stats = counters(kernel_file("memory.stat"))
    ev = counters(kernel_file("memory.events"))
    free = int(get("docker", "exec", cid, "sh", "-ec", "df -B1 /build-target | awk 'NR==2{print $4}'"))
    rss = int(get("docker", "exec", cid, "sh", "-ec", READ_RSS))
    return {
        "utc": utc(), "host_available_memory_bytes": memavail, "host_anon_plus_shmem_bytes": stats["anon"] + stats["shmem"],
        "oom_kill": ev["oom_kill"], "builder_process_rss_sum_bytes": rss,
        "builder_tmpfs_free_bytes": free, "builder_tmpfs_used_bytes": provision["tmpfs_cap_bytes"] - free,
    }


assert provision["source_before"] == provision["source_after"] == stamp()
assert provision["source_commit"] == args.commit and provision["exit_code"] == 0
assert archive_tools["source_before"] == archive_tools["source_after"] == args.source_id
assert archive_tools["source_commit"] == args.commit and archive_tools["exit_code"] == 0
assert archive_tools["container"] == cid
assert sha(out / "jammy-archive-dpkg.txt") == archive_tools["system_packages_sha256"]
assert sha(Path(provision["source_bundle"])) == provision["source_bundle_sha256"]
assert sha(repo / "Cargo.lock") == provision["lock_sha256"]
assert not archive_dir.exists()
assert not json.loads(get("docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"))
assert get("docker", "inspect", cid, "--format", "{{.Image}}") == provision["image_id"]
before = stamp()
start = utc()
build_status = None
messages = {}
samples = []
stopped_by = None
initial = None
cmd = [
    "docker", "exec", "--user", "65534:65534", cid,
    "/usr/bin/timeout", "--signal=TERM", "--kill-after=20s", "42m",
    "/bin/sh", "/tmp/entangle-build-jammy.sh", args.commit, provision["lock_sha256"],
]
try:
    assert get("docker", "exec", cid, "getconf", "GNU_LIBC_VERSION") == "glibc 2.35"
    assert get("docker", "exec", cid, "python3", "--version").startswith("Python 3.10.")
    get("docker", "cp", build_script, cid + ":/tmp/entangle-build-jammy.sh")
    get("docker", "exec", cid, "chmod", "0444", "/tmp/entangle-build-jammy.sh")
    get("docker", "exec", cid, "mkdir", "-p", "/opt/entangle-build/bin")
    get("docker", "cp", b3sum, cid + ":/opt/entangle-build/bin/b3sum")
    get("docker", "exec", cid, "chmod", "0555", "/opt/entangle-build/bin/b3sum")
    confined = ["docker", "exec", "--user", "65534:65534", cid]
    assert get(*confined, "sha256sum", "/opt/entangle-build/bin/b3sum").split()[0] == sha(b3sum)
    assert get(*confined, "sha256sum", "/tmp/entangle-build-jammy.sh").split()[0] == sha(build_script)
    messages["b3sum"] = get(*confined, "/opt/entangle-build/bin/b3sum", "--version")
    initial = measure()
    assert initial["host_available_memory_bytes"] >= 15 * GIB
    assert initial["host_anon_plus_shmem_bytes"] <= 6 * GIB
    assert initial["builder_tmpfs_used_bytes"] == 0
    with buildlog.open("xb") as output, watchlog.open("x") as activity:
        child = subprocess.Popen(cmd, cwd=repo, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 44 * 60
        while child.poll() is None:
            try:
                child.wait(timeout=12)
                break
            except subprocess.TimeoutExpired:
                pass
            row = measure()
            samples.append(row)
            print(json.dumps(row), file=activity, flush=True)
            limits = {
                "host available memory": row["host_available_memory_bytes"] < 9 * GIB,
                "host anon plus tmpfs": row["host_anon_plus_shmem_bytes"] > 16 * GIB,
                "builder process RSS sum": row["builder_process_rss_sum_bytes"] > 7 * GIB,
                "builder tmpfs almost full": row["builder_tmpfs_free_bytes"] < GIB // 4,
                "host OOM kill event": row["oom_kill"] != initial["oom_kill"],
                "outer deadline": time.monotonic() > deadline,
            }
            tripped = [name for name, violated in limits.items() if violated]
            if tripped:
                stopped_by = tripped
                get("docker", "rm", "-f", cid)
                child.wait(timeout=25)
                break
        build_status = child.returncode
    if build_status != 0:
        raise RuntimeError(f"portable compile exit {build_status}; guard={stopped_by}")
    assert samples
    # Export the unsigned checked archive and checksum sidecars, keeping the native target private.
    archive_dir.mkdir()
    for name in (NAME, NAME + ".sha256", NAME + ".b3"):
        container_path = "/build-target/archive/" + name
        expected = get("docker", "exec", cid, "sha256sum", container_path).split()[0]
        get("docker", "cp", cid + ":" + container_path, archive_dir / name)
        assert sha(archive_dir / name) == expected
    archive = archive_dir / NAME
    digest = sha(archive)
    blake = get(b3sum, "--no-names", archive)
    assert (archive_dir / (NAME + ".sha256")).read_text().split() == [digest, NAME]
    assert (archive_dir / (NAME + ".b3")).read_text().split() == [blake, NAME]
    files = {}
    with tarfile.open(archive) as tar:
        prefix = NAME.removesuffix(".tar.gz") + "/"
        for name in ("LICENSE", "README.md", "architecture.md", "tutorial.md", "entangle", "entangled"):
            member = tar.getmember(prefix + name)
            assert member.isfile()
            with tar.extractfile(member) as stream:
                files[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    for name in ("entangle", "entangled"):
        assert files[name] == get("docker", "exec", cid, "sha256sum", RELEASE + "/" + name).split()[0]
    for name, source in (("LICENSE", "LICENSE"), ("README.md", "README.md"),
                         ("architecture.md", "docs/architecture.md"), ("tutorial.md", "docs/tutorial.md")):
        assert files[name] == sha(repo / source)
    data = {
        "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": stamp(),
        "started_utc": start, "finished_utc": utc(), "exit_code": 0, "name": NAME,
        "archive_path": str(archive), "size": archive.stat().st_size, "sha256": digest, "blake3": blake,
        "files_sha256": files, "command": cmd, "build_script_sha256": sha(build_script),
        "tool_sha256": get("docker", "exec", cid, "sha256sum", RELEASE + "/cargo-entangle").split()[0],
        "build_log_sha256": sha(buildlog), "initial_resources": initial,
        "resource_log_sha256": sha(watchlog), "provision_receipt_sha256": sha(provision_file),
        "archive_tools_receipt_sha256": sha(archive_tools_file),
        "peaks": {
            "max_sampled_builder_rss": max(row["builder_process_rss_sum_bytes"] for row in samples),
            "max_sampled_tmpfs_bytes": max(row["builder_tmpfs_used_bytes"] for row in samples),
            "min_sampled_host_available_memory": min(row["host_available_memory_bytes"] for row in samples),
        },
        "signing_status": "unsigned local compatibility candidate built in pinned Jammy",
    }
    with (out / "jammy-linux-archive.json").open("x") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"archive": str(archive), "sha256": digest, "b3": blake, "peaks": data["peaks"]}))

    # Keep the hello-world package control independent of native release success.
    if measure()["builder_tmpfs_free_bytes"] >= GIB // 2:
        staged_key = "/tmp/entangle-public-repro-fixture.pem"
        get("docker", "cp", KEY, cid + ":" + staged_key)
        get("docker", "exec", cid, "chmod", "0444", staged_key)
        hello_archive = "/build-target/hello-world-repro.tar.zst"
        hello_command = [
            "docker", "exec", "--user", "65534:65534", "--workdir=/build-target", cid, "/usr/bin/timeout", "300s",
            "/usr/bin/env", "PATH=" + RELEASE + ":" + TOOLCHAIN + "/bin:/usr/bin:/bin", "HOME=/build-target/home",
            "CARGO_HOME=/build-target/cargo-home", "CARGO_NET_OFFLINE=true", "CARGO_BUILD_JOBS=2",
            "CARGO_INCREMENTAL=0", TOOLCHAIN + "/bin/cargo", "entangle", "package", SOURCE + "/examples/hello-world",
            "--source-url", "https://github.com/thekozugroup/Entanglement.git", "--key", staged_key,
            "--out", hello_archive,
        ]
        hello_log = out / "jammy-hello-world-package.log"
        hello_start = utc()
        with hello_log.open("xb") as stream:
            hello_status = subprocess.run(hello_command, cwd=repo, stdout=stream, stderr=subprocess.STDOUT).returncode
        (out / "jammy-hello-world-package.json").write_text(json.dumps({
            "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": stamp(),
            "started_utc": hello_start, "finished_utc": utc(), "command": hello_command, "exit_code": hello_status,
            "log_sha256": sha(hello_log), "tool_sha256": data["tool_sha256"],
            "archive_sha256": get("docker", "exec", cid, "sha256sum", hello_archive).split()[0] if hello_status == 0 else None,
            "archive_size": int(get("docker", "exec", cid, "stat", "-c", "%s", hello_archive)) if hello_status == 0 else None,
        }, indent=2) + "\n")
finally:
    present = subprocess.run(["docker", "inspect", cid], capture_output=True, timeout=15).returncode == 0
    if present:
        get("docker", "rm", "-f", cid)
    assert subprocess.run(["docker", "inspect", cid], capture_output=True, timeout=15).returncode
    if not (out / "jammy-linux-archive.json").is_file():
        report = {
            "source_commit": args.commit, "source_id": before, "source_before": before, "source_after": stamp(),
            "started_utc": start, "finished_utc": utc(), "exit_code": 1, "build_exit_code": build_status,
            "guard": stopped_by, "command": cmd, "initial_resources": initial, "recorded_samples": len(samples),
            "build_log_sha256": sha(buildlog) if buildlog.is_file() else None,
            "resource_log_sha256": sha(watchlog) if watchlog.is_file() else None,
        }
        with (out / "jammy-build-failure.json").open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
