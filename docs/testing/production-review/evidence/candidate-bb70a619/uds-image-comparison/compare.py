"""Matched local UDS 6 MiB signed image dispatch engineering comparison."""

import argparse
import binascii
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import signal
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zlib


ROOT = Path("/workspace/Entanglement")
BASELINE_COMMIT = "42bb9a3360ce2b4d5bcf2268dfa5a76bc6d6247e"
BASELINE_SOURCE = "sha256:fcb2f28c293a30b2496d2a788442782aba96c3806d4e4d1e868d4c6db32dc348"
BASELINE = ROOT / "target/release-candidate" / BASELINE_COMMIT[:12]
OLD_ARCHIVE = BASELINE / "entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ORDERS = [["baseline", "candidate"] if i % 2 == 0 else ["candidate", "baseline"] for i in range(6)]
WARM_COUNT = 3


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def product_stamp():
    return {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_id": subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"],
                                             cwd=ROOT, text=True).strip(),
    }


def env_for(home):
    env = {**os.environ, "HOME": str(home), "RUST_LOG": "warn",
           "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "2"}
    env.pop("ENTANGLE_ALLOW_LOCAL", None)
    return env


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data))


def fixture_png(path, side, seed):
    stride = side * 6
    raw = random.Random(seed).randbytes(side * stride)
    scan = b"".join(b"\0" + raw[i:i+stride] for i in range(0, len(raw), stride))
    packets = (
        (b"IHDR", struct.pack(">IIBBBBB", side, side, 16, 2, 0, 0, 0)),
        (b"gAMA", struct.pack(">I", 100_000)),
        (b"cHRM", struct.pack(">8I", 31_270, 32_900, 64_000, 33_000, 30_000, 60_000, 15_000, 6000)),
        (b"IDAT", zlib.compress(scan, 1)),
        (b"IEND", b""),
    )
    path.write_bytes(PNG_SIGNATURE + b"".join(chunk(kind, data) for kind, data in packets))


def validate_png(path, side):
    buffer = path.read_bytes()
    assert buffer.startswith(PNG_SIGNATURE) and len(buffer) < 16 * 1024 * 1024
    at = len(PNG_SIGNATURE)
    kinds = []
    compressed = bytearray()
    while at < len(buffer):
        size, kind = struct.unpack_from(">I4s", buffer, at)
        at += 8
        data = buffer[at:at+size]
        assert len(data) == size
        at += size
        assert struct.unpack_from(">I", buffer, at)[0] == binascii.crc32(kind + data), kind
        at += 4
        kinds.append(kind)
        if kind == b"IHDR":
            assert struct.unpack(">IIBBBBB", data) == (side, side, 16, 2, 0, 0, 0)
        elif kind == b"gAMA":
            assert struct.unpack(">I", data) == (100_000,)
        elif kind == b"cHRM":
            assert struct.unpack(">8I", data) == (31_270, 32_900, 64_000, 33_000, 30_000, 60_000, 15_000, 6000)
        elif kind == b"IDAT":
            compressed.extend(data)
        elif kind != b"IEND":
            raise AssertionError(f"unexpected PNG metadata {kind}")
    assert kinds[:3] == [b"IHDR", b"gAMA", b"cHRM"] and kinds[-1] == b"IEND"
    assert set(kinds[3:-1]) == {b"IDAT"}
    assert len(zlib.decompress(compressed)) == (side * 6 + 1) * side
    return hashlib.sha256(buffer).hexdigest()


def require_exec(command, env=None):
    result = subprocess.run(command, env=env, cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"{shlex.join(map(str, command))} returned {result.returncode}: "
                           f"{result.stderr}\n{result.stdout}")
    return result


def binary_digests(directory):
    return {name: sha(directory / name) for name in ("entangle", "entangled")}


def baseline_bins(directory):
    return directory / "baseline" / OLD_ARCHIVE.name.removesuffix(".tar.gz")


def prepare(work, wasm):
    work.mkdir(mode=0o700)
    manifest = json.loads((BASELINE / "verification.json").read_text())
    assert manifest["source_commit"] == BASELINE_COMMIT
    assert manifest["source_id"] == manifest["source_after"] == BASELINE_SOURCE
    assert manifest["sha256"] == sha(OLD_ARCHIVE)
    (work / "baseline").mkdir()
    with tarfile.open(OLD_ARCHIVE) as archive:
        archive.extractall(work / "baseline", filter="data")
    bins = baseline_bins(work)
    assert binary_digests(bins) == {n: manifest["files_sha256"][n] for n in ("entangle", "entangled")}
    fixture_png(work / "warm-64.png", 64, 1024)
    fixture_png(work / "timed-1024.png", 1024, 0x20261127)
    for side, payload in ((64, "warm-64.png"), (1024, "timed-1024.png")):
        validate_png(work / payload, side)
    signer = work / "signer"
    signer.mkdir()
    cli = bins / "entangle"
    require_exec([cli, "init", "--non-interactive"], env_for(signer))
    package = work / "package"
    require_exec([cli, "plugins", "build", ROOT / "plugins/image-dehaze", "--wasm", wasm,
                  "--out", package], env_for(signer))
    assert sha(package / "plugin.wasm") == sha(wasm)
    certificate = subprocess.check_output([
        "openssl", "pkey", "-in", signer / ".entangle/identity.key", "-pubout", "-outform", "DER"])
    assert len(certificate) == 44 and certificate[:12].hex() == "302a300506032b6570032100"
    plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
    record = {
        "prepared_utc": now(), "orders": ORDERS, "warm_calls_per_process": WARM_COUNT,
        "timed_calls_per_process": 1, "baseline_commit": BASELINE_COMMIT,
        "baseline_source": BASELINE_SOURCE, "baseline_archive_sha256": manifest["sha256"],
        "baseline_binary_sha256": binary_digests(bins), "plugin_id": plugin,
        "publisher_key": certificate[-32:].hex(),
        "signed_package_sha256": {p.name: sha(p) for p in sorted(package.iterdir()) if p.is_file()},
        "timed_input_bytes": (work / "timed-1024.png").stat().st_size,
        "input_sha256": {name: sha(work / name) for name in ("warm-64.png", "timed-1024.png")},
        "method": "fresh isolated daemons for all 12 arms, exact local trusted peer, no mesh network",
        "wall_clock": "starts before launching the CLI and ends after wait4 reaps the child, includes UDS, guest and output-file write",
        "memory": "Linux wait4 child ru_maxrss KiB; daemon /proc VmHWM KiB before/after each timed call",
        "scope": "engineering comparator, Linux x86_64, one localhost plugin workload",
    }
    assert 6_000_000 < record["timed_input_bytes"] < 7_000_000
    (work / "plan.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


@contextmanager
def node(bins, home, plan, work):
    home.mkdir()
    environment = env_for(home)
    cli = bins / "entangle"
    peer_output = require_exec([cli, "init", "--non-interactive"], environment).stdout
    peer = re.search(r"Fingerprint:\s*([0-9a-f-]+)", peer_output)[1].replace("-", "")
    require_exec([cli, "keyring", "add", plan["publisher_key"], "--name", "UDS comparator fixture"], environment)
    state = home / ".entangle"
    (state / "config.toml").write_text("[mesh]\ntransports = []\n")
    with (home / "daemon.log").open("wb") as log:
        process = subprocess.Popen([bins / "entangled", "run"], env=environment, cwd=ROOT,
                                   stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not (state / "sock").is_socket():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError((home / "daemon.log").read_text())
                time.sleep(.025)
            assert sha(Path(f"/proc/{process.pid}/exe")) == sha(bins / "entangled")
            require_exec([cli, "plugins", "load", work / "package"], environment)
            yield environment, peer, process.pid
        finally:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
                raise


def proc_kib(pid, field):
    data = Path(f"/proc/{pid}/status").read_text()
    match = re.search(rf"(?m)^{field}:\s+(\d+) kB$", data)
    assert match, field
    return int(match[1])


def dispatch_command(bins, plan, peer, payload, output):
    return [bins / "entangle", "compute", "dispatch", plan["plugin_id"], "--input-file", payload,
            "--output-file", output, "--timeout-ms", "30000", "--integrity", "trusted-executor",
            "--allow", peer]


def timed_exec(command, environment, log_path):
    def timeout(signum, frame):
        raise TimeoutError("timed CLI call exceeded 60 seconds")

    previous = signal.signal(signal.SIGALRM, timeout)
    with log_path.open("wb") as log:
        start = time.perf_counter_ns()
        process = subprocess.Popen(command, env=environment, cwd=ROOT, stdout=log, stderr=log)
        signal.setitimer(signal.ITIMER_REAL, 60)
        try:
            pid, status, usage = os.wait4(process.pid, 0)
            wall_ms = (time.perf_counter_ns() - start) / 1_000_000
            assert pid == process.pid
            process.returncode = os.waitstatus_to_exitcode(status)
        except TimeoutError:
            process.kill()
            process.wait(5)
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    stderr = log_path.read_text()
    if process.returncode:
        raise RuntimeError(f"{shlex.join(map(str, command))} returned {process.returncode}: {stderr}")
    return wall_ms, usage, stderr


def arm(kind, pair, bins, work, plan, golden):
    with tempfile.TemporaryDirectory(prefix=f"ent-uds-{pair}-{kind}-", dir="/tmp") as temp:
        home = Path(temp) / "node"
        with node(bins, home, plan, work) as (env, peer, pid):
            warm = work / "warm-64.png"
            for i in range(WARM_COUNT):
                output = home / f"warm-{i}.png"
                completed = require_exec(dispatch_command(bins, plan, peer, warm, output), env)
                assert f"Chosen: {peer}" in completed.stderr, completed.stderr
                digest = validate_png(output, 64)
                assert golden.setdefault("warm", digest) == digest
            warm_hwm = proc_kib(pid, "VmHWM")
            warm_current = proc_kib(pid, "VmRSS")
            payload = work / "timed-1024.png"
            output = home / "timed.png"
            command = dispatch_command(bins, plan, peer, payload, output)
            start_utc = now()
            wall_ms, usage, stderr = timed_exec(command, env, home / "timed.log")
            daemon_hwm = proc_kib(pid, "VmHWM")
            daemon_current = proc_kib(pid, "VmRSS")
            assert f"Chosen: {peer}" in stderr, stderr
            digest = validate_png(output, 1024)
            assert golden.setdefault("timed", digest) == digest
            return {
                "started_utc": start_utc, "pair": pair, "route": kind, "wall_ms": wall_ms,
                "chosen_peer": peer, "daemon_pid": pid, "command": list(map(str, command)),
                "cli_peak_rss_kib": usage.ru_maxrss, "cli_user_seconds": usage.ru_utime,
                "cli_system_seconds": usage.ru_stime, "daemon_warm_peak_rss_kib": warm_hwm,
                "daemon_warm_rss_kib": warm_current, "daemon_peak_rss_kib": daemon_hwm,
                "daemon_after_rss_kib": daemon_current, "output_sha256": digest,
                "output_size": output.stat().st_size,
            }


def host_limits():
    cgroup = Path("/sys/fs/cgroup")
    return {name: (cgroup / name).read_text().strip() for name in
            ("cpu.max", "cpu.stat", "memory.max") if (cgroup / name).is_file()}


def live_compilers():
    output = subprocess.check_output(["ps", "-eo", "pid=,stat=,comm="], text=True)
    compiler_names = {"cargo", "rustc", "cc", "gcc", "clang", "ld", "ld.lld", "lld"}
    return [{"pid": int(pid), "state": state, "command": name}
            for line in output.splitlines() if len(parts := line.split()) == 3
            for pid, state, name in [parts] if not state.startswith("Z") and name in compiler_names]


def run(work, candidate, commit, source, out, candidate_archive):
    plan = json.loads((work / "plan.json").read_text())
    expected = {"commit": commit, "source_id": source}
    assert product_stamp() == expected
    baseline = baseline_bins(work)
    baseline_sha = binary_digests(baseline)
    candidate_sha = binary_digests(candidate)
    assert baseline_sha == plan["baseline_binary_sha256"]

    archive_receipt = None
    if candidate_archive is not None:
        manifest_path = candidate_archive.with_name("verification.json")
        manifest = json.loads(manifest_path.read_text())
        assert manifest["source_commit"] == commit and manifest["source_id"] == manifest["source_after"] == source
        assert manifest["name"] == candidate_archive.name and manifest["sha256"] == sha(candidate_archive)
        assert candidate_sha == {name: manifest["files_sha256"][name] for name in candidate_sha}
        archive_receipt = {"name": str(candidate_archive), "sha256": manifest["sha256"],
                           "receipt_sha256": sha(manifest_path)}
    for name, wanted in plan["input_sha256"].items():
        assert sha(work / name) == wanted
    for name, wanted in plan["signed_package_sha256"].items():
        assert sha(work / "package" / name) == wanted
    assert hasattr(os, "wait4")
    golden = {}
    trials = []
    limits_before = host_limits()
    compiler_observations = []
    started = now()
    for i, order in enumerate(ORDERS, 1):
        for route in order:
            compiler_observations.append({"at": now(), "pair": i, "route": route,
                                          "started": live_compilers()})
            result = arm(route, i, baseline if route == "baseline" else candidate, work, plan, golden)
            trials.append(result)
            with out.with_suffix(".partial.jsonl").open("a") as partial:
                partial.write(json.dumps(result) + "\n")
            compiler_observations[-1]["finished"] = live_compilers()
            print(f"pair {i} {route} {result['wall_ms']:.2f} ms "
                  f"CLI {result['cli_peak_rss_kib']} KiB daemon {result['daemon_peak_rss_kib']} KiB",
                  flush=True)
    assert product_stamp() == expected and binary_digests(candidate) == candidate_sha
    assert binary_digests(baseline) == baseline_sha and len(trials) == 12
    assert len({r["daemon_pid"] for r in trials}) == 12 and len({r["chosen_peer"] for r in trials}) == 12
    assert all(r["output_sha256"] == golden["timed"] for r in trials)
    keys = ("wall_ms", "cli_peak_rss_kib", "daemon_peak_rss_kib", "daemon_warm_peak_rss_kib")
    medians = {
        route: {key: statistics.median(r[key] for r in trials if r["route"] == route) for key in keys}
        for route in ("baseline", "candidate")
    }
    ratios = {
        key: [next(r[key] for r in trials if r["pair"] == i and r["route"] == "candidate") /
              next(r[key] for r in trials if r["pair"] == i and r["route"] == "baseline")
              for i in range(1, len(ORDERS) + 1)]
        for key in keys
    }
    report = {
        "candidate": expected, "candidate_binary_sha256": candidate_sha, "candidate_archive": archive_receipt,
        "started_utc": started, "finished_utc": now(), "platform": dict(zip(("sysname", "nodename", "release", "version", "machine"), os.uname(), strict=True)),
        "allowed_cpus": sorted(os.sched_getaffinity(0)), "plan": plan,
        "cgroup_before": limits_before, "cgroup_after": host_limits(),
        "compiler_observations_at_arm_boundaries": compiler_observations,
        "driver_sha256": sha(__file__), "plan_sha256": sha(work / "plan.json"),
        "command": [sys.executable, *sys.argv], "all_calls_have_identical_output": golden,
        "route_medians": medians, "paired_candidate_over_baseline": ratios, "trials": trials,
    }
    with out.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(medians, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--work", required=True, type=Path)
    prep.add_argument("--wasm", required=True, type=Path)
    test = sub.add_parser("run")
    test.add_argument("--work", required=True, type=Path)
    test.add_argument("--candidate-dir", required=True, type=Path)
    test.add_argument("--candidate-archive", type=Path)
    test.add_argument("--commit", required=True)
    test.add_argument("--source-id", required=True)
    test.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.cmd == "prepare":
        prepare(args.work.resolve(), args.wasm.resolve(strict=True))
    else:
        run(args.work.resolve(strict=True), args.candidate_dir.resolve(strict=True),
            args.commit, args.source_id, args.out, args.candidate_archive)


if __name__ == "__main__":
    main()
