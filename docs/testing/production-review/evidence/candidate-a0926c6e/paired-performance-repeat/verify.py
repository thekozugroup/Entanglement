"""Rerun frozen large-image and tiny greeting paths with paired CPU placement."""
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib

DIR = Path(__file__).resolve().parent
ROOT = DIR.parents[5]
PRIMARY = json.loads((DIR.parent / "performance.json").read_text())
BB = "/tmp/entangle-recovery-performance-a0926c6e"
BINS = {route: Path(BB) / route for route in ("baseline", "candidate")}
WASM = ROOT / "target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm"
IMAGE = Path("/usr/share/matplotlib/mpl-data/sample_data/grace_hopper.jpg")
TINY = next(p for p in (ROOT / "target/debug/deps").glob("daemon_compute-*") if p.is_file() and os.access(p, os.X_OK) and hashlib.sha256(p.read_bytes()).hexdigest() == PRIMARY["driver_sha256"])
ORDERS = [("baseline", "candidate") if i % 2 == 0 else ("candidate", "baseline") for i in range(6)]
A = runpy.run_path(str(ROOT / "scripts/benchmark_image_batch.py"))
HOST_CPUS = sorted(os.sched_getaffinity(0))


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as reader:
        return hashlib.file_digest(reader, "sha256").hexdigest()


def stamp():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source = subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"],
                                     cwd=ROOT, text=True).strip()
    assert revision == PRIMARY["candidate_commit"] and source == PRIMARY["source_id"] == PRIMARY["source_after"]
    return dict(commit=revision, source_id=source)


def dump(path, data):
    with path.open("x") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def compiler_census():
    names = {"cargo", "rustc", "clang", "cc", "ld", "ld.lld"}
    return [line.strip() for line in subprocess.check_output(["ps", "-eo", "pid=,stat=,comm="], text=True).splitlines()
            if len(fields := line.split()) == 3 and fields[-1] in names and fields[1][0] != "Z"]


def masks(nodes):
    records = {}
    for role, pid in nodes.items():
        threads = {}
        for task in Path(f"/proc/{pid}/task").iterdir():
            try:
                threads[task.name] = sorted(os.sched_getaffinity(int(task.name)))
            except ProcessLookupError:
                continue
        assert threads, role
        expected = [0, 1, 2] if role == "worker" else [3]
        assert all(value == expected for value in threads.values()), (role, threads)
        records[role] = threads
    return records


def image_arm(side, pair, work, package, plugin, publisher, cases):
    started = now()
    binaries = BINS[side]
    with tempfile.TemporaryDirectory(prefix="ent-one-image-", dir="/tmp") as tmp, ExitStack() as cleanup:
        profiles = Path(tmp)
        worker = A["Node"](profiles / "worker", binaries / "entangle")
        coordinator = A["Node"](profiles / "coordinator", binaries / "entangle")
        coordinator.trust(worker)
        worker.trust(coordinator)
        worker.command("keyring", "add", publisher, "--name", "image comparison publisher")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        worker.start(cleanup, binaries / "entangled", port, [], cpu="0,1,2")
        worker.command("plugins", "load", package)
        coordinator.start(cleanup, binaries / "entangled", 0, [f"{worker.key}@127.0.0.1:{port}"], cpu=3)
        assert coordinator.rpc("plugins/list", {})["plugins"] == []
        messages = [A["dispatch_frame"](plugin, payload, [worker.peer]) for payload, _ in cases]
        deadline = time.monotonic() + 30
        while True:
            try:
                result = A["decoded"](A["exchange"](coordinator.sock, messages[0])[1])
                break
            except RuntimeError as exc:
                if "no live workers" not in str(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
        assert result["chosen_peer"] == worker.peer
        first, _ = A["verify_png"](bytes(result["output"]), cases[0][1])
        golden = {0: first}
        processes = {"runner": os.getpid(), "coordinator": coordinator.pid, "worker": worker.pid}
        actual_masks = masks(processes)
        before = compiler_census()
        warm = {}
        trials = {}
        for route, client in (("one_remote", coordinator), ("local", worker)):
            def batch():
                return A["measure"](route, client, messages, [worker.peer], cases, golden, processes)
            warm[route] = batch()
            trials[route] = [batch() for _ in range(3)]
        after = compiler_census()
        digest = hashlib.sha256(b"".join(bytes.fromhex(golden[i]) for i in range(len(cases)))).hexdigest()
        assert digest == PRIMARY["image"][side]["png_digest_list_sha256"]
        record = {
            "pair": pair, "side": side, "started_utc": started, "finished_utc": now(),
            "actual_thread_affinity_at_warmup": actual_masks, "compiler_census_before_and_after": [before, after],
            "peer": worker.peer, "golden_output_sha256": digest, "warm": warm, "trials": trials,
        }
        dump(DIR / f"image-{pair}-{side}.json", record)
        return record


def tiny_arm(side, pair):
    start = now()
    log_path = DIR / f"greeting-{pair}-{side}.log"
    env = {**os.environ, "ENTANGLE_BENCH_DAEMON": str(BINS[side] / "entangled")}
    command = ["taskset", "-c", "0-3", str(TINY), "benchmark::measure_dispatch", "--exact", "--ignored", "--nocapture"]
    cpu_before = compiler_census()
    with log_path.open("x") as log:
        subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    parsed = []
    pattern = r"(local|remote) concurrency=(\d+) requests=(\d+) p50_ms=([\d.]+) p95_ms=([\d.]+) requests_per_s=([\d.]+)"
    for line in log_path.read_text().splitlines():
        if match := re.fullmatch(pattern, line):
            route, clients, n, p50, p95, rate = match.groups()
            parsed.append(dict(route=route, clients=int(clients), calls=int(n),
                               p50_ms=float(p50), p95_ms=float(p95), rate=float(rate)))
    assert len(parsed) == 4 and sum(r["calls"] for r in parsed) == 4096
    selected, = (r for r in parsed if r["route"] == "remote" and r["clients"] == 1)
    return dict(pair=pair, side=side, start=start, end=now(), cpu_affinity=[0,1,2,3],
                compiler_census_before_and_after=[cpu_before, compiler_census()],
                command=command, daemon=str(BINS[side] / "entangled"), log=log_path.name,
                log_sha256=sha(log_path), all_routes=parsed, remote_one=selected)


def summarize(rows):
    keys = ("p50_ms", "p95_ms", "rate")
    builds = {}
    for side in BINS:
        builds[side] = {key: statistics.median(r[key] for r in rows if r["side"] == side) for key in keys}
    pairs = []
    for i in range(1, 7):
        before, = (r for r in rows if r["pair"] == i and r["side"] == "baseline")
        after, = (r for r in rows if r["pair"] == i and r["side"] == "candidate")
        pairs.append(dict(pair=i, **{key: after[key] / before[key] for key in keys}))
    ratios = {k: dict(median=statistics.median(row[k] for row in pairs),
                      minimum=min(row[k] for row in pairs), maximum=max(row[k] for row in pairs)) for k in keys}
    return dict(arm_medians=rows, build_medians=builds, pairs=pairs, ratios=ratios,
                p95_limit_misses=sum(r["p95_ms"] > 1.05 for r in pairs),
                rate_limit_misses=sum(r["rate"] < .95 for r in pairs))


def main():
    before = stamp()
    started = now()
    assert HOST_CPUS == [0,1,2,3,4]
    assert sha(TINY) == PRIMARY["driver_sha256"]
    sha_images = {}
    for side,bins in BINS.items():
        assert sha(bins / "entangled") == PRIMARY["daemons"][side]
        assert sha(bins / "entangle") == PRIMARY["cli_sha256"]
        data = PRIMARY["image"][side]
        assert sha(WASM) == data["wasm_sha256"] and sha(IMAGE) == data["source_sha256"]
        assert A["pillow_version"] == data["pillow_version"]
    os.sched_setaffinity(0, {3})
    cases = A["corpus"](IMAGE)
    inputs = hashlib.sha256(b"".join(payload for payload, _ in cases)).hexdigest()
    assert all(inputs == data["input_sha256"] for data in PRIMARY["image"].values())
    image_results = []
    with tempfile.TemporaryDirectory(prefix="ent-one-image-publisher-", dir="/tmp") as tmp:
        work = Path(tmp)
        signer = A["Node"](work / "signer", BINS["candidate"] / "entangle")
        package = work / "package"
        signer.command("plugins", "build", ROOT / "plugins/image-resize", "--wasm", WASM, "--out", package)
        plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
        package_sha256 = {p.name: sha(p) for p in package.iterdir() if p.is_file()}
        assert package_sha256["plugin.wasm"] == sha(WASM)
        for i, order in enumerate(ORDERS, 1):
            for side in order:
                record = image_arm(side, i, work, package, plugin, signer.key, cases)
                image_results.append(record)
                print("image", i, side, [f"{r['p95_ms']:.2f}" for r in record["trials"]["one_remote"]], flush=True)
    comparisons = {}
    for route in ("one_remote", "local"):
        rows = []
        for arm in image_results:
            trial = arm["trials"][route]
            rows.append(dict(pair=arm["pair"], side=arm["side"],
                             p50_ms=statistics.median(r["p50_ms"] for r in trial),
                             p95_ms=statistics.median(r["p95_ms"] for r in trial),
                             rate=statistics.median(r["images_s"] for r in trial)))
        comparisons["image_" + route] = summarize(rows)
    dump(DIR / "image-results.json", {
        "source_before": before, "source_after": stamp(), "pair_orders": ORDERS,
        "fixture_input_bytes": [len(raw) for raw, _ in cases], "input_sha256": inputs,
        "wasm_sha256": sha(WASM), "signed_package_sha256": package_sha256, "driver_sha256": sha(Path(__file__)),
        "original_benchmark_sha256": sha(ROOT / "scripts/benchmark_image_batch.py"),
        "comparisons": comparisons, "started_utc": started, "finished_utc": now(),
    })
    os.sched_setaffinity(0, set(HOST_CPUS))
    tiny_results = []
    for i, order in enumerate(ORDERS, 1):
        for side in order:
            record = tiny_arm(side, i)
            tiny_results.append(record)
            print("greeting", i, side, record["remote_one"], flush=True)
    comparison = summarize([dict(pair=r["pair"], side=r["side"], **r["remote_one"]) for r in tiny_results])
    dump(DIR / "greeting-results.json", {
        "source_before": before, "source_after": stamp(), "test_driver_sha256": sha(TINY),
        "pair_orders": ORDERS, "all_results": tiny_results, "remote_one_comparison": comparison,
    })


if __name__ == "__main__":
    main()
