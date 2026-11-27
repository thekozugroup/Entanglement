"""Compare signed catalog image-resize on one local, one remote, and three remote workers."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import tempfile
import time
import tomllib

from PIL import Image, ImageChops, ImageOps, ImageStat, __version__ as pillow_version

ROOT = Path(__file__).resolve().parents[1]
IMAGES = 24
CLIENTS = 4
SIZE = (192, 224)
ROUTES = ("local", "one_remote", "three_remote")


def corpus(path):
    """Create distinct JPEG assets once, then retain identical bytes for every route."""
    with Image.open(path) as original:
        source = original.convert("RGB")
    if source.width < 64 or source.height < 64:
        raise ValueError("source image must be at least 64 pixels on each axis")
    cases = []
    for index in range(IMAGES):
        left, top = 2 * (index % 6), 3 * (index // 6)
        crop = source.crop((left, top, source.width - 12 + left, source.height - 12 + top))
        if index % 2:
            crop = ImageOps.mirror(crop)
        stream = io.BytesIO()
        crop.resize((768, 896), Image.Resampling.LANCZOS).save(stream, "JPEG", quality=88)
        jpeg = stream.getvalue()
        with Image.open(io.BytesIO(jpeg)) as decoded:
            reference = decoded.convert("RGB").resize(SIZE, Image.Resampling.LANCZOS)
        header = b'{"width":192,"height":224,"format":"png","filter":"lanczos3"}\n'
        cases.append((header + jpeg, reference))
    if len({hashlib.sha256(data).digest() for data, _ in cases}) != IMAGES:
        raise ValueError("the source produced duplicate image inputs")
    return cases


def verify_png(data, reference):
    with Image.open(io.BytesIO(data)) as result:
        if result.format != "PNG" or result.size != reference.size:
            raise ValueError(f"unexpected image {result.format} {result.size}")
        difference = ImageChops.difference(result.convert("RGB"), reference)
        error = max(ImageStat.Stat(difference).mean)
    if error > 3.0:
        raise ValueError(f"maximum channel mean absolute error {error:.3f} exceeds 3.0")
    return hashlib.sha256(data).hexdigest(), error


def frame(method, params):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    return json.dumps(request, separators=(",", ":")).encode() + b"\n"


def exchange(path, request):
    started = time.perf_counter()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(35)
        client.connect(str(path))
        client.sendall(request)
        with client.makefile("rb") as reader:
            response = reader.readline(16 * 1024 * 1024)
    if not response.endswith(b"\n"):
        raise RuntimeError("RPC response exceeded the benchmark limit or was incomplete")
    return time.perf_counter() - started, response


def decoded(raw):
    body = json.loads(raw)
    if body.get("jsonrpc") != "2.0" or body.get("id") != 1 or "result" not in body:
        raise RuntimeError(str(body.get("error", "invalid RPC envelope")))
    return body["result"]


class Node:
    def __init__(self, home, cli):
        home.mkdir()
        self.home = home
        self.cli = cli
        self.env = {**os.environ, "HOME": str(home), "RUST_LOG": "warn",
                    "TOKIO_WORKER_THREADS": "4", "RAYON_NUM_THREADS": "4"}
        self.env.pop("ENTANGLE_ALLOW_LOCAL", None)
        output = self.command("init", "--non-interactive")
        self.peer = re.search(rb"Fingerprint:\s*([0-9a-f-]+)", output)[1].decode().replace("-", "")
        cert = subprocess.check_output(["openssl", "pkey", "-in", home / ".entangle/identity.key",
                                        "-pubout", "-outform", "DER"])
        if len(cert) != 44 or cert[:12] != bytes.fromhex("302a300506032b6570032100"):
            raise ValueError("unexpected Ed25519 public key")
        self.key = cert[12:].hex()
        self.sock = home / ".entangle/sock"

    def command(self, *arguments):
        return subprocess.check_output([self.cli, *arguments], env=self.env, timeout=60)

    def trust(self, peer):
        self.command("mesh", "trust", peer.peer, "--public-key-hex", peer.key,
                     "--display-name", peer.home.name)

    def start(self, stack, binary, port, routes, cpu=None):
        config = (f'[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\n'
                  f'bind="127.0.0.1:{port}"\nrelay=false\npeers={json.dumps(routes)}\n')
        (self.home / ".entangle/config.toml").write_text(config)
        log = stack.enter_context((self.home / "daemon.log").open("wb"))
        command = [binary, "run"] if cpu is None else ["taskset", "-c", str(cpu), binary, "run"]
        process = subprocess.Popen(command, env=self.env, stdout=log, stderr=log)
        self.pid = process.pid

        def stop():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        stack.callback(stop)
        deadline = time.monotonic() + 30
        while not self.sock.is_socket():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError((self.home / "daemon.log").read_text())
            time.sleep(0.05)

    def rpc(self, method, params):
        return decoded(exchange(self.sock, frame(method, params))[1])


def dispatch_frame(plugin, payload, peers):
    return frame("compute/dispatch", {
        "plugin_id": plugin, "input": list(payload), "timeout_ms": 30_000,
        "cpu_cores": 0.01, "memory_bytes": 0, "gpu_required": False, "gpu_vram_min_bytes": 0,
        "integrity": {"kind": "trusted-executor", "allowlist": peers},
    })


def cpu_times(nodes):
    """Process CPU seconds from Linux procfs, summed across all runtime threads."""
    if not Path("/proc/self/stat").exists():
        return {}
    hz = os.sysconf("SC_CLK_TCK")
    times = {}
    for role, pid in nodes.items():
        # Everything after the process name (which may contain a space) starts at field 3.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        times[role] = (int(fields[11]) + int(fields[12])) / hz
    return times


def measure(route, client, requests, peers, cases, golden, nodes=None):
    nodes = nodes or {}
    with ThreadPoolExecutor(max_workers=CLIENTS) as pool:
        cpu_before = cpu_times(nodes)
        start = time.perf_counter()
        responses = list(pool.map(lambda message: exchange(client.sock, message), requests))
        wall = time.perf_counter() - start
        cpu_after = cpu_times(nodes)
    workers = Counter()
    errors = []
    output_bytes = 0
    for index, (_, raw) in enumerate(responses):
        result = decoded(raw)
        workers[result["chosen_peer"]] += 1
        output = bytes(result["output"])
        digest, error = verify_png(output, cases[index][1])
        output_bytes += len(output)
        errors.append(error)
        if digest != golden.setdefault(index, digest):
            raise ValueError(f"{route} returned different PNG bytes for input {index}")
    if set(workers) != set(peers):
        raise ValueError(f"{route} used unexpected worker set: {workers}")
    latencies = sorted(elapsed for elapsed, _ in responses)
    mean_cores = {role: (end - cpu_before[role]) / wall for role, end in cpu_after.items()}
    return {"route": route, "wall_s": wall, "mean_cpu_cores": mean_cores, "images_s": len(responses) / wall,
            "latency_ms_by_input": [1000 * elapsed for elapsed, _ in responses],
            "p50_ms": 1000 * latencies[math.ceil(0.50 * len(latencies)) - 1],
            "p95_ms": 1000 * latencies[math.ceil(0.95 * len(latencies)) - 1],
            "workers": dict(workers), "png_bytes": output_bytes, "max_channel_mae": max(errors)}


def run(args):
    routes = ROUTES if args.route is None else (args.route,)
    cases = corpus(args.image)
    cli = (args.bin_dir / "entangle").resolve(strict=True)
    daemon = (args.bin_dir / "entangled").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="ent-image-", dir="/tmp") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        worker_cpus = [None] * 3
        driver_cpus = None
        if args.worker_cpu_affinity:
            allowed = sorted(os.sched_getaffinity(0))
            if len(allowed) < 4:
                raise RuntimeError("one CPU per worker and at least one coordinator CPU are required")
            worker_cpus, driver_cpus = allowed[:3], allowed[3:]
            os.sched_setaffinity(0, driver_cpus)
            stack.callback(os.sched_setaffinity, 0, allowed)
        coordinator = Node(directory / "coordinator", cli)
        workers = [Node(directory / f"worker-{i}", cli) for i in range(3)]
        first = workers[0]
        first.command("plugins", "install", "image-resize", "--catalog", ROOT / "plugins",
                      "--wasm", args.wasm.resolve(strict=True), "--no-load")
        package = first.home / ".entangle/plugins/image-resize"
        plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
        worker_addresses = []
        for index, worker in enumerate(workers):
            coordinator.trust(worker)
            worker.trust(coordinator)
            if worker != first:
                worker.command("keyring", "add", first.key, "--name", "benchmark publisher")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            worker.start(stack, daemon, port, [], cpu=worker_cpus[index])
            worker.command("plugins", "load", package)
            worker_addresses.append(f"{worker.key}@127.0.0.1:{port}")
        coordinator.start(stack, daemon, 0, worker_addresses)
        if coordinator.rpc("plugins/list", {})["plugins"]:
            raise RuntimeError("coordinator unexpectedly has a local plugin")
        peer_ids = [worker.peer for worker in workers]
        # Verify each advertised executor can run the signed package before timing.
        for peer in peer_ids:
            message = dispatch_frame(plugin, cases[0][0], [peer])
            deadline = time.monotonic() + 45
            while True:
                try:
                    result = decoded(exchange(coordinator.sock, message)[1])
                    break
                except RuntimeError as exc:
                    if "no live workers" not in str(exc) or time.monotonic() > deadline:
                        raise
                    time.sleep(0.1)
            if result["chosen_peer"] != peer:
                raise RuntimeError("warmup selected an unexpected executor")
            verify_png(bytes(result["output"]), cases[0][1])
        configs = {
            route: (first if route == "local" else coordinator,
                    peer_ids if route == "three_remote" else peer_ids[:1])
            for route in routes
        }
        requests = {route: [dispatch_frame(plugin, payload, peers) for payload, _ in cases]
                    for route, (_, peers) in configs.items()}
        trials, golden = [], {}
        nodes = {"driver": os.getpid(), "coordinator": coordinator.pid,
                 **{node.home.name: node.pid for node in workers}}
        observed_cpus = ({name: sorted(os.sched_getaffinity(pid)) for name, pid in nodes.items()}
                         if hasattr(os, "sched_getaffinity") else {})
        thread_counts = {}
        if Path("/proc/self/task").exists():
            for name, pid in nodes.items():
                masks = []
                for thread in Path(f"/proc/{pid}/task").iterdir():
                    try:
                        masks.append(sorted(os.sched_getaffinity(int(thread.name))))
                    except ProcessLookupError:
                        continue
                thread_counts[name] = len(masks)
                if args.worker_cpu_affinity and any(mask != observed_cpus[name] for mask in masks):
                    raise RuntimeError(f"{name} has a thread outside the requested CPU set")
        if args.worker_cpu_affinity:
            for index, cpu in enumerate(worker_cpus):
                if observed_cpus[f"worker-{index}"] != [cpu]:
                    raise RuntimeError("worker affinity did not match the requested CPU")
            if observed_cpus["coordinator"] != driver_cpus or observed_cpus["driver"] != driver_cpus:
                raise RuntimeError("coordinator and driver CPU affinity mismatch")
        for trial in range(3):
            for route in routes[trial:] + routes[:trial]:
                client, peers = configs[route]
                result = measure(route, client, requests[route], peers, cases, golden, nodes)
                trials.append(result)
                print(json.dumps(result, sort_keys=True), flush=True)

    rates = {route: statistics.median(row["images_s"] for row in trials if row["route"] == route)
             for route in routes}
    speedup = rates["three_remote"] / rates["one_remote"] if len(routes) == 3 else None
    with daemon.open("rb") as binary:
        daemon_hash = hashlib.file_digest(binary, "sha256").hexdigest()
    target = 1.50 if args.worker_cpu_affinity else 1.10
    return {"images": IMAGES, "worker_cpu_affinity": args.worker_cpu_affinity,
            "cpu_affinity": observed_cpus, "process_threads_at_warmup": thread_counts,
            "three_over_one_target": target, "concurrency": CLIENTS, "trials": trials,
            "input_bytes_per_batch": sum(len(data) for data, _ in cases),
            "input_sha256": hashlib.sha256(b"".join(data for data, _ in cases)).hexdigest(),
            "source_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
            "png_digest_list_sha256": hashlib.sha256(b"".join(bytes.fromhex(golden[i]) for i in range(IMAGES))).hexdigest(),
            "daemon_sha256": daemon_hash,
            "wasm_sha256": hashlib.sha256(args.wasm.read_bytes()).hexdigest(),
            "pillow_version": pillow_version,
            "median_images_s": rates, "three_over_one_remote": speedup,
            "throughput_target_met": speedup >= target if speedup is not None else None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--worker-cpu-affinity", action="store_true",
                        help="Linux: assign each worker its own CPU and restrict driver/coordinator to the rest")
    parser.add_argument("--route", choices=ROUTES, help="measure just one route and omit the scaling check")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    result = run(args)
    args.results.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if result["three_over_one_remote"] is not None:
        print("three_remote / one_remote:", result["three_over_one_remote"], flush=True)
    raise SystemExit(2 if result["throughput_target_met"] is False else 0)
