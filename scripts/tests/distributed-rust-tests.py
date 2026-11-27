#!/usr/bin/env python3
"""Exercise the operator Rust runner against two authenticated Iroh workers."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import tomllib


RUNNER = Path(__file__).resolve().parents[1] / "run-rust-tests.py"
IGNORED_FIXTURE = "intentionally_fails_on_every_attempt"
RETRY_TEST = "intentionally_fails_on_first_attempt"


class Node:
    def __init__(self, directory, binaries):
        directory.mkdir()
        self.binaries = binaries
        self.directory = directory
        self.env = {**os.environ, "HOME": str(directory), "RUST_LOG": "warn",
                    "TOKIO_WORKER_THREADS": "2"}
        self.state = directory / ".entangle"
        self.socket = self.state / "sock"
        output = self.cli("init", "--non-interactive")
        self.peer = re.search(rb"Fingerprint:\s*([0-9a-f-]+)", output)[1].decode().replace("-", "")
        public_key = subprocess.check_output(
            ["openssl", "pkey", "-in", self.state / "identity.key", "-pubout", "-outform", "DER"],
            timeout=10,
        )
        assert len(public_key) == 44 and public_key[:12].hex() == "302a300506032b6570032100"
        self.key = public_key[12:].hex()

    def cli(self, *arguments):
        return subprocess.check_output([self.binaries / "entangle", *arguments], env=self.env, timeout=60)

    def trust(self, node):
        self.cli("mesh", "trust", node.peer, "--public-key-hex", node.key,
                 "--display-name", node.directory.name)

    def start(self, stack, port, routes):
        (self.state / "config.toml").write_text(
            f'[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\n'
            f'bind="127.0.0.1:{port}"\nrelay=false\npeers={json.dumps(routes)}\n'
        )
        log_path = self.directory / "daemon.log"
        log = stack.enter_context(log_path.open("wb"))
        process = subprocess.Popen([self.binaries / "entangled", "run"],
                                   env=self.env, stdout=log, stderr=log)

        def stop():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        stack.callback(stop)
        deadline = time.monotonic() + 30
        while not self.socket.is_socket():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(log_path.read_text())
            time.sleep(0.05)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def signed_suite(coordinator, directory, name, wasm):
    source = directory / name
    source.mkdir()
    (source / "entangle.toml").write_text(
        f'[plugin]\nid = "PUBLISHER_PLACEHOLDER/{name}@0.1.0"\nversion = "0.1.0"\n'
        'tier = 1\nruntime = "wasm"\ndescription = "Entanglement libtest integration suite"\n'
        '[build]\nwit_world = "wasi:cli/command@0.2.0"\ntarget = "wasm32-wasip2"\n'
    )
    package = directory / f"{name}-package"
    coordinator.cli("plugins", "build", source, "--wasm", wasm, "--out", package)
    plugin = tomllib.loads((package / "entangle.toml").read_text())["plugin"]["id"]
    return plugin, package


def run(binaries, types_wasm, manifest_wasm, retry_wasm):
    with tempfile.TemporaryDirectory(prefix="ent-rust-test-", dir="/tmp") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        coordinator = Node(directory / "coordinator", binaries)
        workers = [Node(directory / f"worker-{index}", binaries) for index in range(2)]
        packages = [signed_suite(coordinator, directory, name, wasm) for name, wasm in (
            ("types-atc", types_wasm), ("manifest-atc", manifest_wasm), ("retry-fixture", retry_wasm),
        )]
        types, manifest, retry = [plugin for plugin, _ in packages]
        routes = []
        for worker in workers:
            port = free_port()
            coordinator.trust(worker)
            worker.trust(coordinator)
            worker.cli("keyring", "add", coordinator.key, "--name", "test-suite publisher")
            worker.start(stack, port, [])
            for _, package in packages:
                worker.cli("plugins", "load", package)
            routes.append(f"{worker.key}@127.0.0.1:{port}")
        coordinator.start(stack, 0, routes)
        peers = [worker.peer for worker in workers]
        command = [sys.executable, RUNNER, "--socket", coordinator.socket,
                   "--peer", peers[0], "--peer", peers[1]]

        def suite(*arguments, code=0):
            result = subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=90)
            assert result.returncode == code, (result.stderr, result.stdout)
            return json.loads(result.stdout)

        full = suite(types, manifest)
        assert full["counts"]["passed"] >= 4, full
        assert full["counts"]["flaky"] == full["counts"]["failed"] == full["counts"]["error"] == 0, full
        for report in full["suites"]:
            assert {attempt["peer"] for test in report["results"] for attempt in test["attempts"]} == set(peers)
        assert full["filtered"] == 0
        filtered = suite(types, "--filter", "atc_int", "--skip", "streaming")
        discovered = full["suites"][0]["results"]
        selected = [row["name"] for row in discovered if "atc_int" in row["name"] and "streaming" not in row["name"]]
        assert 0 < len(selected) < len(discovered)
        assert filtered["filtered"] == len(discovered) - len(selected), filtered
        assert [row["name"] for row in filtered["suites"][0]["results"]] == selected, filtered
        with_ignore = suite(retry, "--retries", "1")
        ignored, = (test for test in with_ignore["suites"][0]["results"] if test["status"] == "ignored")
        assert ignored["name"] == IGNORED_FIXTURE and ignored["attempts"] == [], with_ignore
        failure = suite(retry, "--ignored", "--filter", IGNORED_FIXTURE, "--exact", "--retries", "1", code=1)
        result, = failure["suites"][0]["results"]
        assert result["name"] == IGNORED_FIXTURE and failure["counts"]["failed"] == 1, failure
        assert [attempt["peer"] for attempt in result["attempts"]] == peers, failure
        result, = (test for test in with_ignore["suites"][0]["results"] if test["status"] == "flaky")
        assert result["name"] == RETRY_TEST and with_ignore["counts"]["flaky"] == 1, with_ignore
        assert [(x["attempt"], x["peer"], x["status"]) for x in result["attempts"]] == [
            (1, peers[0], "failed"), (2, peers[1], "passed"),
        ], with_ignore
        assert "intentional first-attempt failure" in result["attempts"][0]["stderr"], with_ignore
        print(json.dumps({"full": full, "filtered": filtered, "failure": failure,
                          "retry_fixture": with_ignore}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path("target/debug"))
    parser.add_argument("--types-wasm", type=Path, required=True)
    parser.add_argument("--manifest-wasm", type=Path, required=True)
    parser.add_argument("--retry-wasm", type=Path, required=True)
    args = parser.parse_args()
    run(*(path.resolve(strict=True) for path in (
        args.bin_dir, args.types_wasm, args.manifest_wasm, args.retry_wasm,
    )))
