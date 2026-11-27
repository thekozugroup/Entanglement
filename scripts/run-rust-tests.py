#!/usr/bin/env python3
"""Shard a signed WASI libtest suite over paired Entanglement workers."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import socket
import sys
import time


class DispatchError(Exception):
    """A transport, worker, or libtest protocol failure."""


MAX_RPC_LINE = 4 * 1024 * 1024
STATUSES = ("passed", "flaky", "failed", "ignored", "error")
RESULT = re.compile(
    r"^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out(?:; finished in [0-9]+(?:\.[0-9]+)?s)?$",
    re.MULTILINE,
)
PANIC = re.compile(r"^thread '[^'\r\n]*'(?: \(\d+\))? panicked at(?: |$)", re.MULTILINE)
RUN_HEADER = re.compile(r"running [0-9]+ tests?")


def rpc(socket_path, method, params, timeout):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(timeout)
            stream.connect(str(socket_path))
            request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            stream.sendall(json.dumps(request).encode() + b"\n")
            with stream.makefile("rb") as reader:
                line = reader.readline(MAX_RPC_LINE + 1)
        if not line.endswith(b"\n") or len(line) > MAX_RPC_LINE:
            raise DispatchError("daemon returned an incomplete or oversized RPC response")
        reply = json.loads(line)
        if reply["id"] != 1 or reply["jsonrpc"] != "2.0":
            raise DispatchError("unexpected RPC response envelope")
        if "error" in reply:
            raise DispatchError(reply["error"]["message"])
        return reply["result"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise DispatchError(f"{method}: {error}") from error


def dispatcher(socket_path, plugin, timeout_ms):
    def dispatch(peer, operation):
        request = {
            "plugin_id": plugin,
            "input": list(json.dumps(operation).encode()),
            "timeout_ms": timeout_ms,
            "cpu_cores": 0.0,
            "memory_bytes": 0,
            "gpu_required": False,
            "gpu_vram_min_bytes": 0,
            "integrity": {"kind": "trusted-executor", "allowlist": [peer]},
        }
        reply = rpc(socket_path, "compute/dispatch", request, timeout_ms / 1000 + 15)
        try:
            if reply["chosen_peer"] != peer:
                raise DispatchError("scheduler returned a different executor")
            result = json.loads(bytes(reply["output"]))
            if (not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)
                    or (result["exit_code"] is not None and type(result["exit_code"]) is not int)):
                raise DispatchError("invalid WASI libtest response")
            return {"peer": reply["chosen_peer"], "exit_code": result["exit_code"],
                    "stdout": result["stdout"], "stderr": result["stderr"]}
        except (KeyError, TypeError, ValueError) as error:
            raise DispatchError(f"invalid WASI libtest response: {error}") from error

    return dispatch


def test_list(result):
    if result["exit_code"] != 0:
        raise DispatchError(f"libtest listing failed on {result['peer']}: {result['stderr']}")
    names = set()
    for line in result["stdout"].splitlines():
        if line.endswith(": test"):
            name = line.removesuffix(": test")
            if name in names:
                raise DispatchError(f"duplicate test in harness listing: {name}")
            names.add(name)
        elif line and not line.endswith(": benchmark"):
            raise DispatchError(f"unexpected libtest listing output: {line}")
    return names


def suite_listing(dispatch, peer):
    names = test_list(dispatch(peer, {"operation": "list"}))
    ignored = test_list(dispatch(peer, {"operation": "list", "ignored": True}))
    if not ignored <= names:
        raise DispatchError(f"inconsistent ignored-test listing on {peer}")
    return names, ignored


def classify(result):
    lines = result["stdout"].splitlines()
    summaries = [line for line in lines if line.startswith("test result:")]
    header = next((line for line in lines if line.strip()), "")
    exit_code = result["exit_code"]
    if exit_code is None:
        if summaries:
            raise DispatchError("WASI libtest trapped after reporting a test summary")
        if RUN_HEADER.fullmatch(header) and header != "running 1 test":
            raise DispatchError("exact libtest selector did not report one selected test")
        if PANIC.search(result["stderr"]):
            return "failed"
        raise DispatchError("WASI libtest trapped without a Rust panic report")
    if len(summaries) != 1 or not (summary := RESULT.fullmatch(summaries[0])):
        raise DispatchError("expected one valid Rust libtest summary")
    if header != "running 1 test":
        raise DispatchError("exact libtest selector did not report one selected test")
    status, passed, failed, ignored, measured, _ = summary.groups()
    counts = (passed, failed, ignored, measured)
    if status == "ok" and exit_code == 0:
        if counts == ("1", "0", "0", "0"):
            return "passed"
        if counts == ("0", "0", "1", "0"):
            return "ignored"
    if status == "FAILED" and exit_code != 0 and counts == ("0", "1", "0", "0"):
        return "failed"
    raise DispatchError("exact libtest selector did not report one completed test")


def run_test(dispatch, peers, index, name, ignored, retries):
    attempts = []
    for attempt in range(1, retries + 2):
        peer = peers[(index + attempt - 1) % len(peers)]
        record = {"attempt": attempt, "peer": peer}
        try:
            result = dispatch(peer, {"operation": "test", "name": name, "ignored": ignored,
                                     "attempt": attempt})
            record.update(result)
            record["status"] = classify(result)
        except DispatchError as error:
            record.update(status="error", error=str(error))
        attempts.append(record)
        if record["status"] == "passed":
            flaky = any(item["status"] == "failed" for item in attempts[:-1])
            return {"name": name, "status": "flaky" if flaky else "passed", "attempts": attempts}
        if record["status"] == "ignored" and attempt == 1:
            return {"name": name, "status": "ignored", "attempts": attempts}
        # An ignored retry leaves the earlier failure or error unresolved.
    status = "failed" if any(item["status"] == "failed" for item in attempts) else "error"
    return {"name": name, "status": status, "attempts": attempts}


def run_suite(args, plugin):
    filters = (args.filter,) if isinstance(args.filter, str) else args.filter

    def matches(name, selector):
        return name == selector if args.exact else selector in name

    peers = args.peer
    dispatch = dispatcher(args.socket, plugin, args.timeout_ms)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(peers)) as executor:
        listings = list(executor.map(lambda peer: suite_listing(dispatch, peer), peers))
        names, ignored = listings[0]
        if any(listing != listings[0] for listing in listings[1:]):
            raise DispatchError("workers disagree about the signed suite's test names or ignores")
        selected = [name for name in sorted(names)
                    if (not filters or any(matches(name, selector) for selector in filters))
                    and not any(matches(name, skip) for skip in args.skip)
                    and (not args.ignored or name in ignored)]
        results = {}
        work = {}
        for name in selected:
            if name in ignored and not (args.ignored or args.include_ignored):
                results[name] = {"name": name, "status": "ignored", "attempts": []}
            else:
                work[name] = executor.submit(
                    run_test, dispatch, peers, len(work), name, name in ignored, args.retries
                )
        results.update((name, future.result()) for name, future in work.items())

    counts = dict.fromkeys(STATUSES, 0)
    for result in results.values():
        counts[result["status"]] += 1
    return {"suite": plugin, "listing_peers": peers, "filtered": len(names) - len(selected),
            "counts": counts, "elapsed_ms": round((time.monotonic() - started) * 1000),
            "results": [results[name] for name in selected]}


def run_suites(args):
    local_peer = rpc(args.socket, "mesh/status", None, 10)["local_peer_id"]
    if len(set(args.peer)) != len(args.peer) or local_peer in args.peer:
        raise DispatchError("supply distinct remote peer identities")
    started = time.monotonic()
    suites = [run_suite(args, plugin) for plugin in args.plugins]
    return {"suites": suites,
            "counts": {status: sum(suite["counts"][status] for suite in suites) for status in STATUSES},
            "filtered": sum(suite["filtered"] for suite in suites),
            "elapsed_ms": round((time.monotonic() - started) * 1000)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugins", nargs="+", metavar="PLUGIN", help="operator-loaded, signed libtest plugin IDs")
    parser.add_argument("--socket", type=Path, default=Path.home() / ".entangle" / "sock")
    parser.add_argument("--peer", action="append", required=True, help="trusted remote peer ID")
    parser.add_argument("--filter", action="append", default=[], help="include a matching name (repeatable, any match)")
    parser.add_argument("--exact", action="store_true", help="match complete names in filters and skips")
    parser.add_argument("--skip", action="append", default=[], help="exclude a matching name (repeatable)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--ignored", action="store_true", help="select ignored tests only")
    modes.add_argument("--include-ignored", action="store_true")
    parser.add_argument("--retries", type=int, choices=range(11), default=0)
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    args = parser.parse_args()
    if any(not re.fullmatch(r"[0-9a-f]{32}", peer) for peer in args.peer):
        parser.error("peer IDs must be 32 lowercase hexadecimal characters")
    if len(set(args.plugins)) != len(args.plugins):
        parser.error("supply distinct plugin IDs")
    if not 0 < args.timeout_ms <= 300_000:
        parser.error("timeout must be between 1 and 300000 milliseconds")
    try:
        report = run_suites(args)
    except DispatchError as error:
        print(f"Rust test dispatch failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return int(bool(report["counts"]["failed"] or report["counts"]["error"]))


if __name__ == "__main__":
    sys.exit(main())
