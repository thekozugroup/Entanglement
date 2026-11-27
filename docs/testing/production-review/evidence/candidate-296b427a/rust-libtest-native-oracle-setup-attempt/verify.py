#!/usr/bin/env python3
"""Replay the native selection oracle and signed WASI libtest controls."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time


SELECTIONS = [
    ("all", [], [], False, ""),
    ("single-substring", ["alpha"], ["second"], False, ""),
    ("multiple-includes-skips", ["first", "muted", "first"], ["alphabet", "beta::muted"], False, ""),
    ("single-exact-prefix-skip", ["alpha::first"], ["alpha::"], True, ""),
    ("multiple-exact-with-exclusions", ["alpha::first", "alpha", "beta::second"],
     ["alpha::", "beta::second"], True, ""),
    ("exact-skips-with-no-includes", [], ["alpha::", "beta::first"], True, ""),
    ("only-ignored", ["alpha", "beta"], ["alpha::"], False, "--ignored"),
    ("include-ignored", ["alpha::muted", "beta::muted"], ["beta::"], True, "--include-ignored"),
    ("empty-selection", ["absent", "no such test"], [], False, ""),
]

DIAGNOSTICS = [
    ("quiet", "tests::quiet", "passed", ["passed"], []),
    ("logged_application_success", "tests::prints_application_result_diagnostic", "passed", ["passed"], []),
    ("logged_valid_summary_success", "tests::prints_captured_summary_from_fixture", "passed", ["passed"], []),
    ("logged_assertion_failure", "tests::reports_error_after_diagnostic", "failed", ["failed"], []),
    ("ordinary_result_error", "tests::returns_result_error", "failed", ["failed"], []),
    ("failure_then_pass", "tests::checks_timeout_with_diagnostic_on_first_attempt",
     "flaky", ["failed", "passed"], ["--retries", "1"]),
    ("inline_success", "tail_controls::prints_without_newline_before_success", "passed", ["passed"], []),
    ("early_exit_after_logged_count", "tail_controls::exits_before_libtest_finishes", "error", ["error"], []),
    ("expected_panic_ignored", "tail_controls::expected_panic_with_reason", "ignored",
     ["ignored"], ["--include-ignored"]),
    ("empty_legitimate_filter", "test-name-not-present", None, [], []),
]


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(command, cwd, timeout=60, env=None):
    command = list(map(str, command))
    start = time.monotonic()
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return {"command": command, "exit_code": result.returncode, "stdout": result.stdout,
            "stderr": result.stderr, "elapsed_seconds": time.monotonic() - start}


def checked(command, cwd):
    result = capture(command, cwd)
    assert result["exit_code"] == 0, result
    return result["stdout"].strip()


def load(name, module):
    spec = importlib.util.spec_from_file_location(name, module)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def unpack(archive, destination, digests):
    destination.mkdir()
    prefix = archive.name.removesuffix(".tar.gz")
    actual = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            name = member.name
            for binary in ("entangle", "entangled"):
                if name != f"{prefix}/{binary}":
                    continue
                assert member.isfile() and binary not in actual, member
                destination_file = destination / binary
                with bundle.extractfile(member) as source, destination_file.open("xb") as stream:
                    shutil.copyfileobj(source, stream)
                destination_file.chmod(0o755)
                actual[binary] = sha(destination_file)
    assert actual == {binary: digests[binary] for binary in ("entangle", "entangled")}, actual
    return actual


def selector_flags(skips, exact, mode):
    return (["--exact"] if exact else []) + ([mode] if mode else []) + [
        flag for value in skips for flag in ("--skip", value)
    ]


def suite_record(rpc, pin, peers):
    data = json.loads(rpc["stdout"])
    suite, = data["suites"]
    assert suite["suite_identity"] == pin, suite
    assert suite["listing_peers"] == peers, suite
    records = suite["results"]
    attempts = [attempt for test in records for attempt in test["attempts"]]
    assert all(attempt["peer"] in peers for attempt in attempts), attempts
    assert all(attempt.get("suite_identity", pin) == pin for attempt in attempts), attempts
    for row in records:
        for number, attempt in enumerate(row["attempts"], start=1):
            assert attempt["attempt"] == number, attempts
            if "exit_code" in attempt:
                assert attempt["suite_identity"] == pin, attempts
    return data, {row["name"]: row["status"] for row in records}, attempts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--legacy-archive", type=Path, required=True)
    parser.add_argument("--legacy-verification", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--b3sum", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repo, archive, verification, rustc, b3sum, out = (
        path.resolve() for path in (args.repo, args.archive, args.verification,
                                    args.rustc, args.b3sum, args.out)
    )
    old_archive, old_verification = args.legacy_archive.resolve(), args.legacy_verification.resolve()
    fixtures = Path(__file__).resolve().parent
    sharder = repo / "scripts/run-rust-tests.py"
    topology = repo / "scripts/tests/distributed-rust-tests.py"
    construct = load("topology_fixture", topology)
    operator = load("operator_sharder", sharder)
    source_id_command = [sys.executable, "scripts/production_score.py", "--source-id"]
    source_before = checked(source_id_command, repo)
    commit = checked(["git", "rev-parse", "HEAD"], repo)
    manifest = json.loads(verification.read_text())
    assert source_before == manifest["source_id"] == manifest["source_after"], manifest
    assert commit == manifest["source_commit"], manifest
    assert archive.name == manifest["name"] and sha(archive) == manifest["sha256"], manifest
    if "blake3" in manifest:
        assert checked([b3sum, "--no-names", archive], repo) == manifest["blake3"], manifest
    legacy = json.loads(old_verification.read_text())
    assert legacy["source_id"] == legacy["source_after"] and legacy["source_commit"] != commit
    assert old_archive.name == legacy["name"] and sha(old_archive) == legacy["sha256"], legacy
    assert checked([b3sum, "--no-names", old_archive], repo) == legacy["blake3"], legacy
    out.mkdir(parents=True)
    report = {
        "source_commit": commit, "source_before": source_before, "started_utc": utc(),
        "command": [sys.executable, *sys.argv],
        "release_archive": archive.name, "release_archive_sha256": manifest["sha256"],
        "release_manifest_sha256": sha(verification),
        "driver_sha256": sha(Path(__file__)), "operator_sharder_sha256": sha(sharder),
        "topology_helper_sha256": sha(topology), "rustc_vv": checked([rustc, "-vV"], repo),
        "rustc_sha256": sha(rustc), "b3sum_version": checked([b3sum, "--version"], repo),
        "b3sum_sha256": sha(b3sum), "compile": {}, "packages": {}, "selection": [], "diagnostics": {},
        "legacy": {"source_commit": legacy["source_commit"], "source_id": legacy["source_id"],
                   "release_archive": old_archive.name, "release_archive_sha256": legacy["sha256"],
                   "release_manifest_sha256": sha(old_verification)},
        "scope": "One Linux host, one stateless coordinator, two distinct signed worker identities "
                 "over authenticated loopback QUIC. Only workers load the signed test components.",
    }

    try:
        with tempfile.TemporaryDirectory(prefix="ent-libtest-", dir="/tmp") as temp, ExitStack() as stack:
            place = Path(temp)
            bins = place / "bin"
            report["release_binaries_sha256"] = unpack(archive, bins, manifest["files_sha256"])
            old_bins = place / "old-bin"
            report["legacy"]["release_binaries_sha256"] = unpack(
                old_archive, old_bins, legacy["files_sha256"]
            )
            sources = {}
            for label in ("selectors", "diagnostics", "deadline"):
                src = fixtures / f"{label}.rs"
                compiled = {"source_sha256": sha(src)}
                report["compile"][label] = compiled
                for target in (["native", "wasm32-wasip2"] if label != "deadline" else ["wasm32-wasip2"]):
                    output = place / f"{label}.{target}"
                    target_arg = [] if target == "native" else ["--target", target]
                    run = capture([rustc, "--test", "--edition", "2021", *target_arg, src, "-o", output], repo)
                    compiled[target] = run
                    assert run["exit_code"] == 0, run
                    run["sha256"] = sha(output)
                    if target == "wasm32-wasip2":
                        with output.open("rb") as file:
                            assert file.read(8) == b"\0asm\x0d\0\x01\0"
                    sources[label, target] = output
            coordinator = construct.Node(place / "coord", bins)
            workers = [construct.Node(place / f"worker-{number}", bins) for number in range(2)]
            old_coordinator = construct.Node(place / "old-coord", old_bins)
            old_worker = construct.Node(place / "old-worker", old_bins)

            def audit_files():
                for node in (coordinator, *workers, old_coordinator, old_worker):
                    log = node.directory / "daemon.log"
                    if log.exists():
                        shutil.copyfile(log, out / f"{node.directory.name}.daemon.log")

            stack.callback(audit_files)
            plugin_ids, package_dirs, pins = {}, {}, {}
            for label in ("selectors", "diagnostics", "deadline"):
                plugin, package = construct.signed_suite(coordinator, place, f"oracle-{label}",
                                                         sources[label, "wasm32-wasip2"])
                plugin_ids[label], package_dirs[label] = plugin, package
                pins[label] = {
                    "artifact_blake3": checked([b3sum, "--no-names", package / "plugin.wasm"], repo),
                    "manifest_blake3": checked([b3sum, "--no-names", package / "entangle.toml"], repo),
                }
                report["packages"][label] = {
                    "id": plugin, "pin": pins[label], "sha256": {
                        file.name: sha(file) for file in sorted(package.iterdir()) if file.is_file()
                    },
                }
            routes = []
            for worker in workers:
                port = construct.free_port()
                coordinator.trust(worker)
                worker.trust(coordinator)
                worker.cli("keyring", "add", coordinator.key, "--name", "local signed libtest oracle")
                worker.start(stack, port, [])
                for package in package_dirs.values():
                    worker.cli("plugins", "load", package)
                routes.append(f"{worker.key}@127.0.0.1:{port}")
            old_port = construct.free_port()
            coordinator.trust(old_worker)
            old_worker.trust(coordinator)
            old_worker.cli("keyring", "add", coordinator.key, "--name", "local signed libtest oracle")
            old_worker.start(stack, old_port, [])
            old_worker.cli("plugins", "load", package_dirs["selectors"])
            routes.append(f"{old_worker.key}@127.0.0.1:{old_port}")
            coordinator.start(stack, 0, routes)
            peers = [worker.peer for worker in workers]
            report["coordinator_status"] = operator.rpc(coordinator.socket, "mesh/status", None, 10)
            assert report["coordinator_status"]["libtest_remote_codes"] == 1
            assert report["coordinator_status"]["local_peer_id"] == coordinator.peer
            report["coordinator_loaded_plugins"] = json.loads(coordinator.cli("plugins", "list", "--json"))
            assert not report["coordinator_loaded_plugins"]["plugins"]
            report["worker_peers"] = peers

            def shard(plugins, *flags, node=coordinator, selected_peers=peers):
                return capture([sys.executable, "-B", sharder, *plugins, "--socket", node.socket,
                                *[flag for peer in selected_peers for flag in ("--peer", peer)], *flags], repo,
                               timeout=65, env=node.env)

            full_native = None
            for label, filters, skips, exact, mode in SELECTIONS:
                flags = selector_flags(skips, exact, mode)
                native = capture([sources["selectors", "native"], "--format", "pretty",
                                  "--test-threads", "1", *flags, "--", *filters], repo)
                sharded = shard([plugin_ids["selectors"]], *flags,
                                *[flag for value in filters for flag in ("--filter", value)])
                case = {"case": label, "native": native, "sharded": sharded}
                report["selection"].append(case)
                assert native["exit_code"] == sharded["exit_code"] == 0, case
                selected = {name: "passed" if status == "ok" else status for name, status in
                            re.findall(r"(?m)^test (.+) \.\.\. (ok|ignored)$", native["stdout"])}
                data, distributed, attempts = suite_record(sharded, pins["selectors"], peers)
                assert selected == distributed, case
                if label == "all":
                    full_native = selected
                    assert len(full_native) == 8 and {attempt["peer"] for attempt in attempts} == set(peers)
                assert data["filtered"] == len(full_native) - len(selected), case
                case["native_selection"], case["sharded_selection"] = selected, distributed
                case["attempt_workers"] = sorted({attempt["peer"] for attempt in attempts})

            output = report["diagnostics"]
            for label, test, expected, statuses, flags in DIAGNOSTICS:
                native_flags = ["--include-ignored"] if "--include-ignored" in flags else []
                native_env = {name: value for name, value in os.environ.items()
                              if name != "ENTANGLE_LIBTEST_ATTEMPT"}
                native = capture([sources["diagnostics", "native"], "--format", "pretty",
                                  "--test-threads", "1", "--nocapture", "--exact", *native_flags,
                                  "--", test], repo, env=native_env)
                result = shard([plugin_ids["diagnostics"]], "--exact", "--filter", test, *flags)
                output[label] = {"native": native, "sharded": result}
                assert result["exit_code"] == int(expected in {"error", "failed"}), result
                data, observed, attempts = suite_record(result, pins["diagnostics"], peers)
                assert observed == ({test: expected} if expected else {}), data
                assert [attempt["status"] for attempt in attempts] == statuses, attempts
                output[label]["status"] = expected
                output[label]["attempt_statuses"] = statuses
                if label == "expected_panic_ignored":
                    assert native["exit_code"] == 0 and f"test {test} - should panic ... ok" in native["stdout"], native
                if expected == "flaky":
                    assert [attempt["peer"] for attempt in attempts] == peers, attempts
                    assert "first worker attempt reports a real assertion failure" in attempts[0]["stderr"]

            missing = plugin_ids["diagnostics"].split("/")[0] + "/not-loaded@0.1.0"
            failure = shard([plugin_ids["diagnostics"], missing], "--exact", "--filter", "tests::quiet")
            output["second_suite_discovery_failure"] = failure
            assert failure["exit_code"] == 1 and failure["stdout"] == "", failure
            assert "no live workers" in failure["stderr"], failure

            timed = shard([plugin_ids["deadline"]], "--exact", "--filter", "runs_past_worker_deadline",
                          "--timeout-ms", "750", "--retries", "1")
            output["actual_worker_deadline"] = timed
            assert timed["exit_code"] == 1, timed
            _, observed, attempts = suite_record(timed, pins["deadline"], peers)
            assert observed == {"runs_past_worker_deadline": "error"}, timed
            assert [(row["peer"], row["status"]) for row in attempts] == [
                (peers[0], "error"), (peers[1], "error")
            ], timed
            assert all("timeout" in row["error"].lower() or "timed out" in row["error"].lower()
                       for row in attempts), timed
            live = shard([plugin_ids["diagnostics"]], "--exact", "--filter", "tests::quiet")
            output["worker_health_after_deadline"] = live
            assert live["exit_code"] == 0, live
            _, observed, _ = suite_record(live, pins["diagnostics"], peers)
            assert observed == {"tests::quiet": "passed"}, live

            incorrect_pin = {**pins["diagnostics"], "manifest_blake3": "0" * 64}
            assert incorrect_pin != pins["diagnostics"]
            command = {"operation": "test", "name": "tests::quiet", "expected_suite_identity": incorrect_pin}
            try:
                operator.dispatcher(coordinator.socket, plugin_ids["diagnostics"], 30_000)(peers[0], command)
            except operator.SuiteIdentityError as error:
                output["pinned_mismatch_wire"] = {
                    "plugin": plugin_ids["diagnostics"], "peer": peers[0], "params": command,
                    "error_kind": error.error_kind, "remote_code": error.remote_code, "error": str(error),
                }
                assert error.remote_code == "suite-identity-mismatch", str(error)
            else:
                raise AssertionError("remote host accepted a wrong suite pin")

            old_coordinator.start(stack, 0, [])
            legacy_report = report["legacy"]
            legacy_report["old_mesh_status"] = operator.rpc(old_coordinator.socket, "mesh/status", None, 10)
            assert legacy_report["old_mesh_status"].get("libtest_remote_codes") != 1
            refusal = shard([plugin_ids["selectors"]], node=old_coordinator, selected_peers=[workers[0].peer])
            legacy_report["old_coordinator"] = refusal
            assert refusal["exit_code"] == 1 and refusal["stdout"] == "", refusal
            assert "upgrade the coordinator daemon" in refusal["stderr"], refusal

            old_request = {
                "plugin_id": plugin_ids["selectors"],
                "input": list(b'{"operation":"list"}'),
                "timeout_ms": 30000, "cpu_cores": 0.0, "memory_bytes": 0,
                "gpu_required": False, "gpu_vram_min_bytes": 0,
                "integrity": {"kind": "trusted-executor", "allowlist": [old_worker.peer]},
            }
            raw = operator.rpc(coordinator.socket, "compute/dispatch", old_request, 35)
            observed = json.loads(bytes(raw["output"]))
            legacy_report["legacy_unpinned_listing"] = {
                "params": old_request, "chosen_peer": raw["chosen_peer"], "output": observed,
            }
            assert raw["chosen_peer"] == old_worker.peer and observed["exit_code"] == 0, observed
            assert "suite_identity" not in observed and "alpha::first: test" in observed["stdout"], observed
            refusal = shard([plugin_ids["selectors"]], selected_peers=[old_worker.peer])
            legacy_report["old_only_worker"] = refusal
            assert refusal["exit_code"] == 1 and refusal["stdout"] == "", refusal
            upgrade = f"worker {old_worker.peer} does not report signed libtest suite identity; upgrade the worker daemon"
            assert upgrade in refusal["stderr"], refusal

            no_pin = dict(old_request, input=list(b'{"operation":"test","name":"alpha::first"}'),
                          integrity={"kind": "trusted-executor", "allowlist": [peers[0]]})
            raw = operator.rpc(coordinator.socket, "compute/dispatch", no_pin, 35)
            assert raw["chosen_peer"] == peers[0], raw
            observed = json.loads(bytes(raw["output"]))
            assert observed["suite_identity"] == pins["selectors"]
            assert operator.classify(observed, "alpha::first") == "passed", observed
            legacy_report["old_client_unpinned_test_protocol"] = {
                "params": no_pin, "chosen_peer": raw["chosen_peer"], "output": observed,
            }
            report["exit_code"] = 0
    finally:
        report["finished_utc"] = utc()
        report["source_after"] = checked(source_id_command, repo)
        report["source_commit_after"] = checked(["git", "rev-parse", "HEAD"], repo)
        report["release_archive_sha256_after"] = sha(archive)
        assert report["source_after"] == source_before and report["source_commit_after"] == commit
        assert report["release_archive_sha256_after"] == report["release_archive_sha256"]
        assert sha(old_archive) == legacy["sha256"]
        report["daemon_logs_sha256"] = {file.name: sha(file) for file in sorted(out.glob("*.log"))}
        report.setdefault("exit_code", 1)
        with (out / "results.json").open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print(f"{len(report['selection'])} selection cases matched native. "
          f"{len(report['diagnostics'])} diagnostic, deadline and health cases exercised. "
          f"Receipt SHA-256 {sha(out / 'results.json')}")


if __name__ == "__main__":
    main()
