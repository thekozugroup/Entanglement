#!/usr/bin/env python3
"""Complete the registered whole-jaq WASI run after an ENOSPC setup failure."""

import argparse
from collections import Counter
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from replay import STAGE, UPSTREAM_CACHE, check, checked_inputs, git, json_write, now, sha, source


def preserve(input_path, destination):
    with destination.open("xb") as out:
        out.write(input_path.read_bytes())


def compress(input_path, destination):
    with destination.open("xb") as out:
        out.write(gzip.compress(input_path.read_bytes(), mtime=0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit")
    parser.add_argument("source_id")
    args = parser.parse_args()
    repo = Path("/workspace/Entanglement")
    before = source(repo, args.commit, args.source_id)
    candidate = repo / "docs/testing/production-review/evidence" / ("candidate-" + args.commit[:8])
    evidence = candidate / "jaq-natural"
    stage = STAGE / args.commit[:8]
    upstream = UPSTREAM_CACHE / "jaq-natural"
    initial = stage / "jaq-full.log"
    check("[Errno 28] No space left on device" in initial.read_text()
          and "where=d/(\"suite\"+str(i));where.mkdir()" in initial.read_text()
          and not (stage / "jaq-workspace-cargo.log").exists()
          and not (stage / "jaq-distributed.json").exists(),
          "first setup did not fail before distributed Cargo started")
    config = json.loads((candidate / "upstream-rust-preregistration.json").read_text())
    check((config["candidate_commit"], config["candidate_source_id"]) == (args.commit, before)
          and config["upstreams"] == checked_inputs(), "registered workspace inputs changed")
    bound = json.loads((stage / "bound-protocol.json").read_text())
    original_cohort = json.loads((evidence / "cohort-receipt.json").read_text())
    original_verify = json.loads((evidence / "all-block-verification.json").read_text())
    manifest_path = candidate / "linux-archive.json"
    manifest = json.loads(manifest_path.read_text())
    check(manifest["source_commit"] == args.commit == bound["release_commit"]
          and manifest["source_id"] == before == bound["source_before"]
          and bound["archive_sha256"] == manifest["sha256"]
          and all(sha(stage / "binaries" / n) == bound["elf_sha256"][n] == manifest["files_sha256"][n]
                  for n in ("entangle", "entangled")), "archive binaries or frozen identity changed")
    parent = json.loads((candidate / "upstream-rust-qualification.json").read_text())
    native_log = stage / "jaq-native.log"
    with gzip.open(evidence / "full-native-cargo.log.gz", "rb") as archive:
        check(archive.read() == native_log.read_bytes(), "initial native Cargo log differs from retained artifact")
    preserve(initial, evidence / "full-setup-first.log")
    preserve(Path(__file__), evidence / "finish-jaq-setup.py")

    new = stage / "full-remote-after-setup"
    new.mkdir()
    bindings = new / "components"
    bindings.mkdir()
    driver = upstream / "workspace-296.py"
    native_counts = Counter()
    for passed, failed, ignored in re.findall(
        r"(?m)^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", native_log.read_text()
    ):
        native_counts.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    # Cargo ends with 101 on a failed test target. Independently verify the
    # actual observed failure here and retain the original, unrepeated run.
    check("error: 1 target failed:" in native_log.read_text() and native_counts["failed"] > 0,
          "original native failure evidence is missing")
    command = [sys.executable, str(driver), "--root", str(repo), "--workspace", str(upstream / "upstream"),
               "--metadata", str(upstream / "workspace-metadata178.json"), "--wasm-artifacts",
               str(upstream / "original178-wasi-artifacts.jsonl"), "--binaries", str(stage / "binaries"),
               "--out", str(new / "report.json"), "--cargo-log", str(new / "cargo.log"),
               "--sharder", str(repo / "scripts/run-rust-tests.py"), "--binary-manifest", str(manifest_path)]
    cargo_home = Path(os.environ["CARGO_HOME"])
    adapter = (cargo_home / "registry/src/index.crates.io-1949cf8c6b5b557f"
               / "wasi-preview1-component-adapter-provider-36.0.23/artefacts/wasi_snapshot_preview1.command.wasm")
    env = {**os.environ, "CARGO_TARGET_DIR": str(upstream / "target178"),
           "JAQ_COMPONENT_ENCODER": str(upstream / "component-adapter"), "JAQ_WASI_ADAPTER": str(adapter),
           "JAQ_ARTIFACT_EVIDENCE": str(bindings), "ENTANGLE_REVIEW_COMMIT": args.commit,
           "ENTANGLE_REVIEW_SOURCE_ID": before}
    start = now()
    log = evidence / "full-launch.log"
    with log.open("xb") as out:
        result = subprocess.run(command, cwd=repo, env=env, stdout=out, stderr=subprocess.STDOUT)
    after = source(repo, args.commit, before)
    repair = {"source_commit": args.commit, "source_before": before, "source_after": after, "command": command,
              "started_utc": start, "finished_utc": now(), "exit_code": result.returncode,
              "archive_sha256": bound["archive_sha256"], "elf_sha256": bound["elf_sha256"],
              "first_setup_log_sha256": sha(evidence / "full-setup-first.log"),
              "first_driver_receipt_sha256": sha(candidate / "upstream-rust-qualification.json"),
              "first_driver_exit_code": parent["exit_code"], "initial_native_log_sha256": sha(native_log),
              "scope": "A failed suite staging operation stopped the first command before Cargo. This runs the previously unstarted distributed Cargo step. The original native and 128-block natural runs are preserved and unrepeated.",
              "log": str(log.relative_to(repo)), "sha256": sha(log)}
    json_write(evidence / "full-remote-after-setup.json", repair)
    check((new / "report.json").exists() and (new / "cargo.log").exists(), "distributed Cargo did not produce a report")
    report = json.loads((new / "report.json").read_text())
    check(report["source_before"] == report["source_after"] == before
          and report["exit_code"] == result.returncode
          and report["daemon_sha256"] == bound["elf_sha256"]["entangled"]
          and report["cli_sha256"] == bound["elf_sha256"]["entangle"], "raw distributed provenance mismatch")
    compress(new / "report.json", evidence / "full-workspace.json.gz")
    compress(new / "cargo.log", evidence / "full-cargo.log.gz")
    json_write(evidence / "compiled-component-bindings.json",
               [json.loads(item.read_text()) for item in sorted(bindings.glob("*.json"))])
    remote_counts = Counter()
    for target in report["targets"]:
        remote_counts.update(target["report"]["counts"])
    check(report["upstream_commit"] == "606164eb26420c892c9bac27f7daf77b7a406b6d"
          and not git(upstream / "upstream", "status", "--porcelain"), "upstream fixture source changed")
    qualification = {
        **bound, "upstream_revision": report["upstream_commit"], "source_after": after, "finished_utc": now(),
        "full_native_command": ["cargo", "+1.78.0", "test", "--offline", "--locked", "--workspace", "--no-fail-fast"],
        "full_native_exit": None, "full_native_status": "failed",
        "full_native_exit_note": "The original driver recorded the native command output and proceeded to the WASI arm. Its later pre-Cargo failure occurred before it wrote the native subprocess exit code. The untouched native log records the single failed test target.",
        "full_native_counts": native_counts, "full_remote_exit": result.returncode,
        "full_reported_cases": remote_counts, "cohort_exit": 0, "cohort_verifier_exit": 0,
        "cohort_blocks": original_cohort["blocks"], "remote_cohort_patterns": original_cohort["remote_patterns"],
        "native_cohort_patterns": original_cohort["native_patterns"],
        "cross_peer_blocks": original_cohort["verified_remote_transitions"],
        "natural_cross_peer_witness": original_verify["witness_criterion_met"],
        "whole_workspace_native_wasi_parity": False,
        "sharder_sha256": report["sharder_sha256"], "workspace_driver_sha256": sha(driver),
        "independent_verifier_sha256": sha(upstream / "verify-cohort.py"),
        "cohort_script_sha256": sha(upstream / "campaign-296.py"), "qualification_scope": repair["scope"],
        "full_remote_after_setup_sha256": sha(evidence / "full-remote-after-setup.json"),
    }
    json_write(evidence / "qualification.json", qualification)
    print(f"Full native Cargo recorded a failed target {dict(native_counts)}. "
          f"Full WASI Cargo exit {result.returncode} {dict(remote_counts)}.")


if __name__ == "__main__":
    main()
